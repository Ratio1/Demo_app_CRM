"""Shared fixtures for the Demo_App_CRM Slice A test suite.

Authority: ``_agents/projects/CRM/contracts/slice-a.md`` §7 (test hooks) and
§7.5 / ruling R41 (per-test ephemeral TLS server), §7.1 (CLI provisioning),
§7.2 / §10(e) (resetting ``crm_test``), §7.3 (the injectable clock), §7.4
(the fast Argon2 test profile).

Credential discipline
----------------------
No fixture here ever reads, prints or logs a database credential. The only
sanctioned path to one is ``scripts/with-env <env-file> -- <command>``
(``AGENTS.md``, ``PLAN.md`` §7); this module shells out to that script and
never opens an env file itself. Subprocess stdout/stderr is always redirected
to a per-test log **file**, never captured into a string that a failed
``assert`` could echo into the pytest report.

Database roles
---------------
``.env.test.owner.local`` — ``crm_test_owner`` — schema reset, migrations,
and every ``scripts/manage`` maintenance command (bootstrap, create-user,
disable-user, set-origin): all of those need privileges the runtime role
does not have (ACC-605, ACC-609).
``.env.test.local`` — ``crm_test_app`` — the only role the served
application itself runs as.

Server isolation (R41)
------------------------
Every test that needs a live HTTP(S) endpoint gets its **own** uvicorn
subprocess, bound to an OS-assigned ``127.0.0.1:0`` port with **no**
probe-then-bind race: this module binds and listens on the port itself and
hands the already-listening socket's file descriptor to the uvicorn
subprocess (``--fd``), so there is never a second bind. Port ``3002`` is the
human dev-run assignment (``BRIEF.md``) and never appears here.

Why so much of this is lazy-imported
--------------------------------------
Slice A is written against the contract while the Backend, Data and Frontend
lanes are still building it. Most of ``app.main``, ``app.security.*``,
``app.services.*``, ``app.routes.*`` and ``app.db.repositories.*`` do not
exist on disk yet. Importing any of them at *module* level here would make
every single test in the whole session fail to collect, hiding the tests
that *can* run today (``app.config`` and the migration journal already
ship). Every such import is therefore deferred into the fixture or test body
that actually needs it, so a missing module surfaces as one failing test,
not a blank test session.

Two ways a test reaches the database
--------------------------------------
1. **Over HTTP**, via ``live_server``/``admin_client``/``agent_client`` — for
   anything genuinely observable only at the wire (cookie attributes,
   status codes, response headers). The server subprocess builds its own
   ``SystemClock`` (``create_app`` takes no clock parameter), so nothing
   reachable only through HTTP can be driven by ``ManualClock``.
2. **In process**, via ``db_connection`` — for repository-level behaviour
   the contract itself drives by an explicit ``now`` parameter (expiry,
   revocation, throttle/budget windows: §7.3 "every expiry test... advances
   the clock rather than sleeping"). This fixture calls
   ``app.config.load_config()`` with no explicit mapping, so it reads
   ``os.environ`` directly — which means **the test process itself** needs
   the runtime credentials already in its environment. Per slice-a.md §7.2
   ("The suite itself runs under ``.env.test.local`` as ``crm_test_app``"),
   the canonical way to run this suite is therefore::

     scripts/with-env .env.test.local -- .venv/bin/python -B -m pytest

   A bare ``pytest`` invocation still collects and runs every test that
   does not request ``db_connection`` (all of ``tests/unit``,
   ``tests/arch``, and the subprocess-driven
   ``tests/security/test_dep_hostile_env.py``, each of which reaches the
   database only through its own ``with-env`` subprocess); a test that does
   request it fails with a plain, value-free ``ConfigError`` under a bare
   invocation — an honest signal, not a leak. Seeding data that needs the
   **owner** role (for example a ``users`` row, whose runtime grant is
   ``SELECT, UPDATE`` only) still goes through its own dedicated
   ``with-env .env.test.owner.local`` subprocess — see
   :func:`insert_test_user_row` — never through an in-process owner
   connection, because a single test process can only ever hold the one
   role it was launched under.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import time
import uuid
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import httpx
import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Paths and roles, all relative to the submodule root (never the meta-repo).
# ---------------------------------------------------------------------------

SUBMODULE_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
VENV_PYTHON: Final[Path] = SUBMODULE_ROOT / ".venv" / "bin" / "python"
WITH_ENV: Final[Path] = SUBMODULE_ROOT / "scripts" / "with-env"
MANAGE: Final[Path] = SUBMODULE_ROOT / "scripts" / "manage"

#: Owner role — schema DDL and every maintenance CLI command.
OWNER_ENV_FILE: Final[str] = ".env.test.owner.local"
#: Runtime role — the only role the served application runs as.
RUNTIME_ENV_FILE: Final[str] = ".env.test.local"
RUNTIME_ROLE: Final[str] = "crm_test_app"

#: Fictional test principals (spec: fictional data only, ``example.test``).
BOOTSTRAP_ADMIN_EMAIL: Final[str] = "ada.admin@example.test"
BOOTSTRAP_ADMIN_NAME: Final[str] = "Ada Admin"
BOOTSTRAP_ADMIN_PASSWORD: Final[str] = "correct horse battery staple 15"

#: Placeholder origin ``bootstrap`` is given before any server has bound a
#: port; every test's own ``live_server`` fixture re-points it with
#: ``manage set-origin`` before making a request (slice-a.md §7.1).
_PLACEHOLDER_ORIGIN: Final[str] = "https://127.0.0.1:65535"

_RESET_SCHEMA_SNIPPET: Final[str] = """
import asyncio
from typing import Any, cast
from psycopg import AsyncConnection
from app.config import load_config

async def main() -> None:
  kwargs = cast('dict[str, Any]', load_config().connect_kwargs())
  conn = await AsyncConnection.connect(autocommit=True, **kwargs)
  try:
    await conn.execute('DROP SCHEMA IF EXISTS public CASCADE')
    await conn.execute('CREATE SCHEMA public')
  finally:
    await conn.close()

asyncio.run(main())
"""


class SubprocessFailed(RuntimeError):
  """Raised when a helper subprocess exits non-zero.

  The message names the command and the exit code only. It never repeats
  stdout/stderr, because that stream is not guaranteed (by anything this
  module controls) to be as carefully sanitized as ``with-env`` itself is;
  the caller can open ``log_path`` deliberately if it needs to inspect it.
  """

  def __init__(self, argv: list[str], returncode: int, log_path: Path) -> None:
    """Build the message from non-sensitive fields only.

    Parameters
    ----------
    argv : list[str]
      The command that was run, for identification only (no env file
      contents, no credentials, are ever placed in ``argv``).
    returncode : int
      The process exit status.
    log_path : Path
      Where the combined stdout/stderr was written.
    """
    super().__init__(f"subprocess failed (exit {returncode}): {argv[0]} ... — see {log_path}")
    self.argv = argv
    self.returncode = returncode
    self.log_path = log_path


def _run_logged(
  argv: list[str],
  *,
  cwd: Path,
  log_path: Path,
  extra_env: Mapping[str, str] | None = None,
  timeout: float = 60.0,
  check: bool = True,
) -> int:
  """Run ``argv``, writing combined stdout/stderr only to ``log_path``.

  Parameters
  ----------
  argv : list[str]
    The command and its arguments.
  cwd : Path
    Working directory. ``CA_BUNDLE_PATH`` is cwd-relative until D2 lands, so
    every database-touching subprocess runs with ``SUBMODULE_ROOT`` as cwd.
  log_path : Path
    Destination file for the combined output stream. Overwritten.
  extra_env : Mapping[str, str] | None
    Extra variables layered on top of ``os.environ`` for this call only.
  timeout : float
    Seconds before the process is killed and the wait fails loudly.
  check : bool
    When true (the default), a non-zero exit raises :class:`SubprocessFailed`.

  Returns
  -------
  int
    The process return code.
  """
  env = dict(os.environ)
  if extra_env:
    env.update(extra_env)
  with log_path.open("wb") as log_file:
    completed = subprocess.run(  # noqa: S603
      argv,
      cwd=cwd,
      env=env,
      stdout=log_file,
      stderr=subprocess.STDOUT,
      timeout=timeout,
      check=False,
    )
  if check and completed.returncode != 0:
    raise SubprocessFailed(argv, completed.returncode, log_path)
  return completed.returncode


def run_with_env(
  env_file: str,
  *command: str,
  log_path: Path,
  timeout: float = 60.0,
  check: bool = True,
) -> int:
  """Run ``command`` under ``scripts/with-env <env_file> -- <command>``.

  This is the only sanctioned path to a database credential
  (``AGENTS.md``); no fixture in this module ever opens an env file itself.

  Parameters
  ----------
  env_file : str
    ``.env.test.local`` or ``.env.test.owner.local`` — never any other name.
  *command : str
    The command and its arguments, run relative to ``SUBMODULE_ROOT``.
  log_path : Path
    Where combined stdout/stderr is written (never printed).
  timeout : float
    Seconds before the subprocess is killed.
  check : bool
    Raise :class:`SubprocessFailed` on a non-zero exit when true.

  Returns
  -------
  int
    The process return code.
  """
  argv = [str(WITH_ENV), env_file, "--", *command]
  return _run_logged(argv, cwd=SUBMODULE_ROOT, log_path=log_path, timeout=timeout, check=check)


def unique_email(prefix: str) -> str:
  """Return a unique fictional ``example.test`` address for one test.

  Parameters
  ----------
  prefix : str
    A short, readable label (``"agent"``, ``"agent-b"``); a random suffix is
    appended so parallel and repeated test runs never collide on
    ``users.email_norm``'s unique constraint.

  Returns
  -------
  str
    ``f"{prefix}+{token}@example.test"``, fictional per ``AGENTS.md``.
  """
  return f"{prefix}+{uuid.uuid4().hex[:12]}@example.test"


def write_password_fixture(tmp_path: Path, password: str, *, name: str = "password") -> Path:
  """Write a one-line, mode-0600 password fixture for ``--password-stdin``.

  Parameters
  ----------
  tmp_path : Path
    A pytest-provided scratch directory.
  password : str
    A fictional password. Never logged or asserted into a failure message.
  name : str
    The file's basename, for readability when more than one is needed.

  Returns
  -------
  Path
    The file's path. ``scripts/manage --password-stdin`` reads exactly one
    line and strips exactly one trailing ``\\n`` (slice-a.md §1.2), so the
    file carries the password followed by a single newline and nothing else.
  """
  path = tmp_path / name
  path.write_text(password + "\n", encoding="utf-8")
  path.chmod(0o600)
  return path


# ---------------------------------------------------------------------------
# The clock (slice-a.md §7.3)
# ---------------------------------------------------------------------------


@pytest.fixture
def clock() -> object:
  """Return a fresh ``ManualClock`` fixed at a known instant.

  Returns
  -------
  app.security.clock.ManualClock
    Untyped as ``object`` at the signature level because
    ``app.security.clock`` does not exist yet in this tree; every caller
    imports the concrete type itself for static checking once it ships.
    Constructed, never environment-selected, exactly as §7.3 requires.

  Raises
  ------
  ModuleNotFoundError
    Until the Backend lane ships ``app/security/clock.py``. That failure is
    the honest, expected state of every test that requests this fixture
    before then — it is not hidden.
  """
  # Deferred import (module docstring): app/security/clock.py is contracted
  # (slice-a.md §1.1) but not yet shipped by the Backend lane.
  from app.security.clock import ManualClock  # type: ignore[import-not-found]

  return ManualClock(start=datetime(2026, 9, 22, 12, 0, 0, tzinfo=UTC))


# ---------------------------------------------------------------------------
# Argon2 test profile (slice-a.md §7.4) — real argon2-cffi, no app import.
# ---------------------------------------------------------------------------


@pytest.fixture
def fast_password_hasher() -> object:
  """Return a documented fast-profile ``PasswordHasher`` for fixture setup.

  Returns
  -------
  argon2.PasswordHasher
    ``time_cost=1, memory_cost=8, parallelism=1`` — constructed explicitly
    here, never selected through an environment variable or a branch in
    ``app/security/passwords.py`` (``ARC-020``). ``SEC-017`` and ``SEC-033``
    must run against the real, pinned parameters, never this profile.
  """
  from argon2 import PasswordHasher, Type

  return PasswordHasher(
    time_cost=1, memory_cost=8, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
  )


# ---------------------------------------------------------------------------
# Resetting crm_test (slice-a.md §7.2 / §10(e)) — session-scoped.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def crm_test_schema(tmp_path_factory: pytest.TempPathFactory) -> None:
  """Reset ``crm_test`` to an empty, freshly migrated schema, once per session.

  Two owner-role subprocesses, exactly as slice-a.md §10(e) pins: (1) drop
  and recreate ``public`` on an autocommit connection; (2) re-apply the
  migration chain, granting the runtime role. ``crm`` is never touched
  (``D-I``) — only ``.env.test.owner.local`` is used, and its allowed keys
  are the five database names, none of which name the production database.

  Parameters
  ----------
  tmp_path_factory : pytest.TempPathFactory
    Used for the two subprocess logs, which nothing in this session prints.

  Raises
  ------
  SubprocessFailed
    If either step exits non-zero. The log file named in the message holds
    the detail; it is deliberately not inlined into the pytest report.
  """
  log_dir = tmp_path_factory.mktemp("crm_test_reset")

  # `-c`, not a script path: a script *path* puts the script's own directory
  # on sys.path[0] instead of the cwd, so `from app.config import
  # load_config` would fail regardless of `cwd=SUBMODULE_ROOT` — the same
  # reason slice-a.md §10(e) itself uses `-c` rather than a temp file.
  run_with_env(
    OWNER_ENV_FILE,
    str(VENV_PYTHON),
    "-B",
    "-c",
    _RESET_SCHEMA_SNIPPET,
    log_path=log_dir / "01_drop_recreate_schema.log",
  )
  run_with_env(
    OWNER_ENV_FILE,
    str(VENV_PYTHON),
    "-B",
    "-m",
    "app.db.journal",
    "migrate",
    "--grant-to",
    RUNTIME_ROLE,
    log_path=log_dir / "02_migrate.log",
  )


# ---------------------------------------------------------------------------
# In-process database connections — for repository-level tests that drive
# expiry/revocation by an explicit `now` rather than by talking HTTP to a
# server whose own clock cannot be swapped (module docstring, point 2).
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_connection(crm_test_schema: None) -> AsyncIterator[object]:
  """One ``psycopg.AsyncConnection`` to ``crm_test``, as the runtime role.

  Reads credentials from ``os.environ`` via ``app.config.load_config()`` —
  see the module docstring's "two ways a test reaches the database": this
  fixture only works when the test *process itself* was launched under
  ``scripts/with-env .env.test.local -- ...``.

  Yields
  ------
  psycopg.AsyncConnection
    Untyped as ``object`` at the signature level so this module needs no
    top-level ``import psycopg`` failure mode beyond what already exists;
    every caller imports the concrete type itself.

  Raises
  ------
  app.config.ConfigError
    Under a bare ``pytest`` invocation (no DB_* in the environment) — a
    plain, value-free message, not a leak.
  """
  from psycopg import AsyncConnection

  from app.config import load_config

  kwargs = load_config().connect_kwargs()
  connection = await AsyncConnection.connect(**kwargs)  # type: ignore[arg-type]
  try:
    yield connection
  finally:
    await connection.close()


#: Raw SQL, deliberately independent of app.db.repositories.users (which may
#: not exist yet, and whose INSERT is maintenance-only regardless — the
#: runtime role's users grant is SELECT, UPDATE only, migration step 04).
#: This is test-only seeding, not a claim about any repository's behaviour.
_INSERT_TEST_USER_SNIPPET = """
import asyncio
from typing import Any, cast
from psycopg import AsyncConnection
from app.config import load_config

async def main() -> None:
  kwargs = cast('dict[str, Any]', load_config().connect_kwargs())
  conn = await AsyncConnection.connect(**kwargs)
  try:
    await conn.execute(
      "INSERT INTO users (id, email, email_norm, display_name, role, "
      "password_hash, password_changed_at, must_change_password, "
      "is_active, version, created_at, updated_at) "
      "VALUES (%(id)s, %(email)s, %(email_norm)s, %(display_name)s, %(role)s, "
      "%(password_hash)s, %(now)s, %(must_change_password)s, "
      "%(is_active)s, 1, %(now)s, %(now)s)",
      {params},
    )
    await conn.commit()
  finally:
    await conn.close()

asyncio.run(main())
"""


def insert_test_user_row(
  *,
  user_id: str,
  email: str,
  display_name: str,
  role: str,
  password_hash: str,
  must_change_password: bool,
  now: str,
  log_path: Path,
) -> None:
  """Seed one ``users`` row directly, as the owner role, in its own subprocess.

  For repository-level session/throttle tests that need a real user to join
  against but must not depend on ``scripts/manage create-user`` (Backend
  lane, not shipped) or on any repository's own ``insert_user`` (also not
  shipped, and maintenance-only regardless of shipping state).

  Parameters
  ----------
  user_id : str
    A ``str(uuid.uuid4())`` — bound as text, per the repository boundary
    rule that ids cross as ``str``, never ``uuid.UUID`` (slice-a.md §10(b)).
  email, display_name, role : str
    Fictional values only (``AGENTS.md``).
  password_hash : str
    A pre-encoded Argon2 hash string; never a plaintext password.
  must_change_password : bool
  now : str
    An ISO 8601 timestamp string (from a :class:`ManualClock`, typically),
    used for both ``password_changed_at`` and ``created_at``.
  log_path : Path
    Where the subprocess's combined output is saved; never printed.

  Raises
  ------
  SubprocessFailed
  """
  params: dict[str, str | bool] = {
    "id": user_id,
    "email": email,
    "email_norm": email.strip().lower(),
    "display_name": display_name,
    "role": role,
    "is_active": True,
    "must_change_password": must_change_password,
    "password_hash": password_hash,
    "now": now,
  }
  # `repr`, not JSON: this is substituted directly into Python source, and
  # JSON's `true`/`false`/`null` are not valid Python literals.
  script = _INSERT_TEST_USER_SNIPPET.replace("{params}", repr(params))
  run_with_env(
    OWNER_ENV_FILE,
    str(VENV_PYTHON),
    "-B",
    "-c",
    script,
    log_path=log_path,
  )


# ---------------------------------------------------------------------------
# CLI provisioning (slice-a.md §7.1) — needs scripts/manage (Backend lane).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProvisionedUser:
  """A user created through ``scripts/manage`` for one test session/case.

  Attributes
  ----------
  email : str
    Fictional ``example.test`` address.
  name : str
    Display name.
  password : str
    The fictional password chosen for this user. Never logged.
  role : str
    ``"admin"`` or ``"agent"``.
  """

  email: str
  name: str
  password: str
  role: str


@pytest.fixture(scope="session")
def bootstrap_admin(
  crm_test_schema: None,
  tmp_path_factory: pytest.TempPathFactory,
) -> ProvisionedUser:
  """Provision the one first admin ``scripts/manage bootstrap`` ever allows.

  ``bootstrap`` is a one-shot domain operation (exit code 3, "already
  provisioned", on a second call — slice-a.md §1.2), so this runs at most
  once per test session, against the placeholder origin every ``live_server``
  instance re-points with ``manage set-origin`` before it is relied on.

  Returns
  -------
  ProvisionedUser
    The bootstrapped admin's fictional credentials.

  Raises
  ------
  SubprocessFailed
    Expected until the Backend lane ships ``scripts/manage`` — reported, not
    hidden.
  """
  log_dir = tmp_path_factory.mktemp("bootstrap_admin")
  password_file = write_password_fixture(log_dir, BOOTSTRAP_ADMIN_PASSWORD)
  try:
    with password_file.open("rb") as stdin_file:
      argv = [
        str(WITH_ENV),
        OWNER_ENV_FILE,
        "--",
        str(VENV_PYTHON),
        "-B",
        str(MANAGE),
        "bootstrap",
        "--email",
        BOOTSTRAP_ADMIN_EMAIL,
        "--name",
        BOOTSTRAP_ADMIN_NAME,
        "--origin",
        _PLACEHOLDER_ORIGIN,
        "--password-stdin",
      ]
      log_path = log_dir / "bootstrap.log"
      with log_path.open("wb") as log_file:
        completed = subprocess.run(  # noqa: S603
          argv,
          cwd=SUBMODULE_ROOT,
          env=dict(os.environ),
          stdin=stdin_file,
          stdout=log_file,
          stderr=subprocess.STDOUT,
          timeout=60.0,
          check=False,
        )
      if completed.returncode != 0:
        raise SubprocessFailed(argv, completed.returncode, log_path)
  finally:
    password_file.unlink(missing_ok=True)

  return ProvisionedUser(
    email=BOOTSTRAP_ADMIN_EMAIL,
    name=BOOTSTRAP_ADMIN_NAME,
    password=BOOTSTRAP_ADMIN_PASSWORD,
    role="admin",
  )


@pytest.fixture
def provision_agent(
  crm_test_schema: None,
  tmp_path: Path,
) -> Callable[[], ProvisionedUser]:
  """Return a factory that creates one fresh agent per call, via ``create-user``.

  A fresh, uniquely-emailed agent per call (rather than one shared fixture)
  so tests that lock, disable or rotate a session never collide with each
  other inside the one session-scoped database.

  Returns
  -------
  Callable[[], ProvisionedUser]
    Calling it provisions and returns one new agent.
  """

  def _provision() -> ProvisionedUser:
    email = unique_email("agent")
    password = f"a fictional passphrase {uuid.uuid4().hex}"
    password_file = write_password_fixture(tmp_path, password, name=f"pw-{uuid.uuid4().hex[:8]}")
    try:
      with password_file.open("rb") as stdin_file:
        argv = [
          str(WITH_ENV),
          OWNER_ENV_FILE,
          "--",
          str(VENV_PYTHON),
          "-B",
          str(MANAGE),
          "create-user",
          "--email",
          email,
          "--name",
          "Ana Petrescu",
          "--role",
          "agent",
          "--password-stdin",
        ]
        log_path = tmp_path / f"create-user-{uuid.uuid4().hex[:8]}.log"
        with log_path.open("wb") as log_file:
          completed = subprocess.run(  # noqa: S603
            argv,
            cwd=SUBMODULE_ROOT,
            env=dict(os.environ),
            stdin=stdin_file,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            timeout=60.0,
            check=False,
          )
        if completed.returncode != 0:
          raise SubprocessFailed(argv, completed.returncode, log_path)
    finally:
      password_file.unlink(missing_ok=True)
    return ProvisionedUser(email=email, name="Ana Petrescu", password=password, role="agent")

  return _provision


# ---------------------------------------------------------------------------
# The ephemeral TLS server (slice-a.md §7.5 / ruling R41).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TestCertificate:
  """A self-signed ``127.0.0.1`` certificate generated into ``tmp_path``."""

  cert_path: Path
  key_path: Path


def generate_test_certificate(tmp_path: Path) -> TestCertificate:
  """Generate a throwaway self-signed TLS certificate for ``127.0.0.1``.

  Mirrors ``scripts/dev-run.sh``'s ``openssl`` invocation, but always
  regenerates into ``tmp_path`` (never ``app/certs/dev-server.*``, which is
  the human dev-run's pair and is never touched by a test — R41 point 1).

  Parameters
  ----------
  tmp_path : Path
    Destination directory; the key is written mode 0600.

  Returns
  -------
  TestCertificate

  Raises
  ------
  SubprocessFailed
    If ``openssl`` is not on ``PATH`` or refuses the request.
  """
  cert_path = tmp_path / "test-server.crt"
  key_path = tmp_path / "test-server.key"
  argv = [
    "openssl",
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-keyout",
    str(key_path),
    "-out",
    str(cert_path),
    "-subj",
    "/CN=127.0.0.1",
    "-addext",
    "subjectAltName=IP:127.0.0.1,DNS:localhost",
  ]
  _run_logged(argv, cwd=tmp_path, log_path=tmp_path / "openssl.log")
  key_path.chmod(0o600)
  return TestCertificate(cert_path=cert_path, key_path=key_path)


def bind_ephemeral_listening_socket() -> socket.socket:
  """Bind and listen on ``127.0.0.1:0``, returning the live socket.

  Returns
  -------
  socket.socket
    A bound, listening TCP socket whose OS-assigned port is read back with
    ``getsockname()``. Handed to the uvicorn subprocess by file descriptor
    (``--fd``) so there is no second bind and therefore no
    probe-then-bind race (slice-a.md §7.5 point 2, explicit on this).
  """
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind(("127.0.0.1", 0))
  sock.listen(128)
  sock.set_inheritable(True)
  return sock


@dataclass(frozen=True, slots=True)
class LiveServer:
  """A running, per-test uvicorn instance over TLS on an ephemeral port.

  Attributes
  ----------
  base_url : str
    ``https://127.0.0.1:<port>`` — never ``3002`` (R41 point 5).
  port : int
    The OS-assigned port.
  log_path : Path
    Combined stdout/stderr of the uvicorn subprocess. Read deliberately by
    ``SEC-061`` only; never printed by this module.
  process : subprocess.Popen[bytes]
    The running subprocess, for tests that need to signal or inspect it.
  """

  base_url: str
  port: int
  log_path: Path
  process: subprocess.Popen[bytes]


def _wait_until_serving(base_url: str, *, timeout: float) -> None:
  """Poll ``/health/live`` until it answers or ``timeout`` elapses.

  Parameters
  ----------
  base_url : str
    The server's origin.
  timeout : float
    Seconds to keep polling.

  Raises
  ------
  TimeoutError
    If nothing answered within the budget — expected today, since
    ``app.main`` does not exist yet and the subprocess exits immediately.
  """
  deadline = time.monotonic() + timeout
  last_error: Exception | None = None
  while time.monotonic() < deadline:
    try:
      response = httpx.get(f"{base_url}/health/live", verify=False, timeout=1.0)  # noqa: S501
    except httpx.HTTPError as error:
      last_error = error
      time.sleep(0.1)
      continue
    if response.status_code in (200, 405, 404, 503):
      return
    last_error = RuntimeError(f"unexpected status {response.status_code}")
    time.sleep(0.1)
  raise TimeoutError(f"server at {base_url} never answered /health/live: {last_error!r}")


@pytest.fixture
def live_server(
  tmp_path: Path,
  bootstrap_admin: ProvisionedUser,
) -> Iterator[LiveServer]:
  """Start one uvicorn instance over TLS, on its own ephemeral port.

  Plain sync generator fixture: nothing in its body ``await``s (subprocess
  management, socket binding and the polling wait are all synchronous), so
  there is no reason to add async-fixture/event-loop-scope friction under
  ``asyncio_mode = strict`` for a fixture that does no I/O through asyncio.

  Order, per slice-a.md §7.5: generate a throwaway certificate into
  ``tmp_path``; bind and listen on ``127.0.0.1:0`` ourselves; hand the
  listening socket to uvicorn by file descriptor; wait for it to answer;
  re-point ``crm_test``'s stored origin to this exact port with
  ``manage set-origin`` under the owner env file, its own subprocess.

  Yields
  ------
  LiveServer

  Notes
  -----
  Depends on ``bootstrap_admin`` (and transitively ``crm_test_schema``) so
  that an origin row and an active admin exist before any request is made —
  both are provisioning preconditions of ``/health/ready`` (ACC-902/903).
  """
  certificate = generate_test_certificate(tmp_path)
  sock = bind_ephemeral_listening_socket()
  port = sock.getsockname()[1]
  base_url = f"https://127.0.0.1:{port}"
  log_path = tmp_path / "uvicorn.log"

  argv = [
    str(WITH_ENV),
    RUNTIME_ENV_FILE,
    "--",
    str(VENV_PYTHON),
    "-B",
    "-m",
    "uvicorn",
    "app.main:app",
    "--fd",
    str(sock.fileno()),
    "--ssl-certfile",
    str(certificate.cert_path),
    "--ssl-keyfile",
    str(certificate.key_path),
    "--no-server-header",
    "--no-proxy-headers",
    "--no-access-log",
  ]
  with log_path.open("wb") as log_file:
    process = subprocess.Popen(  # noqa: S603
      argv,
      cwd=SUBMODULE_ROOT,
      env=dict(os.environ),
      stdout=log_file,
      stderr=subprocess.STDOUT,
      pass_fds=(sock.fileno(),),
    )
  sock.close()  # the child owns its own dup of the fd now

  try:
    _wait_until_serving(base_url, timeout=10.0)
    set_origin_log = tmp_path / "set-origin.log"
    run_with_env(
      OWNER_ENV_FILE,
      str(VENV_PYTHON),
      "-B",
      str(MANAGE),
      "set-origin",
      "--origin",
      base_url,
      log_path=set_origin_log,
    )
    yield LiveServer(base_url=base_url, port=port, log_path=log_path, process=process)
  finally:
    if process.poll() is None:
      process.terminate()
      try:
        process.wait(timeout=10.0)
      except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10.0)


# ---------------------------------------------------------------------------
# httpx client fixtures — cookie jars (slice-a.md §7.5 point 4).
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def http_client_factory(
  live_server: LiveServer,
) -> AsyncIterator[Callable[[], httpx.AsyncClient]]:
  """Return a factory for fresh, independent httpx clients against ``live_server``.

  Each call returns a client with its **own** cookie jar (``ACC-0xx``/S1-S2
  need genuinely separate sessions, not one jar reused) and
  ``follow_redirects=False`` so a test can inspect a ``303``'s ``Location``
  header itself rather than the redirect target's body.

  Yields
  ------
  Callable[[], httpx.AsyncClient]
  """
  clients: list[httpx.AsyncClient] = []

  def _factory() -> httpx.AsyncClient:
    client = httpx.AsyncClient(
      base_url=live_server.base_url,
      verify=False,  # noqa: S501 — R41 point 4: the test cert is not a trust decision
      follow_redirects=False,
      timeout=10.0,
    )
    clients.append(client)
    return client

  try:
    yield _factory
  finally:
    for client in clients:
      await client.aclose()


@pytest_asyncio.fixture
async def admin_client(
  http_client_factory: Callable[[], httpx.AsyncClient],
) -> httpx.AsyncClient:
  """One httpx client with its own cookie jar, for the admin persona."""
  return http_client_factory()


@pytest_asyncio.fixture
async def agent_client(
  http_client_factory: Callable[[], httpx.AsyncClient],
) -> httpx.AsyncClient:
  """One httpx client with its own cookie jar, for the agent persona."""
  return http_client_factory()


@pytest_asyncio.fixture
async def anon_client(
  http_client_factory: Callable[[], httpx.AsyncClient],
) -> httpx.AsyncClient:
  """One httpx client with its own, empty cookie jar — no session at all."""
  return http_client_factory()


# ---------------------------------------------------------------------------
# Logging in over HTTP — shared by every test that needs an authenticated
# client rather than being about login itself.
# ---------------------------------------------------------------------------

_CSRF_INPUT_PATTERN = re.compile(r'<input[^>]*name="csrf_token"[^>]*value="([^"]*)"', re.IGNORECASE)


def extract_csrf_token(html: str) -> str:
  """Pull the ``csrf_token`` hidden-field value out of a rendered form page.

  Parameters
  ----------
  html : str
    The response body of ``GET /login`` (or any page carrying the same
    hidden field, per ``auth/login.html`` and ``auth/change_password.html``).

  Returns
  -------
  str
    The token value.

  Raises
  ------
  AssertionError
    If no such field is present — an honest failure naming what was
    expected, since a missing CSRF field is itself a finding.
  """
  match = _CSRF_INPUT_PATTERN.search(html)
  assert match is not None, "no csrf_token hidden field found in the response body"
  return match.group(1)


async def login_via_http(client: httpx.AsyncClient, *, email: str, password: str) -> httpx.Response:
  """Drive the real ``GET /login`` → ``POST /login`` flow for one client.

  Parameters
  ----------
  client : httpx.AsyncClient
    A client with its own cookie jar (``admin_client``/``agent_client``/
    a fresh one from ``http_client_factory``); the pre-auth cookie set by
    ``GET /login`` and the full-session cookie set on success both land in
    this client's own jar.
  email, password : str
    The principal's fictional credentials.

  Returns
  -------
  httpx.Response
    The ``POST /login`` response, **not followed** (``follow_redirects`` is
    always ``False`` on these clients — slice-a.md §4 pins a ``303`` on
    success; the caller asserts on it directly rather than on whatever the
    destination page happens to render).
  """
  get_response = await client.get("/login")
  csrf_token = extract_csrf_token(get_response.text)
  return await client.post(
    "/login",
    data={"csrf_token": csrf_token, "email": email, "password": password},
  )


@pytest_asyncio.fixture
async def admin_session(
  admin_client: httpx.AsyncClient, bootstrap_admin: ProvisionedUser
) -> httpx.AsyncClient:
  """``admin_client``, already logged in as the bootstrapped admin.

  Yields the same client passed in (its cookie jar now carries a full
  session), so a test can go straight to the page it actually wants to
  assert on.
  """
  response = await login_via_http(
    admin_client, email=bootstrap_admin.email, password=bootstrap_admin.password
  )
  assert response.status_code == 303, (
    f"login as the bootstrapped admin failed (status {response.status_code}); "
    "every test depending on admin_session assumes this succeeds"
  )
  return admin_client
