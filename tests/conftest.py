"""Shared fixtures for the Demo_App_CRM Slice A test suite.

Authority: ``_agents/projects/CRM/contracts/slice-a.md`` §7 (test hooks) and
§7.5 / ruling R41 (the ephemeral TLS server's certificate/port shape,
amended by **R46(b)**/**R57** to one server per *session* rather than per
test), §7.1 (CLI provisioning), §7.2 / §10(e) (resetting ``crm_test``,
amended by **R57** to a session-scoped **autouse** fixture), §7.3 (the
injectable clock), §7.4 (the fast Argon2 test profile), **R54** (the
``create_app`` injection seam ``tests/inprocess`` drives).

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

Server isolation (R41, amended by R46(b)/R57)
------------------------------------------------
One test **session** that needs a live HTTP(S) endpoint gets **one**
uvicorn subprocess (``live_server``, session-scoped), bound to an
OS-assigned ``127.0.0.1:0`` port with **no** probe-then-bind race: this
module binds and listens on the port itself and hands the
already-listening socket's file descriptor to the uvicorn subprocess
(``--fd``), so there is never a second bind. Port ``3002`` is the human
dev-run assignment (``BRIEF.md``) and never appears here. Every test that
uses it shares that one process and its one certificate; isolation between
tests is by data (dedicated ``example.test`` identities from
``provision_agent``/``unique_email``, never the shared ``bootstrap_admin``,
for anything that mutates account-scoped or global counters) and by
targeted owner-role cleanup (``test_throttle_and_budget.py``'s autouse
clear of ``login_throttle``/``rate_budget``), not by a fresh process.

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

Three ways a test reaches the database
--------------------------------------
1. **Over HTTP, against the real TLS server**, via
   ``live_server``/``admin_client``/``agent_client`` — for anything
   genuinely observable only at the wire (cookie attributes, TLS itself,
   status codes, response headers). ``live_server`` builds its app with the
   production ``SystemClock`` (**R46(b)**: one such server per *session*,
   not per test — see the fixture's own docstring), so nothing reached
   through it can be driven by ``ManualClock``; a clock-dependent
   assertion belongs on transport 3 instead.
2. **In process, at the repository layer**, via ``db_connection`` — for
   behaviour the contract drives by an explicit ``now`` parameter without
   needing a request at all (expiry, revocation: §7.3 "every expiry
   test... advances the clock rather than sleeping").
3. **In process, through the whole ASGI app**, via ``tests/inprocess``'s
   own fixtures (``in_process_app``/``in_process_client``): **R54** gives
   ``create_app`` a ``clock``/``password_hasher`` injection seam, so a test
   can drive the real route table — middleware, CSRF, throttle, sessions,
   the lot — through ``httpx.ASGITransport`` with a :class:`ManualClock`
   it advances by hand, entering the lifespan with ``async with
   app.router.lifespan_context(app):`` (no new dependency — **R42** still
   holds). This is the strongest of the three: it is the only one that
   proves an expiry or a window boundary the way the *served* application
   would actually enforce it, not just the repository function underneath.
   See ``tests/inprocess/conftest.py`` for the fixtures and why its origin
   is ``https://crm.test`` rather than an ephemeral port.

Transport 2's fixture (``db_connection``) calls ``app.config.load_config()`` with no
   explicit mapping, so **it**, in turn, reads ``os.environ`` — but this
   module's own fixtures never read ``os.environ`` directly to build a
   database credential; they always go through ``load_config()``, which
   means **the test process itself** needs the runtime credentials already
   in its environment. Per slice-a.md §7.2 ("The suite itself runs under
   ``.env.test.local`` as ``crm_test_app``") and ruling **R52**, the
   canonical, and only supported, way to run this suite is::

     scripts/with-env .env.test.local -- .venv/bin/python -B -m pytest tests -p no:cacheprovider -q

   (from ``Demo_app_CRM``; also recorded in ``tests/README.md`` and
   ``ACCEPTANCE.md``). **A bare ``pytest`` invocation is not a supported
   invocation (R52)** — it still collects and runs every test that does
   not request ``db_connection`` (all of ``tests/unit``, ``tests/arch``,
   and the subprocess-driven ``tests/security/test_dep_hostile_env.py``,
   each of which reaches the database only through its own ``with-env``
   subprocess) as a convenience for iterating on one file, and a test that
   does request ``db_connection`` fails with a plain, value-free
   ``ConfigError`` under it — an honest signal, not a leak — but it is not
   the invocation whose results this suite's reports may cite. Seeding
   data that needs the **owner** role (for example a ``users`` row, whose
   runtime grant is ``SELECT, UPDATE`` only) still goes through its own
   dedicated ``with-env .env.test.owner.local`` subprocess — see
   :func:`insert_test_user_row` — never through an in-process owner
   connection, because a single test process can only ever hold the one
   role it was launched under.

``tests/e2e`` and the pytest-asyncio / pytest-playwright interaction
-----------------------------------------------------------------------
Earlier revisions of this docstring claimed the corruption below reproduced
from **collection** alone, in either order. Isolating it further (this
revision) shows that claim was wrong: the trigger is *fixture setup*, not
collection, and order matters. When at least one ``tests/e2e`` item's
fixture chain (pytest-playwright's session-scoped ``playwright``/``browser``
fixtures, reached even by a test that then errors on something else, such
as a missing ``scripts/manage``) is set up **before** a
``pytest.mark.asyncio`` test runs in the same session, every later
``pytest-asyncio`` strict-mode ``asyncio.Runner.run()`` call can fail with
``RuntimeError: Runner.run() cannot be called from a running event loop``,
or silently leave a coroutine that pytest reports on without it ever having
run (``RuntimeWarning: coroutine '...' was never awaited``) — corrupting
the result of tests that have nothing to do with ``tests/e2e`` and never
request a browser. It is a known category of interaction between the two
plugins' event-loop management, not a bug in any test here.

This module's ``pytest_collection_modifyitems`` hook (bottom of this file)
now reorders every ``tests/e2e`` item to run **after** everything else in
the same session, which removes the corruption for a single, literal
``pytest tests`` invocation (verified: zero ``Runner.run()`` errors and
zero "never awaited" warnings across the whole suite with the hook in
place, where the same run showed both before it existed). **R52 pins the
single, literal invocation as canonical** (see above); the two-invocation
split below is kept only as a fallback for isolating a browser-less run by
hand, is not itself the R52 invocation, and is never what a gate or
``ACCEPTANCE.md`` run cites::

  scripts/with-env .env.test.local -- .venv/bin/python -B -m pytest tests/ --ignore=tests/e2e
  .venv/bin/python -B -m pytest tests/e2e   # separate invocation; no with-env needed today

Every count this suite's commit messages report from before this revision
was measured with that split; counts reported afterwards use either form
interchangeably, since both are now corruption-free — but only the R52
single invocation is the one this suite's own reports (``README.md``,
``ACCEPTANCE.md``, ``tests/README.md``) may cite as *the* run.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import time
import uuid
from collections.abc import AsyncIterator, Callable, Coroutine, Iterator, Mapping
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

#: Mirrors ``app.main._SAFE_METHODS`` (slice-a.md §2.1 step 0a): a request
#: with none of these methods must carry a matching ``Origin`` header or the
#: middleware refuses it before routing. httpx, unlike a browser, never adds
#: this header on its own — see ``_default_origin_on_unsafe_methods`` below.
_SAFE_HTTP_METHODS: Final[frozenset[str]] = frozenset({"GET", "HEAD", "OPTIONS"})

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
  # Deferred import (module docstring): keeps a missing module a single
  # failing test rather than a blank collection. Shipped now, so no
  # `type: ignore` is needed (or accepted by mypy --strict) any more.
  from app.security.clock import ManualClock

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


@pytest.fixture(scope="session", autouse=True)
def crm_test_schema(tmp_path_factory: pytest.TempPathFactory) -> None:
  """Reset ``crm_test`` to an empty, freshly migrated schema, once per session.

  Two owner-role subprocesses, exactly as slice-a.md §10(e) pins: (1) drop
  and recreate ``public`` on an autocommit connection; (2) re-apply the
  migration chain, granting the runtime role. ``crm`` is never touched
  (``D-I``) — only ``.env.test.owner.local`` is used, and its allowed keys
  are the five database names, none of which name the production database.

  **Session-scoped and autouse (ruling R57).** Every test in the session
  depends on this, whether or not it names it, so it always runs **first**
  — before the first test's body, regardless of collection order or of
  which module happens to be collected first. That is what makes the
  canonical invocation (``tests/README.md``) runnable starting from a
  *clean* ``crm_test`` (freshly created, unmigrated: nothing has ever run
  ``app.db.journal migrate`` against it) exactly as well as from a *dirty*
  one left over from a previous run — a module that reaches the database
  without ever requesting a fixture that names ``crm_test_schema``
  (``tests/concurrency/test_audit_atomicity.py`` is the example this suite
  has) no longer has to rely on some *other*, earlier test having migrated
  the schema as a side effect.

  ``tests/concurrency/test_last_admin_race.py`` is the one module that
  still resets and re-provisions the schema **again**, independently, in
  its own ``module``-scoped fixture — it needs the total active-admin
  count at exactly two, which the shared ``bootstrap_admin`` cannot give
  it without disabling the admin every other module relies on. Collection
  runs it dead last (this module's own ``pytest_collection_modifyitems``,
  below), *after* ``bootstrap_admin`` has already been provisioned and
  used by every other module in the session, so the schema it leaves
  dirty at session end affects nothing else in *this* run; the *next*
  run's ``crm_test_schema`` (this fixture) absorbs it, which is exactly
  the "runnable from a dirty ``crm_test``" property this fixture exists
  to hold.

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


@pytest.fixture(scope="session")
def live_server(
  tmp_path_factory: pytest.TempPathFactory,
  bootstrap_admin: ProvisionedUser,
) -> Iterator[LiveServer]:
  """Start one uvicorn instance over TLS, on its own ephemeral port, once per session.

  Plain sync generator fixture: nothing in its body ``await``s (subprocess
  management, socket binding and the polling wait are all synchronous), so
  there is no reason to add async-fixture/event-loop-scope friction under
  ``asyncio_mode = strict`` for a fixture that does no I/O through asyncio.

  Order, per slice-a.md §7.5: generate a throwaway certificate into a
  dedicated ``tmp_path_factory`` directory (session-scoped — **not**
  ``tmp_path``, which is function-scoped and would be a pytest
  ``ScopeMismatch`` error here); bind and listen on ``127.0.0.1:0``
  ourselves; hand the listening socket to uvicorn by file descriptor; wait
  for it to answer; re-point ``crm_test``'s stored origin to this exact
  port with ``manage set-origin`` under the owner env file, its own
  subprocess.

  **Session-scoped (ruling R46(b)/R57):** one TLS uvicorn subprocess serves
  every test in the session that needs one, rather than a fresh subprocess
  per test (the original R41 shape). It starts once, the first time any
  test requests it (directly or through ``http_client_factory``), and is
  torn down at session end. Isolation between the tests that share it is
  by data — a dedicated, uniquely-generated ``example.test`` identity per
  test that mutates anything account-scoped or global
  (``provision_agent``/``unique_email``; never the shared
  ``bootstrap_admin``/``admin_session`` for that) — and by targeted
  owner-role cleanup where a counter is genuinely shared and global
  (``test_throttle_and_budget.py``'s autouse clear of
  ``login_throttle``/``rate_budget``), never by restarting the process.
  This is safe to share because nothing in the served app's in-process
  state is test-mutable in a way a fresh process would have reset anyway:
  the Argon2 hash-queue gate empties itself once every concurrent request
  in a test completes (before the next test starts, since tests run
  sequentially — the canonical invocation is never run under a
  parallelizing plugin), and the origin/readiness caches are warm on a
  value that never changes for the life of this server (this fixture sets
  it exactly once, below).

  Yields
  ------
  LiveServer

  Notes
  -----
  Depends on ``bootstrap_admin`` (and transitively ``crm_test_schema``) so
  that an origin row and an active admin exist before any request is made —
  both are provisioning preconditions of ``/health/ready`` (ACC-902/903).
  """
  tmp_path = tmp_path_factory.mktemp("live_server")
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


def _default_origin_on_unsafe_methods(
  base_url: str,
) -> Callable[[httpx.Request], Coroutine[None, None, None]]:
  """Build an httpx ``request`` event hook that stamps a same-origin ``Origin``.

  ``app.main.OriginHostMiddleware`` (slice-a.md §2.1 step 0a) requires an
  ``Origin`` header on every unsafe-method request and refuses ``403`` when
  it is absent — matching a real browser, which always sends one on a
  same-origin ``POST`` navigation (verified live: a plain Chromium form
  submission carries ``Origin: <page origin>`` for an ordinary page).
  httpx, unlike a browser, adds no such header on its own, so every helper
  in this suite that drives ``POST``/``PUT``/``PATCH``/``DELETE``/``TRACE``
  through a client from :func:`http_client_factory` would otherwise be
  refused at step 0a before the behaviour it means to exercise (CSRF, the
  route handler, a throttle) is ever reached — that is what produced the
  ``AssertionError: ... status 403`` and ``ConfigError``-free ``ERROR at
  setup`` failures this hook fixes.

  A test that deliberately exercises a missing or foreign ``Origin``
  (``SEC-040a`` et al.) already passes its own ``headers={"Origin": ...}``
  per call, which httpx merges over the client's defaults *before* this
  hook runs — so the hook only fills a header that is not already present
  and never overrides an explicit test choice, including the intentionally
  empty ``headers={}`` a safe-method test passes to assert on the no-Origin
  case (a safe method is untouched here regardless).

  Historical note, resolved by ruling **R50** — kept because it explains
  why this hook exists rather than the app simply always sending
  ``Origin``: a **real** browser does not always send the page's origin on
  an unsafe navigation — when the referring page carries
  ``Referrer-Policy: no-referrer``, the Fetch standard's "append a request
  `Origin` header" algorithm serializes it as the literal string
  ``"null"`` instead, which fails an exact-``Origin`` equality check.
  Reproduced live in Slice A gate round 1 (headless Chromium, real form
  ``POST``) and on a plain, unrelated ``http.server`` (no TLS, no app
  code): a ``GET`` response carrying only ``Referrer-Policy: no-referrer``
  made a same-origin form ``POST`` arrive with ``Origin: null``. **R50**
  fixed this at the source — ``app/security/headers.py`` now sends
  ``Referrer-Policy: same-origin`` (``SEC-027``), under which a real
  browser keeps sending the true ``Origin`` on a same-origin ``POST`` — so
  this is no longer an open backend gap; the header value below is
  verified against the response in ``tests/security/test_headers.py``.
  This hook still exists because httpx, unlike a browser, never adds
  ``Origin`` on its own regardless of ``Referrer-Policy``, so every
  unsafe-method call in this httpx-driven suite still needs it stamped
  explicitly.

  Parameters
  ----------
  base_url : str
    ``live_server.base_url`` — the exact string the stored ``public_origin``
    is set to by ``manage set-origin``.

  Returns
  -------
  Callable[[httpx.Request], Coroutine[None, None, None]]
    An async httpx request hook.
  """

  async def _hook(request: httpx.Request) -> None:
    if request.method in _SAFE_HTTP_METHODS:
      return
    if "origin" in request.headers:
      return
    request.headers["origin"] = base_url

  return _hook


@pytest_asyncio.fixture
async def http_client_factory(
  live_server: LiveServer,
) -> AsyncIterator[Callable[[], httpx.AsyncClient]]:
  """Return a factory for fresh, independent httpx clients against ``live_server``.

  Each call returns a client with its **own** cookie jar (``ACC-0xx``/S1-S2
  need genuinely separate sessions, not one jar reused) and
  ``follow_redirects=False`` so a test can inspect a ``303``'s ``Location``
  header itself rather than the redirect target's body. Every such client
  also carries the ``Origin``-stamping request hook (see
  :func:`_default_origin_on_unsafe_methods`) so an unsafe-method request
  reaches the behaviour a test means to exercise instead of being refused
  at step 0a for lacking a header a real browser sends automatically.

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
      event_hooks={"request": [_default_origin_on_unsafe_methods(live_server.base_url)]},
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


# ---------------------------------------------------------------------------
# Clearing the two global throttle/budget counters (ruling R52, extended by
# R57 to the in-process transport too) — shared by
# ``tests/security/test_throttle_and_budget.py`` (``live_server``) and
# ``tests/inprocess`` (``in_process_client``): both drive the same
# DB-shared, global ``login_throttle``/``rate_budget`` rows, so one clearing
# routine belongs in one place rather than two copies drifting apart.
# ---------------------------------------------------------------------------

_CLEAR_THROTTLE_AND_BUDGET_SNIPPET: Final[str] = """
import asyncio
from typing import Any, cast
from psycopg import AsyncConnection
from app.config import load_config

async def main() -> None:
  kwargs = cast('dict[str, Any]', load_config().connect_kwargs())
  conn = await AsyncConnection.connect(autocommit=True, **kwargs)
  try:
    await conn.execute('DELETE FROM public.login_throttle')
    await conn.execute('DELETE FROM public.rate_budget')
  finally:
    await conn.close()

asyncio.run(main())
"""


def clear_throttle_and_budget_state(*, log_path: Path) -> None:
  """Delete every row from ``login_throttle`` and ``rate_budget`` (owner role).

  A blunt test-isolation wipe of exactly the two counter tables ruling
  **R52** names, nothing else (``crm`` is never touched; this only ever
  runs against ``crm_test``, via ``OWNER_ENV_FILE``).

  Parameters
  ----------
  log_path : Path
    Where the owner-role subprocess's combined output is saved; never
    printed.
  """
  run_with_env(
    OWNER_ENV_FILE,
    str(VENV_PYTHON),
    "-B",
    "-c",
    _CLEAR_THROTTLE_AND_BUDGET_SNIPPET,
    log_path=log_path,
  )


# ---------------------------------------------------------------------------
# Collection ordering.
#
# Four concerns, addressed in one hook because they interact (see each
# bucket's rationale below): the pytest-asyncio / pytest-playwright event
# loop corruption (module docstring, "tests/e2e runs as its own separate
# invocation"), the new in-process/ASGI transport's origin (Hazard, ruling
# R54), and ``test_last_admin_race.py``'s independent schema reset (ruling
# R57, this module's ``crm_test_schema`` docstring).
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
  """Order the session as ``[inprocess] -> [everything else] -> [e2e] -> [last_admin_race]``.

  Four buckets, in this order, each explained below. A test collected in
  more than one bucket's predicate is placed by whichever bucket is
  checked first, in the order the buckets are built (inprocess, then
  last-admin-race, then e2e): today no test matches two predicates at
  once, since the three special directories/files are disjoint, but the
  precedence is stated so a future addition cannot become ambiguous by
  accident.

  1. ``tests/inprocess`` **first.** Its own module-scoped fixture points
     ``crm_test``'s stored ``public_origin`` at ``https://crm.test``
     (ruling **R54**). ``live_server`` (bucket 2/3) points the same row at
     its own ``https://127.0.0.1:<port>`` the moment it is first
     constructed and never repoints it again for the rest of the session —
     so if any ``live_server``-backed test ran *before* ``tests/inprocess``,
     the in-process fixture's ``manage set-origin`` would still work, but
     every ``live_server`` test **after** it would start failing every
     request with ``403`` (``Host``/``Origin`` no longer match the origin
     ``live_server`` was actually pointed at) — and reordering it back
     would break the tests that ran in between. Running ``tests/inprocess``
     first and letting ``live_server`` set its own origin exactly once,
     after, needs no toggling back at all.
  2. **Everything else**, unordered relative to itself except as buckets
     3-4 pull specific items out of it.
  3. ``tests/e2e`` **second to last.** See the module docstring: at least
     one ``tests/e2e`` item's fixture chain sets up pytest-playwright's
     session-scoped fixtures, and once that has happened in a session,
     ``pytest-asyncio``'s ``asyncio.Runner.run()`` can fail or silently
     drop a coroutine for every *later* async test — never an earlier one.
     Ordering ``tests/e2e`` last among the async-test buckets removes the
     corruption for the single, literal ``pytest tests`` invocation.
  4. ``tests/concurrency/test_last_admin_race.py`` **absolute last, after
     even tests/e2e.** Its own module-scoped fixture resets and
     re-migrates ``crm_test`` from scratch and bootstraps two admins of
     its own — a schema wipe that would take the shared
     ``bootstrap_admin``/``crm_test_schema`` state (every other module's
     ``live_server``/``db_connection`` fixture depends on it) down with
     it. Placing it after every other test in the session, including
     ``tests/e2e``, means nothing that runs afterward in *this* session
     needs that state any more; the *next* session's ``crm_test_schema``
     (autouse, ruling R57) absorbs whatever this module leaves behind,
     which is the "runnable from a dirty ``crm_test``" property that
     fixture's own docstring names. It is also, incidentally, a plain
     sync test module with no Playwright fixtures of its own, so its
     position relative to bucket 3's event-loop concern is moot either
     way — it is placed last for the schema reason, not that one.
  """

  def _path_parts(item: pytest.Item) -> tuple[str, ...]:
    return Path(item.nodeid.split("::", 1)[0]).parts

  def _is_inprocess(item: pytest.Item) -> bool:
    return "inprocess" in _path_parts(item)

  def _is_last_admin_race(item: pytest.Item) -> bool:
    parts = _path_parts(item)
    return bool(parts) and parts[-1] == "test_last_admin_race.py"

  def _is_e2e(item: pytest.Item) -> bool:
    return "e2e" in _path_parts(item)

  inprocess_items = [item for item in items if _is_inprocess(item)]
  last_admin_race_items = [item for item in items if _is_last_admin_race(item)]
  e2e_items = [item for item in items if _is_e2e(item)]
  special = {id(item) for item in inprocess_items + last_admin_race_items + e2e_items}
  other_items = [item for item in items if id(item) not in special]
  items[:] = inprocess_items + other_items + e2e_items + last_admin_race_items


# ---------------------------------------------------------------------------
# Slice B — contacts: three-principal fixtures and HTTP helpers, shared by
# every contact-surface module under tests/access, tests/security and
# tests/concurrency. Defined here, at the root, rather than in a
# sub-package conftest: every consuming module then gets `admin`/`agent_a`/
# `agent_b` as ordinary fixtures with **no import at all**, so a test
# function's own same-named parameter can never collide with an imported
# fixture object (the cross-package-import shape this replaced produced a
# `ruff` `F811 redefinition` on every single test using it — this file's
# fixtures don't have that problem, the same way `admin_session`/
# `agent_client` above never did).
#
# Authority: `contracts/slice-b.md` §2(g) hook 1 ("Three principals":
# bootstrap admin plus two `create-user` agents, each barred from every
# contact route by the forced-reset gate until its own
# `POST /account/password` completes); `ACCESS_MATRIX.md` §1.5 (actors
# `ADM`, `AG-O`, `AG-X`).
#
# Why login is driven fresh per principal here rather than reusing
# `admin_session`/`agent_client` directly: `create-user` sets
# `must_change_password = TRUE` (`app/services/accounts.py`), so a freshly
# provisioned agent's first login lands on `/account/password`, not on any
# contact route — completing that forced change is part of the fixture,
# not an afterthought.
# ---------------------------------------------------------------------------

_CANONICAL_UUID_PATTERN = re.compile(
  r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_CONTACT_LOCATION_PATTERN = re.compile(r"^/contacts/([0-9a-fA-F-]{36})(?:[?].*)?$")


def extract_hidden_field(html: str, name: str) -> str:
  """Pull one hidden-field ``value`` out of a rendered form page, by ``name``.

  Generalizes :func:`extract_csrf_token` to any of the other
  server-generated hidden fields Slice B's mutation forms carry
  (``idempotency_key`` — PIN 1; ``version`` — PIN 3, the concurrency token).

  Parameters
  ----------
  html : str
    A rendered mutation form (``contacts/form.html``, or a detail page's
    embedded archive/restore/reassign form).
  name : str
    The field's ``name`` attribute.

  Returns
  -------
  str

  Raises
  ------
  AssertionError
    If no such hidden field is present.
  """
  pattern = re.compile(rf'<input[^>]*name="{re.escape(name)}"[^>]*value="([^"]*)"', re.IGNORECASE)
  match = pattern.search(html)
  assert match is not None, f"no {name!r} hidden field found in the response body"
  return match.group(1)


@dataclass(frozen=True, slots=True)
class LoggedInPrincipal:
  """One authenticated actor, ready to drive contact routes.

  Attributes
  ----------
  user : ProvisionedUser
    The principal's current (post-forced-reset, where applicable) credentials.
  client : httpx.AsyncClient
    Its own cookie jar, already carrying a full (non-forced) session.
  """

  user: ProvisionedUser
  client: httpx.AsyncClient


async def complete_forced_reset(
  client: httpx.AsyncClient, *, user: ProvisionedUser
) -> ProvisionedUser:
  """Drive ``GET`` -> ``POST /account/password`` so a ``create-user`` agent can reach contacts.

  Every agent Slice B's tests provision is forced to change its password on
  first login (``must_change_password = TRUE``, set by ``create-user``); the
  order step 2 forced-reset gate (``ACCESS_MATRIX.md`` §1.1) would otherwise
  answer every contact route with a ``403`` regardless of ownership, making
  every ``ACC-0xx``/``ACC-1xx`` cell untestable for an agent. Not an
  afterthought — slice-b.md §2(g) hook 1 names this step explicitly.

  Parameters
  ----------
  client : httpx.AsyncClient
    Already logged in (its cookie jar carries the forced-reset session that
    ``POST /login`` just issued).
  user : ProvisionedUser
    The principal's current credentials — ``user.password`` is submitted as
    ``current_password``.

  Returns
  -------
  ProvisionedUser
    The same principal, with ``password`` replaced by the fresh one this
    call set. The caller's client now carries a full, non-forced session.

  Raises
  ------
  AssertionError
    If either leg fails — an honest signal that the forced-reset path
    itself (Slice A, already shipped) regressed, not a Slice B finding.
  """
  get_response = await client.get("/account/password")
  assert get_response.status_code == 200, (
    f"expected the forced-reset change-password form, got {get_response.status_code}"
  )
  csrf_token = extract_csrf_token(get_response.text)
  new_password = f"a fictional post-reset passphrase {uuid.uuid4().hex}"
  post_response = await client.post(
    "/account/password",
    data={
      "csrf_token": csrf_token,
      "current_password": user.password,
      "new_password": new_password,
      "confirm_password": new_password,
    },
  )
  assert post_response.status_code == 303, (
    f"the mandatory forced password change failed (status {post_response.status_code}); "
    "every fixture depending on it assumes it succeeds"
  )
  return ProvisionedUser(email=user.email, name=user.name, password=new_password, role=user.role)


async def _login_contacts_agent(
  http_client_factory: Callable[[], httpx.AsyncClient],
  provision_agent: Callable[[], ProvisionedUser],
) -> LoggedInPrincipal:
  """Provision one fresh agent, log in, complete its forced reset, return it ready to use."""
  user = provision_agent()
  client = http_client_factory()
  login_response = await login_via_http(client, email=user.email, password=user.password)
  assert login_response.status_code == 303, (
    f"first login for a freshly provisioned agent failed (status {login_response.status_code})"
  )
  assert login_response.headers.get("location") == "/account/password", (
    "a freshly create-user'd agent must land on the forced-reset form on its "
    f"first login; got Location: {login_response.headers.get('location')!r}"
  )
  user = await complete_forced_reset(client, user=user)
  return LoggedInPrincipal(user=user, client=client)


@pytest_asyncio.fixture
async def admin(
  admin_session: httpx.AsyncClient, bootstrap_admin: ProvisionedUser
) -> LoggedInPrincipal:
  """``ADM`` — the shared bootstrap admin, already logged in.

  ``bootstrap`` keeps ``must_change_password = FALSE`` by design (R58), so
  no forced-reset step applies here — unlike ``agent_a``/``agent_b`` below.
  """
  return LoggedInPrincipal(user=bootstrap_admin, client=admin_session)


@pytest_asyncio.fixture
async def agent_a(
  http_client_factory: Callable[[], httpx.AsyncClient],
  provision_agent: Callable[[], ProvisionedUser],
) -> LoggedInPrincipal:
  """``AG-O`` for its own objects, ``AG-X`` for ``agent_b``'s — a freshly provisioned agent."""
  return await _login_contacts_agent(http_client_factory, provision_agent)


@pytest_asyncio.fixture
async def agent_b(
  http_client_factory: Callable[[], httpx.AsyncClient],
  provision_agent: Callable[[], ProvisionedUser],
) -> LoggedInPrincipal:
  """The second agent — always foreign (``AG-X``) with respect to ``agent_a``'s objects."""
  return await _login_contacts_agent(http_client_factory, provision_agent)


def normalize_body(body: str) -> str:
  """Replace a canonical-UUID-shaped correlation id with a fixed placeholder.

  Slice B test hook 4 (slice-b.md §2(g)): the byte-identical-404 assertion
  compares two responses for the *same* principal "modulo correlation id" —
  every error page embeds one (``CONTRACTS.md`` §8.4/``SEC-062``), and it is
  freshly generated per request, so a raw ``==`` on two error bodies would
  always fail even when the page is otherwise identical.

  Parameters
  ----------
  body : str
    A rendered response body.

  Returns
  -------
  str
    The same text with every canonical 36-character UUID replaced by
    ``"<cid>"``. This also normalizes any UUID-shaped object id the body
    might otherwise leak, which is fine here: the whole point of the
    identical-404 rule is that *no* id-shaped value may differ between the
    foreign and the missing case.
  """
  return _CANONICAL_UUID_PATTERN.sub("<cid>", body)


def normalized_headers(response: httpx.Response) -> dict[str, str]:
  """Return ``response.headers`` as a plain dict, minus ``Date`` and ``Content-Length``.

  Slice B test hook 4: the identical-404 comparison is also made over
  "response headers minus ``Date`` and ``Content-Length``" — ``Date``
  changes with wall-clock time and ``Content-Length`` tracks the
  correlation id's own text length once it is embedded in the body, so
  both are expected, meaningless differences rather than evidence of a
  behavioural difference.

  Parameters
  ----------
  response : httpx.Response

  Returns
  -------
  dict[str, str]
  """
  return {
    key.lower(): value
    for key, value in response.headers.items()
    if key.lower() not in ("date", "content-length")
  }


@dataclass(frozen=True, slots=True)
class SeededContact:
  """A contact created through the real HTTP surface, for a test to act on.

  Attributes
  ----------
  id : str
    Parsed from the ``303``'s ``Location: /contacts/{id}?notice=...``.
  owner : LoggedInPrincipal
    Whoever created it (``AG-O`` for their own objects).
  """

  id: str
  owner: LoggedInPrincipal


def parse_contact_id_from_location(location: str) -> str:
  """Pull ``{id}`` out of a ``/contacts/{id}...`` ``Location`` header.

  Parameters
  ----------
  location : str
    E.g. ``"/contacts/3fa85f64-5717-4562-b3fc-2c963f66afa6?notice=contact_created"``.

  Returns
  -------
  str

  Raises
  ------
  AssertionError
    If the header does not match the expected shape — an honest failure
    naming what was expected, since a malformed redirect target is itself
    a finding.
  """
  match = _CONTACT_LOCATION_PATTERN.match(location)
  assert match is not None, f"unexpected Location header shape: {location!r}"
  return match.group(1)


async def create_contact(
  principal: LoggedInPrincipal,
  *,
  name: str = "Alice Example",
  company: str = "Acme Corp",
  email: str | None = None,
  phone: str = "+1 555 0100",
  kind: str = "lead",
) -> SeededContact:
  """Drive ``GET /contacts/new`` -> ``POST /contacts`` for one principal, return the new id.

  Parameters
  ----------
  principal : LoggedInPrincipal
    Creates the contact as themselves (``owner_id := scope.actor_id``,
    ``ACC-007`` — never supplied by the caller).
  name, company, phone, kind : str
    Fictional field values (``AGENTS.md``: fictional data only).
  email : str | None
    Defaults to a fresh, unique ``example.test`` address per call so
    repeated calls in one test never collide on anything an accidental
    future unique constraint might add (``contacts.email`` itself carries
    none — ``SQL-022`` — but the fixture stays collision-free regardless).

  Returns
  -------
  SeededContact

  Raises
  ------
  AssertionError
    If either leg does not behave as the contract requires — reported
    honestly, never hidden, until ``app/routes/contacts.py`` ships.
  """
  if email is None:
    email = f"contact+{uuid.uuid4().hex[:12]}@example.test"
  new_form = await principal.client.get("/contacts/new")
  assert new_form.status_code == 200, (
    f"GET /contacts/new failed (status {new_form.status_code}) — contact creation cannot proceed"
  )
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  create_response = await principal.client.post(
    "/contacts",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "name": name,
      "company": company,
      "email": email,
      "phone": phone,
      "kind": kind,
    },
  )
  assert create_response.status_code == 303, (
    f"POST /contacts failed (status {create_response.status_code}); body follows: "
    f"{create_response.text[:500]!r}"
  )
  contact_id = parse_contact_id_from_location(create_response.headers.get("location", ""))
  return SeededContact(id=contact_id, owner=principal)


def fresh_idempotency_key() -> str:
  """Return a fresh ``uuid.uuid4()`` string, for a test that needs to mint its own (PIN 1)."""
  return str(uuid.uuid4())
