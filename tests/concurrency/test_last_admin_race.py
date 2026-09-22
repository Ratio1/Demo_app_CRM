"""The last-active-admin race: two concurrent disables of the last two admins leave exactly one.

Isolation, documented rather than assumed
-------------------------------------------
Proving the guard needs the total active-admin count to sit at exactly two
before the race, so that exactly one ``disable-user`` may succeed. The
shared, session-scoped ``bootstrap_admin``/``crm_test_schema`` fixtures
cannot be reused for that: other test files log in as that same admin later
in the session, and this module would otherwise have to disable it
out from under them.

This module therefore resets and migrates ``crm_test`` **itself**, in its
own ``module``-scoped fixture, independent of every other fixture in
``conftest.py``.

Collection order
------------------
This module's own reset wipes the schema and bootstraps two admins that
are **not** the shared ``bootstrap_admin``, so it must never run while
anything else in the session still needs the shared admin or the schema
state ``crm_test_schema`` (session-scoped, autouse) established. The real
requirement is stronger than "before tests/security": this module must run
**strictly after every other module in the session**, ``tests/e2e``
included, so that nothing downstream ever asks for
``bootstrap_admin``/``live_server`` again after this module has disabled
and re-created admins out from under them. ``conftest.py``'s
``pytest_collection_modifyitems`` places this exact file dead last for
that reason — see its own docstring for the ordering and why placing it
after ``tests/e2e`` specifically (not merely after ``tests/security``) is
what the guarantee actually requires. Running this file **in isolation**
(``pytest tests/concurrency/test_last_admin_race.py``) is always safe and
is the recommended invocation for re-verifying it by hand.

No ``asyncio`` in this module (deliberately)
------------------------------------------------
The two concurrent ``disable-user`` invocations below are launched with
plain ``subprocess.Popen`` and joined with two ``.wait()`` calls — not
``asyncio.gather``/``asyncio.to_thread`` inside an ``asyncio.run()`` the
way an earlier revision did it. Running ``asyncio.run()`` from a **sync**
test body, in a session where ``tests/e2e``'s pytest-playwright fixtures
have already been set up (which, per the ordering above, they now always
have been by the time this module runs), reproduces exactly the
``Runner.run() cannot be called from a running event loop`` /
"coroutine … was never awaited" corruption ``conftest.py``'s module
docstring documents for ``pytest-asyncio``/``pytest-playwright``
interaction — this module never needs an event loop at all to race two
OS processes, so it does not open one.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import IO, Final

import pytest
from conftest import (
  _RESET_SCHEMA_SNIPPET,  # this module's own isolated reset, see docstring
  MANAGE,
  OWNER_ENV_FILE,
  RUNTIME_ROLE,
  SUBMODULE_ROOT,
  VENV_PYTHON,
  WITH_ENV,
  ProvisionedUser,
  SubprocessFailed,
  run_with_env,
  unique_email,
  write_password_fixture,
)

RACE_REPEAT_COUNT: Final[int] = 20


@pytest.fixture(scope="module")
def isolated_two_admins(
  tmp_path_factory: pytest.TempPathFactory,
) -> tuple[ProvisionedUser, ProvisionedUser]:
  """Reset ``crm_test`` in isolation and provision exactly two active admins.

  Returns
  -------
  tuple[ProvisionedUser, ProvisionedUser]
    ``(admin_a, admin_b)`` — the only two active admins in the database at
    this point.
  """
  log_dir = tmp_path_factory.mktemp("last_admin_race_schema")
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

  admin_a_email = unique_email("admin-a")
  admin_b_email = unique_email("admin-b")
  admin_a_password = "a fictional admin passphrase 1"
  admin_b_password = "a fictional admin passphrase 2"

  password_file = write_password_fixture(log_dir, admin_a_password, name="pw-a")
  try:
    with password_file.open("rb") as stdin_file:
      _run_manage(
        "bootstrap",
        "--email",
        admin_a_email,
        "--name",
        "Admin A",
        "--origin",
        "https://127.0.0.1:65535",
        "--password-stdin",
        stdin=stdin_file,
        log_path=log_dir / "bootstrap.log",
      )
  finally:
    password_file.unlink(missing_ok=True)

  password_file = write_password_fixture(log_dir, admin_b_password, name="pw-b")
  try:
    with password_file.open("rb") as stdin_file:
      _run_manage(
        "create-user",
        "--email",
        admin_b_email,
        "--name",
        "Admin B",
        "--role",
        "admin",
        "--password-stdin",
        stdin=stdin_file,
        log_path=log_dir / "create-user.log",
      )
  finally:
    password_file.unlink(missing_ok=True)

  return (
    ProvisionedUser(email=admin_a_email, name="Admin A", password=admin_a_password, role="admin"),
    ProvisionedUser(email=admin_b_email, name="Admin B", password=admin_b_password, role="admin"),
  )


def _run_manage(
  *args: str, stdin: IO[bytes], log_path: Path, timeout: float = 30.0, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
  """Run ``scripts/manage <args>`` under the owner env file, with a piped stdin."""
  argv = [str(WITH_ENV), OWNER_ENV_FILE, "--", str(VENV_PYTHON), "-B", str(MANAGE), *args]
  with log_path.open("wb") as log_file:
    completed = subprocess.run(  # noqa: S603
      argv,
      cwd=SUBMODULE_ROOT,
      stdin=stdin,
      stdout=log_file,
      stderr=subprocess.STDOUT,
      timeout=timeout,
      check=False,
    )
  if check and completed.returncode != 0:
    raise SubprocessFailed(argv, completed.returncode, log_path)
  return completed


_COUNT_ACTIVE_ADMINS_SNIPPET = """
import asyncio
from typing import Any, cast
from psycopg import AsyncConnection
from app.config import load_config

async def main() -> None:
  kwargs = cast('dict[str, Any]', load_config().connect_kwargs())
  conn = await AsyncConnection.connect(autocommit=True, **kwargs)
  try:
    cur = await conn.execute(
      "SELECT count(*) FROM public.users WHERE role = 'admin' AND is_active = true"
    )
    row = await cur.fetchone()
    print("RESULT count=" + str(row[0]))
  finally:
    await conn.close()

asyncio.run(main())
"""


def _count_active_admins(*, log_path: Path) -> int:
  """Run an owner-role ``SELECT count(*)`` and return the number of active admins.

  Independent of the two subprocesses' exit codes: a bug in the guard's
  own read-after-write logic could in principle exit ``[0, 3]`` for the
  wrong reason while still leaving the database in a bad state, so this is
  a direct assertion on the invariant itself ("exactly one active admin
  remains"), not an inference from process exit status.
  """
  argv = [
    str(WITH_ENV),
    OWNER_ENV_FILE,
    "--",
    str(VENV_PYTHON),
    "-B",
    "-c",
    _COUNT_ACTIVE_ADMINS_SNIPPET,
  ]
  completed = subprocess.run(  # noqa: S603
    argv,
    cwd=SUBMODULE_ROOT,
    capture_output=True,
    text=True,
    timeout=30.0,
    check=False,
  )
  log_path.write_text(
    f"returncode={completed.returncode}\n--- stdout ---\n{completed.stdout}\n"
    f"--- stderr ---\n{completed.stderr}\n",
    encoding="utf-8",
  )
  for line in completed.stdout.splitlines():
    if line.startswith("RESULT count="):
      return int(line.removeprefix("RESULT count="))
  pytest.fail(f"no RESULT line from the active-admin count probe (exit {completed.returncode})")


def test_two_concurrent_disable_user_races_leave_exactly_one_active_admin(
  isolated_two_admins: tuple[ProvisionedUser, ProvisionedUser],
  tmp_path: Path,
) -> None:
  """20 consecutive concurrent ``disable-user`` pairs each leave exactly one survivor.

  Per iteration: re-provision two active admins (the previous iteration's
  survivor plus one fresh one), then race ``disable-user`` on each against
  the other, concurrently, as two ``subprocess.Popen`` processes.
  Exactly one must exit ``0``; the other must exit ``3`` ("last active
  admin") — never both succeeding (would leave 0 active
  admins) and never both failing (would falsely block a legitimate
  disablement).

  Iteration 0 races ``admin_a`` against ``admin_b`` — the fixture's own
  pair — rather than against a freshly created third admin: with three
  admins simultaneously active (``admin_a``, ``admin_b`` and a fresh one),
  disabling any two concurrently is legal and both exit ``0``, since a
  third stays active; the guard is then never exercised. Every later
  iteration races the previous survivor against one freshly created admin,
  so exactly two admins are active immediately before each race, matching
  the invariant this docstring states.

  Each iteration also asserts the invariant directly against the database
  (``_count_active_admins``, an independent owner-role ``SELECT count(*)``),
  not only from the two subprocesses' exit codes: exit codes prove the
  CLI's own view of the outcome, a direct count proves the database itself
  ended the iteration with exactly one active administrator.

  Genuinely concurrent by OS process, not by ``asyncio`` (module docstring):
  both ``disable-user`` subprocesses are started with ``subprocess.Popen``
  before either is waited on, so they race for real; this sync test body
  never opens an event loop.
  """
  admin_a, admin_b = isolated_two_admins
  survivor_email = admin_a.email
  #: Iteration 0's opponent is the fixture's own second admin; every later
  #: iteration creates a fresh one instead (set back to ``None`` below).
  next_opponent_email: str | None = admin_b.email

  def _race(email_a: str, email_b: str, iteration: int) -> tuple[int, int]:
    log_a = tmp_path / f"disable-{iteration}-a.log"
    log_b = tmp_path / f"disable-{iteration}-b.log"

    def _argv(email: str) -> list[str]:
      return [
        str(WITH_ENV),
        OWNER_ENV_FILE,
        "--",
        str(VENV_PYTHON),
        "-B",
        str(MANAGE),
        "disable-user",
        "--email",
        email,
      ]

    with log_a.open("wb") as file_a, log_b.open("wb") as file_b:
      # Both `Popen` calls return before either process is waited on, so
      # the two `disable-user` invocations genuinely overlap in the
      # database rather than merely alternating.
      process_a = subprocess.Popen(  # noqa: S603
        _argv(email_a), cwd=SUBMODULE_ROOT, stdout=file_a, stderr=subprocess.STDOUT
      )
      process_b = subprocess.Popen(  # noqa: S603
        _argv(email_b), cwd=SUBMODULE_ROOT, stdout=file_b, stderr=subprocess.STDOUT
      )
      exit_a = process_a.wait(timeout=30.0)
      exit_b = process_b.wait(timeout=30.0)
    return exit_a, exit_b

  for iteration in range(RACE_REPEAT_COUNT):
    if next_opponent_email is not None:
      fresh_email = next_opponent_email
      next_opponent_email = None
    else:
      fresh_email = unique_email(f"admin-race-{iteration}")
      fresh_password = f"a fictional admin passphrase {iteration}"
      password_file = write_password_fixture(tmp_path, fresh_password, name=f"pw-{iteration}")
      try:
        with password_file.open("rb") as stdin_file:
          _run_manage(
            "create-user",
            "--email",
            fresh_email,
            "--name",
            f"Admin Race {iteration}",
            "--role",
            "admin",
            "--password-stdin",
            stdin=stdin_file,
            log_path=tmp_path / f"create-{iteration}.log",
          )
      finally:
        password_file.unlink(missing_ok=True)

    # Two commands, each targeting a *different* one of the two currently
    # active admins, run concurrently — each removing the other admin:
    # command A targets the current survivor, command B targets the
    # freshly created one.
    exit_survivor, exit_fresh = _race(survivor_email, fresh_email, iteration)
    exits = sorted([exit_survivor, exit_fresh])
    assert exits == [0, 3], (
      f"iteration {iteration}: expected exactly one success (0) and one domain "
      f"refusal (3), got survivor={exit_survivor!r}, fresh={exit_fresh!r}"
    )
    # Exit 0 means that target was disabled; exit 3 means it is still active
    # (the domain refusal fired because disabling it would reach zero) — so
    # whichever target got 3 is the survivor for the next iteration.
    survivor_email = survivor_email if exit_survivor == 3 else fresh_email

    active_admin_count = _count_active_admins(log_path=tmp_path / f"count-{iteration}.log")
    assert active_admin_count == 1, (
      f"iteration {iteration}: expected exactly one active administrator in the "
      f"database after the race, found {active_admin_count}"
    )
