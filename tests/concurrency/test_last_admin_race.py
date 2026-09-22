"""The last-active-admin race — SQL-014 / ACC-608.

Authority: ``ACCESS_MATRIX.md`` §7 (SQL-014, ACC-608); ``DATA_CONTRACT.md``
§6.9; ``slice-a.md`` §1.2 (``scripts/manage disable-user``, exit code 3 on
refusal).

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
``conftest.py``. Running the whole suite in one process is safe under
pytest's default (sorted, non-randomized) collection order, because
``tests/concurrency`` sorts before ``tests/security``/``tests/e2e``, so this
module's reset runs and completes before the shared session fixture is
first requested. Running this file **in isolation**
(``pytest tests/concurrency/test_last_admin_race.py``) is always safe and is
the recommended invocation for re-verifying it by hand. A test-order-
randomizing plugin would break this assumption; none is configured here.

Nothing below can run today: ``scripts/manage`` does not exist yet.
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
  a direct assertion on the invariant itself (ACC-608/SQL-014: "exactly
  one active admin remains"), not an inference from process exit status.
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


def _disable(email: str, *, log_path: Path) -> int:
  """Run ``manage disable-user --email <email>``, returning its exit code (never raising)."""
  argv = [
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
  with log_path.open("wb") as log_file:
    completed = subprocess.run(  # noqa: S603
      argv,
      cwd=SUBMODULE_ROOT,
      stdout=log_file,
      stderr=subprocess.STDOUT,
      timeout=30.0,
      check=False,
    )
  return completed.returncode


def test_sql014_two_concurrent_disable_user_races_leave_exactly_one_active_admin(
  isolated_two_admins: tuple[ProvisionedUser, ProvisionedUser],
  tmp_path: Path,
) -> None:
  """20 consecutive concurrent ``disable-user`` pairs each leave exactly one survivor.

  Per iteration: re-provision two active admins (the previous iteration's
  survivor plus one fresh one), then race ``disable-user`` on each against
  the other, concurrently, via ``asyncio.gather`` over two subprocesses.
  Exactly one must exit ``0``; the other must exit ``3`` ("last active
  admin", slice-a.md §1.2) — never both succeeding (would leave 0 active
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
  ended the iteration with exactly one active administrator, which is what
  ACC-608/SQL-014 actually requires.
  """
  import asyncio

  admin_a, admin_b = isolated_two_admins
  survivor_email = admin_a.email
  #: Iteration 0's opponent is the fixture's own second admin; every later
  #: iteration creates a fresh one instead (set back to ``None`` below).
  next_opponent_email: str | None = admin_b.email

  async def _race(email_a: str, email_b: str, iteration: int) -> tuple[int, int]:
    log_a = tmp_path / f"disable-{iteration}-a.log"
    log_b = tmp_path / f"disable-{iteration}-b.log"

    async def _run(email: str, log_path: Path) -> int:
      return await asyncio.to_thread(_disable, email, log_path=log_path)

    result_a, result_b = await asyncio.gather(_run(email_a, log_a), _run(email_b, log_b))
    return result_a, result_b

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
    # active admins, run concurrently — "each removing the other admin"
    # (ACC-608): command A targets the current survivor, command B targets
    # the freshly created one.
    exit_survivor, exit_fresh = asyncio.run(_race(survivor_email, fresh_email, iteration))
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
