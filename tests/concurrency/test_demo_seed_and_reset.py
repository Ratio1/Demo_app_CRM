"""``scripts/manage seed-demo`` / ``reset-demo`` — the demo-data CLI.

Deliberately **not** ``pytest.mark.asyncio``: this module's owner-role
counts are read through their own subprocess (mirroring
``crm_test_schema``'s own snippets in ``tests/conftest.py``), the same
shape ``test_last_admin_race.py`` and ``test_migration_journal.py`` already
use to stay immune to the pytest-asyncio/pytest-playwright event-loop
interaction ``conftest.py``'s module docstring describes. This module's own
``reset-demo --yes`` deletes every row of every other test module's
fixtures in the shared ``crm_test``, so ``conftest.py``'s
``pytest_collection_modifyitems`` places it in its own trailing bucket,
after ``tests/e2e`` and before ``test_last_admin_race.py`` — see that
hook's docstring for why.

Every count below is read from the database directly (``SELECT count(*)``,
as the owner role), never parsed from ``scripts/manage``'s own printed
summary line: the summary's "now N/N/N" is a *total* row count, and
``crm_test`` is shared across the whole session, so only a **delta** across
one command is independently meaningful here.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Final

from conftest import (
  MANAGE,
  OWNER_ENV_FILE,
  SUBMODULE_ROOT,
  VENV_PYTHON,
  WITH_ENV,
  write_password_fixture,
)

from app.security.passwords import CP_73_BLOCKLISTED, MIN_PASSWORD_LENGTH

#: Every table `reset-demo` touches, plus the four it must leave alone
#: (`app/db/repositories/maintenance.py`'s `DEMO_DELETE_ORDER` and its own
#: "NOT in this tuple" contract).
_DELETED_TABLES: Final[tuple[str, ...]] = (
  "activities",
  "deals",
  "contacts",
  "mutation_receipts",
  "sessions",
  "login_throttle",
  "rate_budget",
)
_PRESERVED_TABLES: Final[tuple[str, ...]] = (
  "users",
  "app_settings",
  "schema_migrations",
  "audit_events",
)
_ALL_TABLES: Final[tuple[str, ...]] = _DELETED_TABLES + _PRESERVED_TABLES

_COUNT_SNIPPET: Final[str] = """
import asyncio
from typing import Any, cast
from psycopg import AsyncConnection
from app.config import load_config

async def main() -> None:
  kwargs = cast('dict[str, Any]', load_config().connect_kwargs())
  conn = await AsyncConnection.connect(autocommit=True, **kwargs)
  try:
    for table in TABLES:
      cursor = await conn.execute(f"SELECT count(*) FROM public.{table}")
      row = await cursor.fetchone()
      print(f"{table}={row[0]}")
  finally:
    await conn.close()

asyncio.run(main())
"""

_COUNT_LINE: Final = re.compile(r"^(\w+)=(\d+)$", re.MULTILINE)

#: A fictional demo-agent password, well inside `MIN_PASSWORD_LENGTH` (15)
#: and `MAX_PASSWORD_LENGTH` (128), and clear of the blocklist and of both
#: demo agents' context words (`scripts/manage`'s `_check_demo_password`) —
#: never logged, never printed, read only from a mode-0600 stdin file.
_DEMO_AGENT_PASSWORD: Final = "a fictional shared passphrase of nine words"

#: Long enough for the length bound, but built from blocklisted words
#: ("demo", "agent") — the regression case below.
_BLOCKLISTED_AGENT_PASSWORD: Final = "a fictional demo agent passphrase, nine words long"


def _counts(tmp_path: Path, *, label: str) -> dict[str, int]:
  """Return `{table: row_count}` for every table this module cares about, as the owner role."""
  script = _COUNT_SNIPPET.replace("TABLES", repr(_ALL_TABLES))
  log_path = tmp_path / f"counts-{label}.log"
  argv = [str(WITH_ENV), OWNER_ENV_FILE, "--", str(VENV_PYTHON), "-B", "-c", script]
  with log_path.open("wb") as log_file:
    completed = subprocess.run(  # noqa: S603
      argv,
      cwd=SUBMODULE_ROOT,
      env=dict(os.environ),
      stdout=log_file,
      stderr=subprocess.STDOUT,
      timeout=60.0,
      check=True,
    )
  assert completed.returncode == 0
  text = log_path.read_text(encoding="utf-8")
  counts = {name: int(value) for name, value in _COUNT_LINE.findall(text)}
  missing = set(_ALL_TABLES) - set(counts)
  assert not missing, f"owner-role count probe produced no line for: {sorted(missing)}"
  return counts


def _run_manage(*args: str, stdin_path: Path, log_path: Path, timeout: float = 60.0) -> int:
  """Run `scripts/manage <args>` as the owner role, feeding `stdin_path` on stdin.

  A local, stdin-carrying sibling of `conftest.py`'s `run_with_env`, needed
  because `seed-demo --agent-password-stdin` reads the password from
  stdin and `run_with_env` itself has no stdin parameter (its callers so
  far have never needed one).
  """
  argv = [str(WITH_ENV), OWNER_ENV_FILE, "--", str(VENV_PYTHON), "-B", str(MANAGE), *args]
  with stdin_path.open("rb") as stdin_file, log_path.open("wb") as log_file:
    completed = subprocess.run(  # noqa: S603
      argv,
      cwd=SUBMODULE_ROOT,
      env=dict(os.environ),
      stdin=stdin_file,
      stdout=log_file,
      stderr=subprocess.STDOUT,
      timeout=timeout,
      check=False,
    )
  return completed.returncode


def test_seed_demo_twice_is_idempotent_and_reset_demo_keeps_accounts_and_audit(
  tmp_path: Path, crm_test_schema: None
) -> None:
  """seed-demo (small) twice writes 20/20/100 once, then nothing; reset-demo (--yes) clears it."""
  del crm_test_schema  # documents the real dependency; already satisfied (session-scoped autouse)
  password_file = write_password_fixture(tmp_path, _DEMO_AGENT_PASSWORD)

  before_seed = _counts(tmp_path, label="00-before-seed")

  seed_log_1 = tmp_path / "seed-1.log"
  exit_code = _run_manage(
    "seed-demo",
    "--scale",
    "small",
    "--agent-password-stdin",
    stdin_path=password_file,
    log_path=seed_log_1,
  )
  assert exit_code == 0, f"seed-demo (run 1) failed (exit {exit_code}) — see {seed_log_1}"
  after_seed_1 = _counts(tmp_path, label="01-after-seed-1")
  assert after_seed_1["contacts"] - before_seed["contacts"] == 20
  assert after_seed_1["deals"] - before_seed["deals"] == 20
  assert after_seed_1["activities"] - before_seed["activities"] == 100
  assert after_seed_1["users"] - before_seed["users"] == 2, "the two demo agents were not created"

  seed_log_2 = tmp_path / "seed-2.log"
  exit_code = _run_manage(
    "seed-demo",
    "--scale",
    "small",
    "--agent-password-stdin",
    stdin_path=password_file,
    log_path=seed_log_2,
  )
  assert exit_code == 0, f"seed-demo (run 2) failed (exit {exit_code}) — see {seed_log_2}"
  after_seed_2 = _counts(tmp_path, label="02-after-seed-2")
  for table in ("contacts", "deals", "activities", "users"):
    assert after_seed_2[table] == after_seed_1[table], (
      f"{table} count changed on a second seed run: {after_seed_1[table]} -> {after_seed_2[table]} "
      "(deterministic uuid5 ids should have made this a no-op)"
    )

  refuse_log = tmp_path / "reset-refuse.log"
  exit_code = _run_manage("reset-demo", stdin_path=password_file, log_path=refuse_log)
  assert exit_code == 2, "reset-demo without --yes must refuse with the usage exit code"
  after_refused_reset = _counts(tmp_path, label="03-after-refused-reset")
  assert after_refused_reset == after_seed_2, "a refused reset-demo must not touch the database"

  reset_log = tmp_path / "reset-yes.log"
  exit_code = _run_manage("reset-demo", "--yes", stdin_path=password_file, log_path=reset_log)
  assert exit_code == 0, f"reset-demo --yes failed (exit {exit_code}) — see {reset_log}"
  after_reset = _counts(tmp_path, label="04-after-reset")
  for table in _DELETED_TABLES:
    assert after_reset[table] == 0, f"{table} not fully cleared by reset-demo --yes"
  assert after_reset["users"] == after_seed_2["users"], "reset-demo must never delete accounts"
  assert after_reset["app_settings"] == after_seed_2["app_settings"], (
    "reset-demo must never touch app_settings (the stored origin)"
  )
  assert after_reset["schema_migrations"] == after_seed_2["schema_migrations"], (
    "reset-demo must never touch the migration journal"
  )
  assert after_reset["audit_events"] == after_seed_2["audit_events"] + 1, (
    "reset-demo must write exactly one demo_reset audit row and delete none"
  )

  reseed_log = tmp_path / "reseed.log"
  exit_code = _run_manage(
    "seed-demo",
    "--scale",
    "small",
    "--agent-password-stdin",
    stdin_path=password_file,
    log_path=reseed_log,
  )
  assert exit_code == 0, f"re-seed after reset failed (exit {exit_code}) — see {reseed_log}"
  after_reseed = _counts(tmp_path, label="05-after-reseed")
  assert after_reseed["contacts"] == 20, "re-run from the same image must produce the same 20"
  assert after_reseed["deals"] == 20
  assert after_reseed["activities"] == 100
  assert after_reseed["users"] == after_seed_2["users"], "no third/fourth demo agent is created"


def test_seed_demo_refuses_a_blocklisted_agent_password(tmp_path: Path) -> None:
  """A long-enough but blocklisted demo-agent password is refused with exit 2, unechoed."""
  assert len(_BLOCKLISTED_AGENT_PASSWORD) >= MIN_PASSWORD_LENGTH, (
    "this case must fail the blocklist, not the length bound"
  )
  password_file = write_password_fixture(
    tmp_path, _BLOCKLISTED_AGENT_PASSWORD, name="pw-blocklisted"
  )
  log_path = tmp_path / "seed-blocklisted.log"

  exit_code = _run_manage(
    "seed-demo",
    "--scale",
    "small",
    "--agent-password-stdin",
    stdin_path=password_file,
    log_path=log_path,
  )

  assert exit_code == 2, (
    f"seed-demo accepted a blocklisted demo-agent password (exit {exit_code}) — see {log_path}"
  )
  text = log_path.read_text(encoding="utf-8")
  assert CP_73_BLOCKLISTED in text, f"the policy message was not reported — see {log_path}"
  assert _BLOCKLISTED_AGENT_PASSWORD not in text, "manage echoed the refused password"
