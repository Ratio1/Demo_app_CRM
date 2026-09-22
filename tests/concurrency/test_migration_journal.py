"""``SQL-024``, ``SQL-025``, ``SQL-026`` — the migration runner's restart/no-op/empty guarantees.

Authority: ``ACCESS_MATRIX.md`` §7 ``SQL-024`` ("the runner is killed
mid-migration and restarted; check-first records the applied-but-unjournaled
step and continues, and the final state equals an uninterrupted run"),
``SQL-025`` ("a second `migrate` run is a no-op — zero DDL executed, journal
unchanged, every check re-verified" — re-verified only when unverified;
already-verified rows are skipped without even a re-check, which is the
stronger, cheaper no-op this module measures), ``SQL-026`` ("migrate from
empty applies every step in order against a freshly reset `crm_test` schema,
with each postcondition TRUE"); ``app/db/journal.py``'s own restart-semantics
docstring (the DDL-then-check-then-journal-write ordering this module drives
directly, by owner-role subprocess, against the real `crm_test` database).

Every mutation here — deleting a journal row, dropping and recreating
`public`, running `migrate` itself — is an owner-role (``crm_test_owner``)
subprocess under ``.env.test.owner.local``, exactly the pattern
``tests/conftest.py``'s own ``crm_test_schema`` fixture uses; this module's
own read-back is the suite's normal runtime-role ``db_connection``, which
holds ``SELECT`` on ``schema_migrations`` (`DATA_CONTRACT.md` §5.2) and
nothing more. **``crm`` is never touched — only ``crm_test``.**

Collection order (see ``tests/conftest.py``'s ``pytest_collection_modifyitems``):
this module is collected **dead last**, after even
``tests/concurrency/test_last_admin_race.py``, because ``SQL-026`` drops and
recreates the whole ``public`` schema (wiping every user, contact and
session the rest of the session's fixtures depend on) — exactly the reason
``test_last_admin_race.py`` itself already runs last among everything else.
A module-scoped, autouse fixture below also runs one more `migrate` at
teardown as a second line of defence, so a database this module leaves
mid-test (a failed assertion partway through ``SQL-024``/``SQL-026``) is
still handed back fully migrated to whatever runs the *next* session's own
``crm_test_schema`` reset.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from conftest import OWNER_ENV_FILE, RUNTIME_ROLE, SUBMODULE_ROOT, VENV_PYTHON, run_with_env

pytestmark = pytest.mark.asyncio

_MIGRATION_ID = "0003_contacts_receipts"
#: An index-postcondition step (§7.1's "index existence has no
#: information_schema view" adaptation point) — a safe, side-effect-free
#: choice for SQL-024's delete-and-readopt probe: its DDL is idempotent-safe
#: to leave untouched (the row is deleted, never the object it describes),
#: and its check is a plain `pg_catalog.pg_class` existence probe with no
#: dependency on any other step's data.
_STEP_ID = "04_ix_contacts_owner_email"

_DROP_RECREATE_PUBLIC_SNIPPET = """
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

_DELETE_JOURNAL_ROW_SNIPPET = """
import asyncio
from typing import Any, cast
from psycopg import AsyncConnection
from app.config import load_config

async def main() -> None:
  kwargs = cast('dict[str, Any]', load_config().connect_kwargs())
  conn = await AsyncConnection.connect(autocommit=True, **kwargs)
  try:
    await conn.execute(
      "DELETE FROM public.schema_migrations "
      "WHERE migration_id = %(migration_id)s AND step_id = %(step_id)s",
      {params},
    )
  finally:
    await conn.close()

asyncio.run(main())
"""


def _run_migrate(log_path: Path) -> None:
  """Run ``python -B -m app.db.journal migrate --grant-to crm_test_app`` (owner role)."""
  run_with_env(
    OWNER_ENV_FILE,
    str(VENV_PYTHON),
    "-B",
    "-m",
    "app.db.journal",
    "migrate",
    "--grant-to",
    RUNTIME_ROLE,
    log_path=log_path,
  )


def _drop_and_recreate_public_schema(*, log_path: Path) -> None:
  """Drop and recreate `public`, leaving `crm_test` schema-empty (owner role, autocommit)."""
  run_with_env(
    OWNER_ENV_FILE, str(VENV_PYTHON), "-B", "-c", _DROP_RECREATE_PUBLIC_SNIPPET, log_path=log_path
  )


def _delete_journal_row(migration_id: str, step_id: str, *, log_path: Path) -> None:
  """Delete one `schema_migrations` row directly (owner role) — simulates a lost journal write.

  The step's DDL is left exactly as it was: only the journal's *record* of
  having applied it disappears, reproducing ``app/db/journal.py``'s own
  documented gap ("a crash can land between the DDL and the journal
  write").
  """
  script = _DELETE_JOURNAL_ROW_SNIPPET.replace(
    "{params}", repr({"migration_id": migration_id, "step_id": step_id})
  )
  run_with_env(OWNER_ENV_FILE, str(VENV_PYTHON), "-B", "-c", script, log_path=log_path)


async def _read_journal_snapshot(
  db_connection: Any,
) -> dict[tuple[str, str], tuple[str, Any, Any]]:
  """Return ``{(migration_id, step_id): (checksum, applied_at, verified_at)}`` for the journal."""
  cursor = await db_connection.execute(
    "SELECT migration_id, step_id, checksum, applied_at, verified_at "
    "FROM public.schema_migrations ORDER BY migration_id, step_id"
  )
  rows = await cursor.fetchall()
  await db_connection.commit()
  return {(str(row[0]), str(row[1])): (str(row[2]), row[3], row[4]) for row in rows}


def _step_report_lines(log_text: str) -> list[str]:
  """Return the per-step report lines `_print_report` writes (two-space indent)."""
  return [line for line in log_text.splitlines() if line.startswith("  ") and "/" in line]


@pytest.fixture(scope="module", autouse=True)
def _restore_fully_migrated_schema_afterwards(
  tmp_path_factory: pytest.TempPathFactory,
) -> Any:
  """Run one more `migrate` at module teardown — belt and braces on top of each test's own state.

  Every test in this module already leaves `crm_test` fully migrated on
  its own (``SQL-024``/``SQL-025`` never remove that property;
  ``SQL-026`` ends with a fresh, complete `migrate`), so this is a second
  line of defence for a database a failed assertion left mid-test, not the
  primary mechanism. This module is collected dead last in the session
  (see the module docstring), so nothing else in *this* run depends on
  what it leaves — the *next* session's autouse `crm_test_schema` reset
  absorbs it regardless.
  """
  yield
  log_path = tmp_path_factory.mktemp("migration_journal_restore") / "final-migrate.log"
  _run_migrate(log_path)


async def test_sql024_restart_recovery_adopts_an_applied_but_unjournaled_step(
  db_connection: Any, tmp_path: Path
) -> None:
  """A step whose DDL already ran but whose journal row was lost is ADOPTED, never re-applied.

  Reproduces `app/db/journal.py`'s own documented restart gap directly:
  the step's effect (an index) is already on disk; only its journal row
  is deleted (owner role). A fresh `migrate` run must record it
  `adopted` — the check-first probe finding the effect already present —
  and every OTHER step's row must come out byte-for-byte identical to
  what it was before, proving nothing else was re-applied or re-verified.
  """
  key = (_MIGRATION_ID, _STEP_ID)
  before = await _read_journal_snapshot(db_connection)
  assert key in before, f"{_MIGRATION_ID}/{_STEP_ID} must already be journaled before this test"

  _delete_journal_row(_MIGRATION_ID, _STEP_ID, log_path=tmp_path / "delete-journal-row.log")

  after_delete = await _read_journal_snapshot(db_connection)
  assert key not in after_delete, "the row must genuinely be gone before the restart-recovery run"
  assert len(after_delete) == len(before) - 1

  _run_migrate(tmp_path / "restart-recovery-migrate.log")
  log_text = (tmp_path / "restart-recovery-migrate.log").read_text(encoding="utf-8")
  report_lines = _step_report_lines(log_text)
  matching = [line for line in report_lines if line.startswith(f"  {_MIGRATION_ID}/{_STEP_ID}  ")]
  assert matching, f"no report line for {_MIGRATION_ID}/{_STEP_ID} in:\n{log_text}"
  assert matching[0].endswith("adopted"), (
    f"expected the deleted step reported 'adopted' (DDL already present, journal row lost), "
    f"got: {matching[0]!r}"
  )

  after = await _read_journal_snapshot(db_connection)
  assert len(after) == len(before), "the final row count must equal the uninterrupted run's"
  assert after[key][0] == before[key][0], "the re-adopted row's checksum must be unchanged"
  for other_key, row in before.items():
    if other_key == key:
      continue
    assert after[other_key] == row, (
      f"{other_key} must be byte-identical to the pre-restart snapshot — restart recovery "
      "must touch only the one unjournaled step"
    )


async def test_sql025_second_migrate_run_is_a_no_op(db_connection: Any, tmp_path: Path) -> None:
  """A second `migrate` run against an already-migrated schema applies and changes nothing."""
  before = await _read_journal_snapshot(db_connection)
  assert before, "the journal must already hold rows from the session's own crm_test_schema reset"

  _run_migrate(tmp_path / "no-op-rerun-migrate.log")
  log_text = (tmp_path / "no-op-rerun-migrate.log").read_text(encoding="utf-8")
  report_lines = _step_report_lines(log_text)
  assert len(report_lines) == len(before), (
    f"expected exactly {len(before)} step report line(s), got {len(report_lines)}:\n{log_text}"
  )
  assert all(line.endswith("already applied") for line in report_lines), (
    f"a no-op rerun must report every step 'already applied' — zero DDL, zero re-verification "
    f"of an already-verified row:\n{log_text}"
  )

  after = await _read_journal_snapshot(db_connection)
  assert after == before, (
    "the journal must be byte-for-byte identical before and after a no-op rerun"
  )


async def test_sql026_migrate_from_empty_applies_every_step_in_order(
  db_connection: Any, tmp_path: Path
) -> None:
  """A fresh `migrate` against a pristine, freshly recreated `public` applies every step, in order.

  Also the first point in the whole suite that genuinely exercises
  `ck_audit_events_denied` and `ck_contacts_kind` from a schema that never
  held them before this very `migrate` call (`ACCESS_MATRIX.md` §7's own
  note on `SQL-026`).

  **One documented exception to "every step applied":** the very first
  step, ``0001_journal/01_schema_migrations``, is reported ``adopted``
  even from a genuinely empty schema — never ``applied`` — because
  ``apply_migrations`` calls :func:`app.db.journal.ensure_journal_table`
  (the identical DDL) *before* the per-step loop ever reaches it, so by
  the time the loop's own check-first probe runs for that step, the table
  already exists. Measured, not assumed: `DECISIONS.md` §5.2's own P0
  row for the (then three-step) `0001_journal` chain reads "migrate from
  empty → 2 applied, **1 adopted**" — the same one-adopted shape this
  test reproduces at 34 steps.
  """
  from app.db.journal import BOOTSTRAP_MIGRATION_ID, BOOTSTRAP_STEP_ID, load_steps

  expected_steps = load_steps(SUBMODULE_ROOT / "migrations")
  expected_total = len(expected_steps)
  assert expected_total > 0, "no migration steps found on disk"
  bootstrap_key = f"{BOOTSTRAP_MIGRATION_ID}/{BOOTSTRAP_STEP_ID}"

  _drop_and_recreate_public_schema(log_path=tmp_path / "drop-recreate-public.log")
  _run_migrate(tmp_path / "migrate-from-empty.log")
  log_text = (tmp_path / "migrate-from-empty.log").read_text(encoding="utf-8")
  report_lines = _step_report_lines(log_text)
  assert len(report_lines) == expected_total, (
    f"expected {expected_total} step report line(s) from an empty schema, got "
    f"{len(report_lines)}:\n{log_text}"
  )
  for line in report_lines:
    report_key, _sep, action = line.strip().partition("  ")
    if report_key == bootstrap_key:
      assert action == "adopted", (
        f"the bootstrap step must be 'adopted' (ensure_journal_table pre-creates it before "
        f"the loop reaches it), got {action!r}:\n{log_text}"
      )
    else:
      assert action == "applied", (
        f"{report_key} must be freshly 'applied' (never 'adopted'/'already applied') from an "
        f"empty schema, got {action!r}:\n{log_text}"
      )
  # In-order: the report lines must read out in exactly `load_steps`' own
  # application order, since a later step's DDL may depend on an earlier
  # one (§1(a): "a table precedes its own indexes, constraints and grant").
  reported_keys = [line.split()[0] for line in report_lines]
  expected_keys = [str(step) for step in expected_steps]
  assert reported_keys == expected_keys, "steps were not applied in load_steps()'s own order"

  after = await _read_journal_snapshot(db_connection)
  assert len(after) == expected_total
  expected_checksums = {step.key: step.checksum for step in expected_steps}
  for key, (checksum, _applied_at, verified_at) in after.items():
    assert checksum == expected_checksums[key], f"{key}: journaled checksum must match the file's"
    assert verified_at is not None, f"{key}: must be verified, not merely recorded as applied"
