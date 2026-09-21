"""The checksummed, restartable migration runner and its command-line entry point.

Spec §5: "Use explicit, single-operator, checksummed/restartable migrations:
one DDL statement/step plus verified postcondition. Do not assume transactional
DDL portability."

Layout
------
``migrations/NNNN_name/MM_step.sql``
  Exactly one DDL statement — comments are free — applied as written. Its
  ``sha256`` over the bytes on disk, with no normalization, is the step's
  checksum and goes into the journal.
``migrations/NNNN_name/MM_step.check.sql``
  The postcondition: a query returning exactly one row and one column named
  ``ok``, holding ``true`` when the step's effect is present. It is
  independently runnable, which is what makes restart recovery possible, and
  it is deliberately **not** checksummed: it verifies, it does not apply.

Restart semantics
-----------------
The target database is never assumed blank, so a run reads before it acts: if
a ``schema_migrations`` table is already there in a shape this runner did not
write, the run stops before creating anything.

DDL is not assumed to be transactional, so a crash can land between the DDL
and the journal write. For a step with no journal row the runner therefore
evaluates the postcondition *first*: if it already holds, the step is adopted
into the journal without re-running the DDL; otherwise the DDL runs, the
postcondition is verified, and only then is the row written. A row whose
``verified_at`` is ``NULL`` re-runs the check alone. A row whose checksum
disagrees with the file is a hard failure with no auto-repair.

The whole run is idempotent: a second invocation applies nothing and writes
nothing.

Portability
-----------
No extension, ``SERIAL``, vendor ``UPSERT``, advisory lock, trigger or row
level security appears here or in ``migrations/``. The runner issues each
statement on an autocommit connection, so it never depends on DDL being
transactional, and it requires autocommit rather than switching it on, because
a failed probe inside a transaction would poison every statement after it.

Grants
------
``--grant-to`` names the runtime role and defaults to ``<DB_NAME>_app``, so the
same migrations apply to ``crm`` and to the scratch ``crm_test`` without a
hardcoded role silently targeting the wrong database. A step file asks for it
with ``{grant_to}`` (composed as :class:`psycopg.sql.Identifier`) or
``{grant_to_name}`` (composed as :class:`psycopg.sql.Literal`, for the
privilege-inquiry functions that take a role *name*). Nothing is ever built by
string formatting, and any other brace token is rejected when the steps load.

Entry point
-----------
``python -B -m app.db.journal migrate [--grant-to ROLE] [--dry-run]``
  Exit ``0`` on success, ``1`` on a migration failure, ``2`` on a
  configuration or usage error. ``scripts/manage migrate`` — a Backend-lane
  file — wraps this; it is not created here.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, LiteralString, cast

import psycopg
from psycopg import AsyncConnection, sql
from psycopg.rows import TupleRow

from app.config import ConfigError, load_config

if TYPE_CHECKING:
  from datetime import datetime

__all__ = [
  "BOOTSTRAP_MIGRATION_ID",
  "BOOTSTRAP_STEP_ID",
  "DEFAULT_MIGRATIONS_ROOT",
  "JOURNAL_TABLE_SQL",
  "ROLE_PATTERN",
  "ChecksumMismatch",
  "JournalRow",
  "MigrationError",
  "MigrationReport",
  "MigrationStep",
  "PostconditionFailed",
  "StepOutcome",
  "apply_migrations",
  "ensure_journal_table",
  "load_steps",
  "main",
  "read_journal",
]

type JournalConnection = AsyncConnection[TupleRow]

DEFAULT_MIGRATIONS_ROOT: Final = Path("migrations")

#: ``NNNN_name``: a zero-padded ordinal and a lowercase slug.
MIGRATION_DIR_PATTERN: Final = re.compile(r"^\d{4}_[a-z0-9]+(?:_[a-z0-9]+)*$")
#: ``MM_step``: a zero-padded ordinal and a lowercase slug, within a migration.
STEP_ID_PATTERN: Final = re.compile(r"^\d{2}_[a-z0-9]+(?:_[a-z0-9]+)*$")
#: A PostgreSQL role name this runner is willing to grant to.
ROLE_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_]{0,62}$")

#: The only brace placeholders a step or check file may contain.
GRANT_IDENTIFIER_PLACEHOLDER: Final = "{grant_to}"
GRANT_LITERAL_PLACEHOLDER: Final = "{grant_to_name}"
_ALLOWED_PLACEHOLDERS: Final = frozenset({GRANT_IDENTIFIER_PLACEHOLDER, GRANT_LITERAL_PLACEHOLDER})
_BRACE_PLACEHOLDER_PATTERN: Final = re.compile(r"\{[^{}]*\}")

BOOTSTRAP_MIGRATION_ID: Final = "0001_journal"
BOOTSTRAP_STEP_ID: Final = "01_schema_migrations"

#: The journal table's own DDL, and the single source of truth for it.
#:
#: :func:`ensure_journal_table` executes this before the journal can be read,
#: because a table that records which steps ran cannot itself be gated on a
#: journal lookup. ``migrations/0001_journal/01_schema_migrations.sql`` holds
#: byte-for-byte the same text so the step is checksummed like any other, and
#: :func:`load_steps` fails hard if the two ever drift apart.
JOURNAL_TABLE_SQL: Final[LiteralString] = """\
-- The migration journal itself. app.db.journal.ensure_journal_table runs this
-- statement before reading the journal, and the same text is journaled as the
-- first step so the manifest covers every object the runner creates. CREATE
-- TABLE IF NOT EXISTS keeps both paths idempotent: whichever runs first, the
-- other is a no-op.
CREATE TABLE IF NOT EXISTS public.schema_migrations (
  migration_id TEXT NOT NULL,
  step_id TEXT NOT NULL,
  checksum TEXT NOT NULL,
  applied_at TIMESTAMP WITH TIME ZONE NOT NULL,
  verified_at TIMESTAMP WITH TIME ZONE,
  CONSTRAINT schema_migrations_pkey PRIMARY KEY (migration_id, step_id),
  CONSTRAINT schema_migrations_checksum_length CHECK (char_length(checksum) = 64)
)
"""

_JOURNAL_TABLE_EXISTS_SQL: Final[LiteralString] = """
SELECT EXISTS (
  SELECT 1 FROM information_schema.tables
  WHERE table_schema = 'public' AND table_name = 'schema_migrations'
)
"""

_SELECT_JOURNAL_SQL: Final[LiteralString] = """
SELECT migration_id, step_id, checksum, applied_at, verified_at
FROM public.schema_migrations
ORDER BY migration_id, step_id
"""

_INSERT_JOURNAL_SQL: Final[LiteralString] = """
INSERT INTO public.schema_migrations
  (migration_id, step_id, checksum, applied_at, verified_at)
VALUES (%s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
"""

_MARK_VERIFIED_SQL: Final[LiteralString] = """
UPDATE public.schema_migrations
SET verified_at = CURRENT_TIMESTAMP
WHERE migration_id = %s AND step_id = %s
"""

#: Outcome labels used by :class:`StepOutcome`.
APPLIED: Final = "applied"
ADOPTED: Final = "adopted"
REVERIFIED: Final = "re-verified"
SKIPPED: Final = "already applied"
PLAN_APPLY: Final = "would apply"
PLAN_ADOPT: Final = "would adopt"
PLAN_REVERIFY: Final = "would re-verify"


class MigrationError(RuntimeError):
  """A migration run cannot continue.

  The message names files, steps and roles only. It never contains a
  credential, a parameter value or a record body.
  """


class ChecksumMismatch(MigrationError):
  """A step's file no longer matches the checksum recorded when it was applied.

  There is no auto-repair: an applied migration is history, and rewriting it
  would make the journal a record of what the files say today rather than of
  what the database actually received.
  """


class PostconditionFailed(MigrationError):
  """A step's ``.check.sql`` did not report ``ok``, or did not report at all."""


@dataclass(frozen=True, slots=True)
class MigrationStep:
  """One DDL statement, its postcondition, and the checksum that pins it.

  Attributes
  ----------
  migration_id : str
    The directory name, ``NNNN_name``.
  step_id : str
    The file stem, ``MM_step``.
  sql_path : Path
    The ``.sql`` file holding exactly one DDL statement.
  check_path : Path
    The ``.check.sql`` file holding the postcondition.
  checksum : str
    ``sha256`` hex digest of the ``.sql`` bytes as read, with no
    normalization: no trimming, no line-ending translation, no case folding.
  """

  migration_id: str
  step_id: str
  sql_path: Path
  check_path: Path
  checksum: str

  @property
  def key(self) -> tuple[str, str]:
    """Return the journal key, ``(migration_id, step_id)``."""
    return (self.migration_id, self.step_id)

  def __str__(self) -> str:
    """Return ``migration_id/step_id``, the form used in messages."""
    return f"{self.migration_id}/{self.step_id}"


@dataclass(frozen=True, slots=True)
class JournalRow:
  """One row of ``schema_migrations``.

  Attributes
  ----------
  migration_id : str
    Directory name of the migration.
  step_id : str
    File stem of the step.
  checksum : str
    The checksum recorded when the step was applied or adopted.
  applied_at : datetime
    Server time at which the row was written.
  verified_at : datetime | None
    Server time at which the postcondition last held. ``None`` means the step
    is recorded but unverified, and the runner re-runs its check alone.
  """

  migration_id: str
  step_id: str
  checksum: str
  applied_at: datetime
  verified_at: datetime | None


@dataclass(frozen=True, slots=True)
class StepOutcome:
  """What the runner did — or, in a dry run, would do — with one step.

  Attributes
  ----------
  migration_id : str
    Directory name of the migration.
  step_id : str
    File stem of the step.
  action : str
    One of :data:`APPLIED`, :data:`ADOPTED`, :data:`REVERIFIED`,
    :data:`SKIPPED`, :data:`PLAN_APPLY`, :data:`PLAN_ADOPT` or
    :data:`PLAN_REVERIFY`.
  """

  migration_id: str
  step_id: str
  action: str


@dataclass(frozen=True, slots=True)
class MigrationReport:
  """The result of one :func:`apply_migrations` call.

  Attributes
  ----------
  grant_to : str
    The validated runtime role the grant steps targeted.
  dry_run : bool
    ``True`` when nothing was executed or written.
  outcomes : tuple[StepOutcome, ...]
    One entry per step, in the order the steps were considered.
  """

  grant_to: str
  dry_run: bool
  outcomes: tuple[StepOutcome, ...]

  def count(self, action: str) -> int:
    """Return how many steps ended with ``action``.

    Parameters
    ----------
    action : str
      One of the outcome labels.

    Returns
    -------
    int
      The number of matching outcomes.
    """
    return sum(1 for outcome in self.outcomes if outcome.action == action)


def _validated_role(role: str) -> str:
  """Return ``role`` if it is a role name this runner will grant to.

  Parameters
  ----------
  role : str
    Candidate role name, from ``--grant-to`` or from ``<DB_NAME>_app``.

  Returns
  -------
  str
    The same name.

  Raises
  ------
  MigrationError
    If the name does not match :data:`ROLE_PATTERN`. The name is still
    composed with :class:`psycopg.sql.Identifier` afterwards; this check is a
    second, earlier line of defence that also keeps the error message
    understandable.
  """
  if not ROLE_PATTERN.match(role):
    raise MigrationError(f"not a usable role name: {role!r}")
  return role


def _validated_tokens(text: str, path: Path) -> None:
  """Reject any brace token other than the two the runner composes.

  Parameters
  ----------
  text : str
    The file's decoded contents.
  path : Path
    The file, named in the error message.

  Raises
  ------
  MigrationError
    If a brace token other than ``{grant_to}`` or ``{grant_to_name}`` appears,
    or if an unbalanced brace is left over. Both would otherwise reach
    :meth:`psycopg.sql.SQL.format` and fail late, or silently, or wrongly.
  """
  found = set(_BRACE_PLACEHOLDER_PATTERN.findall(text))
  unknown = found - _ALLOWED_PLACEHOLDERS
  if unknown:
    listed = ", ".join(sorted(unknown))
    raise MigrationError(f"{path}: unsupported placeholder(s): {listed}")
  residue = _BRACE_PLACEHOLDER_PATTERN.sub("", text)
  if "{" in residue or "}" in residue:
    raise MigrationError(f"{path}: unbalanced brace outside a placeholder")


def _load_migration(directory: Path) -> list[MigrationStep]:
  """Load and validate every step of one migration directory.

  Parameters
  ----------
  directory : Path
    A ``NNNN_name`` directory.

  Returns
  -------
  list[MigrationStep]
    The steps in ``MM`` order.

  Raises
  ------
  MigrationError
    If a file name is malformed, a ``.sql`` has no ``.check.sql``, a
    ``.check.sql`` has no ``.sql``, a step is empty, or a placeholder is not
    one of the two supported tokens.
  """
  migration_id = directory.name
  steps: list[MigrationStep] = []
  seen_checks: set[str] = set()

  for path in sorted(directory.iterdir()):
    if path.is_dir():
      raise MigrationError(f"{path}: a migration directory holds files only")
    if path.name.endswith(".check.sql"):
      seen_checks.add(path.name.removesuffix(".check.sql"))
      continue
    if path.suffix != ".sql":
      raise MigrationError(f"{path}: only .sql and .check.sql files belong here")

    step_id = path.stem
    if not STEP_ID_PATTERN.match(step_id):
      raise MigrationError(f"{path}: step file must be named MM_step.sql")

    check_path = path.with_name(f"{step_id}.check.sql")
    if not check_path.is_file():
      raise MigrationError(f"{path}: missing postcondition {check_path.name}")

    raw = path.read_bytes()
    if not raw.strip():
      raise MigrationError(f"{path}: step file is empty")
    _validated_tokens(raw.decode("utf-8"), path)
    _validated_tokens(check_path.read_bytes().decode("utf-8"), check_path)

    is_bootstrap = migration_id == BOOTSTRAP_MIGRATION_ID and step_id == BOOTSTRAP_STEP_ID
    if is_bootstrap and raw != JOURNAL_TABLE_SQL.encode("utf-8"):
      raise MigrationError(
        f"{path}: must match app.db.journal.JOURNAL_TABLE_SQL byte for byte, "
        "because ensure_journal_table executes that constant before the "
        "journal exists and the two must never diverge"
      )

    steps.append(
      MigrationStep(
        migration_id=migration_id,
        step_id=step_id,
        sql_path=path,
        check_path=check_path,
        checksum=hashlib.sha256(raw).hexdigest(),
      )
    )

  orphans = seen_checks - {step.step_id for step in steps}
  if orphans:
    listed = ", ".join(sorted(orphans))
    raise MigrationError(f"{directory}: postcondition(s) with no step: {listed}")
  if not steps:
    raise MigrationError(f"{directory}: migration directory holds no step")
  return steps


def load_steps(root: Path = DEFAULT_MIGRATIONS_ROOT) -> tuple[MigrationStep, ...]:
  """Load every migration step under ``root``, in application order.

  Parameters
  ----------
  root : Path, optional
    The ``migrations/`` directory. Defaults to
    :data:`DEFAULT_MIGRATIONS_ROOT`, which is relative to the working
    directory — the application root both in the image and in a host run.

  Returns
  -------
  tuple[MigrationStep, ...]
    Steps sorted by directory name, then by file name. Because both carry a
    zero-padded ordinal, lexicographic order is application order.

  Raises
  ------
  MigrationError
    If ``root`` is not a directory, holds no migration, holds an entry that is
    not a ``NNNN_name`` directory, is missing the bootstrap step, or contains
    a malformed step.
  """
  if not root.is_dir():
    raise MigrationError(f"{root}: not a migrations directory")

  steps: list[MigrationStep] = []
  for entry in sorted(root.iterdir()):
    if not entry.is_dir() or not MIGRATION_DIR_PATTERN.match(entry.name):
      raise MigrationError(f"{entry}: expected a migration directory named NNNN_name")
    steps.extend(_load_migration(entry))

  if not steps:
    raise MigrationError(f"{root}: holds no migration")
  if steps[0].key != (BOOTSTRAP_MIGRATION_ID, BOOTSTRAP_STEP_ID):
    raise MigrationError(
      f"{root}: the first step must be {BOOTSTRAP_MIGRATION_ID}/{BOOTSTRAP_STEP_ID}, "
      "which creates the journal the runner writes to"
    )
  return tuple(steps)


def _require_autocommit(conn: JournalConnection) -> None:
  """Refuse to migrate on a connection that is not in autocommit mode.

  Parameters
  ----------
  conn : JournalConnection
    The migration connection.

  Raises
  ------
  MigrationError
    If autocommit is off. The runner does not switch it on, because the
    caller's transaction boundaries are the caller's: inside a transaction, a
    probe that legitimately fails — checking a table that does not exist yet —
    aborts every statement that follows it, and the restart logic silently
    stops working. DDL is also not assumed to be transactional, so wrapping a
    run in one transaction would promise an atomicity the database may not
    deliver.
  """
  if not conn.autocommit:
    raise MigrationError("migrations require an autocommit connection")


def _compose(text: str, role: str) -> sql.SQL | sql.Composed:
  """Compose file-held SQL, substituting the runtime role where asked.

  Parameters
  ----------
  text : str
    The decoded contents of a ``.sql`` or ``.check.sql`` file.
  role : str
    The already validated runtime role.

  Returns
  -------
  sql.SQL | sql.Composed
    The statement, with ``{grant_to}`` composed as an identifier and
    ``{grant_to_name}`` as a string literal.

  Notes
  -----
  This is the one place a runtime string becomes SQL, and the cast is what
  makes that visible rather than incidental. It is safe for exactly two
  reasons, both of which stop holding the moment this helper is reused
  elsewhere: the text comes from a file in this repository — never from a
  request, an argument or the database — and the only values interpolated into
  it are composed by :mod:`psycopg.sql`, never by string formatting. Steps
  that need no role are executed from their raw bytes and never reach here.
  """
  # psycopg declares this parameter `LiteralString` precisely so that a runtime
  # string cannot drift into SQL unnoticed. A file-driven migration runner has
  # to hand it one anyway, so it happens once, here, and nowhere else.
  statement = sql.SQL(text)
  return statement.format(grant_to=sql.Identifier(role), grant_to_name=sql.Literal(role))


async def _execute_file(
  conn: JournalConnection, path: Path, role: str
) -> psycopg.AsyncCursor[TupleRow]:
  """Execute the SQL held in ``path``.

  Parameters
  ----------
  conn : JournalConnection
    An autocommit connection.
  path : Path
    A ``.sql`` or ``.check.sql`` file.
  role : str
    The validated runtime role, used only if the file asks for it.

  Returns
  -------
  psycopg.AsyncCursor[TupleRow]
    The cursor, so a postcondition can be read from it.

  Notes
  -----
  A file with no placeholder is passed to psycopg as bytes. psycopg accepts
  bytes as a query and, with no parameters, performs no interpolation at all,
  so a ``%`` inside the DDL cannot be misread and no cast is needed.
  """
  raw = path.read_bytes()
  text = raw.decode("utf-8")
  if GRANT_IDENTIFIER_PLACEHOLDER in text or GRANT_LITERAL_PLACEHOLDER in text:
    return await conn.execute(_compose(text, role))
  return await conn.execute(raw)


async def _check_holds(conn: JournalConnection, step: MigrationStep, role: str) -> bool:
  """Evaluate a step's postcondition.

  Parameters
  ----------
  conn : JournalConnection
    An autocommit connection.
  step : MigrationStep
    The step whose ``.check.sql`` to run.
  role : str
    The validated runtime role.

  Returns
  -------
  bool
    ``True`` only when the check returned exactly one row of exactly one
    column named ``ok`` whose value **is** ``True``. A truthy value of another
    type is rejected, so a check that accidentally returns a count cannot read
    as a pass.

  Raises
  ------
  PostconditionFailed
    If the check's shape is wrong. A database error is not caught here: during
    verification it is a genuine failure, and the adoption probe is the only
    caller that treats one as "not yet applied".
  """
  cursor = await _execute_file(conn, step.check_path, role)
  description = cursor.description
  if description is None or len(description) != 1 or description[0].name != "ok":
    raise PostconditionFailed(f"{step}: {step.check_path.name} must select one column named ok")
  rows = await cursor.fetchall()
  if len(rows) != 1:
    raise PostconditionFailed(
      f"{step}: {step.check_path.name} returned {len(rows)} rows, expected exactly one"
    )
  return rows[0][0] is True


async def _check_already_holds(conn: JournalConnection, step: MigrationStep, role: str) -> bool:
  """Probe a postcondition for a step that has no journal row.

  Parameters
  ----------
  conn : JournalConnection
    An autocommit connection.
  step : MigrationStep
    The step to probe.
  role : str
    The validated runtime role.

  Returns
  -------
  bool
    ``True`` when the step's effect is already present — the crash-between-DDL
    -and-journal-write case — and ``False`` otherwise.

  Notes
  -----
  A database error means the postcondition cannot even be evaluated, which is
  the normal state before the step runs: a check that reads a column of a table
  that does not exist raises ``42P01``. It is therefore read as "not yet
  applied". Autocommit is what makes that safe; inside a transaction the same
  error would abort everything after it. A malformed check still raises, since
  :class:`PostconditionFailed` is not a :class:`psycopg.Error`.
  """
  try:
    return await _check_holds(conn, step, role)
  except psycopg.Error:
    return False


async def _journal_table_exists(conn: JournalConnection) -> bool:
  """Return whether ``public.schema_migrations`` is visible to this role.

  Parameters
  ----------
  conn : JournalConnection
    Any connection, pooled or not.

  Returns
  -------
  bool
    ``True`` when the table exists and the current role holds some privilege
    on it.

  Notes
  -----
  The probe reads ``information_schema.tables`` rather than selecting from the
  table and catching ``42P01``, because this function is also called on a
  pooled, non-autocommit connection by :mod:`app.db.manifest`, where an error
  would abort the surrounding transaction. ``information_schema`` is standard
  SQL and shows only objects the current role may touch, so a runtime role
  without the ``SELECT`` grant correctly reads as "no journal".
  """
  cursor = await conn.execute(_JOURNAL_TABLE_EXISTS_SQL)
  row = await cursor.fetchone()
  return bool(row is not None and row[0])


async def _preflight_journal_shape(
  conn: JournalConnection, steps: Sequence[MigrationStep], role: str
) -> None:
  """Refuse to act on a ``schema_migrations`` table this runner did not write.

  Parameters
  ----------
  conn : JournalConnection
    An autocommit connection.
  steps : Sequence[MigrationStep]
    The loaded steps; the bootstrap step supplies the shape definition.
  role : str
    The validated runtime role, in case the check file asks for it.

  Raises
  ------
  MigrationError
    If a ``schema_migrations`` table exists but the bootstrap step's
    postcondition does not hold for it.

  Notes
  -----
  Read-only, so it runs in a dry run too. When no journal table exists there
  is nothing to disagree with and the function returns at once. The shape is
  taken from ``0001_journal/01_schema_migrations.check.sql`` rather than from
  a second copy of the column list here, so the pre-flight and the
  postcondition can never drift apart.
  """
  bootstrap = next(
    (step for step in steps if step.key == (BOOTSTRAP_MIGRATION_ID, BOOTSTRAP_STEP_ID)),
    None,
  )
  if bootstrap is None or not await _journal_table_exists(conn):
    return
  if not await _check_holds(conn, bootstrap, role):
    raise MigrationError(
      "public.schema_migrations already exists but is not the table this runner "
      f"writes: {bootstrap.check_path} does not hold for it. The database was "
      "not blank and was not migrated by this chain; resolve it by hand rather "
      "than letting CREATE TABLE IF NOT EXISTS adopt a stranger's table"
    )


async def ensure_journal_table(conn: JournalConnection) -> None:
  """Create ``schema_migrations`` if it is not already there.

  Parameters
  ----------
  conn : JournalConnection
    An autocommit connection held by the migration role.

  Raises
  ------
  MigrationError
    If the connection is not in autocommit mode.

  Notes
  -----
  This runs :data:`JOURNAL_TABLE_SQL`, the same text that
  ``migrations/0001_journal/01_schema_migrations.sql`` holds and that
  :func:`load_steps` enforces byte for byte. The statement is
  ``CREATE TABLE IF NOT EXISTS``, so the bootstrap and the journaled step are
  the same idempotent operation seen twice rather than two definitions that
  could disagree.
  """
  _require_autocommit(conn)
  await conn.execute(JOURNAL_TABLE_SQL)


async def read_journal(conn: JournalConnection) -> dict[tuple[str, str], JournalRow]:
  """Read the whole journal, keyed by ``(migration_id, step_id)``.

  Parameters
  ----------
  conn : JournalConnection
    Any connection. The function is read-only and never creates the table, so
    it is safe on a pooled connection held by the DML-only runtime role.

  Returns
  -------
  dict[tuple[str, str], JournalRow]
    Empty when the journal table does not exist, which means *never migrated*.
  """
  if not await _journal_table_exists(conn):
    return {}
  cursor = await conn.execute(_SELECT_JOURNAL_SQL)
  rows = await cursor.fetchall()
  return {
    (str(row[0]), str(row[1])): JournalRow(
      migration_id=str(row[0]),
      step_id=str(row[1]),
      checksum=str(row[2]),
      applied_at=row[3],
      verified_at=row[4],
    )
    for row in rows
  }


async def _record_applied(conn: JournalConnection, step: MigrationStep) -> None:
  """Write the journal row for a step whose postcondition has just been verified."""
  await conn.execute(_INSERT_JOURNAL_SQL, (step.migration_id, step.step_id, step.checksum))


async def _record_verified(conn: JournalConnection, step: MigrationStep) -> None:
  """Stamp ``verified_at`` on an existing journal row."""
  await conn.execute(_MARK_VERIFIED_SQL, (step.migration_id, step.step_id))


async def apply_migrations(
  conn: JournalConnection,
  steps: Sequence[MigrationStep],
  *,
  grant_to: str,
  dry_run: bool = False,
) -> MigrationReport:
  """Bring the database up to ``steps``, restartably and idempotently.

  Parameters
  ----------
  conn : JournalConnection
    An autocommit connection held by the migration role.
  steps : Sequence[MigrationStep]
    Steps in application order, as returned by :func:`load_steps`.
  grant_to : str
    The runtime role the grant steps target. Validated against
    :data:`ROLE_PATTERN` and composed as an identifier, never formatted.
  dry_run : bool, optional
    When ``True`` nothing is executed and nothing is written: the journal and
    the postconditions are read, and the report says what a real run would do.
    The journal table is not created either, so a dry run against a database
    that has never been migrated is purely read-only.

  Returns
  -------
  MigrationReport
    One outcome per step, in order.

  Raises
  ------
  MigrationError
    If the connection is not in autocommit mode, if ``grant_to`` is not a
    usable role name, if ``steps`` is empty, or if a ``schema_migrations``
    table is already there in a shape this runner did not write.
  ChecksumMismatch
    If a step's file no longer matches the checksum recorded for it.
  PostconditionFailed
    If a step's DDL ran but its postcondition did not then hold, or if a
    recorded-but-unverified step still fails its check.

  Notes
  -----
  The run **reads before it acts**. The target database is never assumed
  blank — ``crm`` was provisioned at bootstrap — so before anything is
  created the runner asks whether a journal table is already present and, if
  one is, whether it has the shape this runner writes. It asks with the
  bootstrap step's own ``.check.sql``, so there is one definition of that
  shape rather than two that could drift.

  Without that pre-flight, ``CREATE TABLE IF NOT EXISTS`` would silently
  accept a table of the same name left by some other tool, and the run would
  fail later and less clearly — after the journal had already been consulted
  as though it were ours.
  """
  _require_autocommit(conn)
  role = _validated_role(grant_to)
  if not steps:
    raise MigrationError("no migration steps to apply")

  await _preflight_journal_shape(conn, steps, role)

  if not dry_run:
    await ensure_journal_table(conn)
  journal = await read_journal(conn)

  outcomes: list[StepOutcome] = []
  for step in steps:
    row = journal.get(step.key)

    if row is not None:
      if row.checksum != step.checksum:
        raise ChecksumMismatch(
          f"{step}: the journal records checksum {row.checksum} but "
          f"{step.sql_path} now hashes to {step.checksum}; an applied step is "
          "history and is never rewritten, so resolve this by hand"
        )
      if row.verified_at is not None:
        outcomes.append(StepOutcome(step.migration_id, step.step_id, SKIPPED))
        continue
      if dry_run:
        outcomes.append(StepOutcome(step.migration_id, step.step_id, PLAN_REVERIFY))
        continue
      if not await _check_holds(conn, step, role):
        raise PostconditionFailed(
          f"{step}: recorded as applied but its postcondition does not hold"
        )
      await _record_verified(conn, step)
      outcomes.append(StepOutcome(step.migration_id, step.step_id, REVERIFIED))
      continue

    already = await _check_already_holds(conn, step, role)
    if dry_run:
      action = PLAN_ADOPT if already else PLAN_APPLY
      outcomes.append(StepOutcome(step.migration_id, step.step_id, action))
      continue
    if already:
      await _record_applied(conn, step)
      outcomes.append(StepOutcome(step.migration_id, step.step_id, ADOPTED))
      continue

    await _execute_file(conn, step.sql_path, role)
    if not await _check_holds(conn, step, role):
      raise PostconditionFailed(f"{step}: applied, but its postcondition still does not hold")
    await _record_applied(conn, step)
    outcomes.append(StepOutcome(step.migration_id, step.step_id, APPLIED))

  return MigrationReport(grant_to=role, dry_run=dry_run, outcomes=tuple(outcomes))


async def _connect(kwargs: dict[str, object]) -> JournalConnection:
  """Open one autocommit connection for a migration run.

  Parameters
  ----------
  kwargs : dict[str, object]
    ``Config.connect_kwargs()``: every libpq parameter, explicitly.

  Returns
  -------
  JournalConnection
    An open connection in autocommit mode.

  Notes
  -----
  Migrations use a single direct connection rather than the pool: the pool's
  ``statement_timeout`` is sized for a business request and would cut a large
  index build short, and a migration run is one operator action, not
  concurrent serving traffic.
  """
  # `connect_kwargs` is typed `dict[str, object]` by the frozen contract in
  # app/config.py; psycopg types the same mapping as connection parameters.
  params = cast("dict[str, Any]", kwargs)
  return await AsyncConnection.connect(autocommit=True, **params)


def _build_parser() -> argparse.ArgumentParser:
  """Return the argument parser for ``python -B -m app.db.journal``."""
  parser = argparse.ArgumentParser(
    prog="python -B -m app.db.journal",
    description="Apply the checksummed, restartable migration chain.",
  )
  subcommands = parser.add_subparsers(dest="command", required=True)
  migrate = subcommands.add_parser("migrate", help="apply every outstanding migration step")
  migrate.add_argument(
    "--grant-to",
    default=None,
    metavar="ROLE",
    help="runtime role the grant steps target (default: <DB_NAME>_app)",
  )
  migrate.add_argument(
    "--dry-run",
    action="store_true",
    help="report what would be done; execute nothing and write nothing",
  )
  migrate.add_argument(
    "--migrations-root",
    default=str(DEFAULT_MIGRATIONS_ROOT),
    metavar="DIR",
    help=f"migrations directory (default: {DEFAULT_MIGRATIONS_ROOT})",
  )
  return parser


async def _migrate(grant_to: str | None, root: Path, *, dry_run: bool) -> MigrationReport:
  """Load the steps, connect, and apply them."""
  config = load_config()
  steps = load_steps(root)
  role = grant_to if grant_to is not None else f"{config.dbname}_app"
  conn = await _connect(config.connect_kwargs())
  try:
    return await apply_migrations(conn, steps, grant_to=role, dry_run=dry_run)
  finally:
    await conn.close()


def _print_report(report: MigrationReport) -> None:
  """Print one line per step and a summary. No value from the database is shown."""
  mode = "dry run" if report.dry_run else "migrate"
  print(f"{mode}: grant-to {report.grant_to}, {len(report.outcomes)} step(s)")
  for outcome in report.outcomes:
    print(f"  {outcome.migration_id}/{outcome.step_id}  {outcome.action}")
  if report.dry_run:
    summary = (
      f"{report.count(PLAN_APPLY)} to apply, "
      f"{report.count(PLAN_ADOPT)} to adopt, "
      f"{report.count(PLAN_REVERIFY)} to re-verify, "
      f"{report.count(SKIPPED)} already applied"
    )
  else:
    summary = (
      f"{report.count(APPLIED)} applied, "
      f"{report.count(ADOPTED)} adopted, "
      f"{report.count(REVERIFIED)} re-verified, "
      f"{report.count(SKIPPED)} already applied"
    )
  print(f"{mode}: {summary}")


def main(argv: Sequence[str] | None = None) -> int:
  """Run the command line.

  Parameters
  ----------
  argv : Sequence[str] | None, optional
    Arguments without the program name. ``None`` means :data:`sys.argv`.

  Returns
  -------
  int
    ``0`` on success, ``1`` on a migration failure, ``2`` on a configuration
    error. ``argparse`` exits with ``2`` on a usage error.

  Notes
  -----
  Failures are reported as one line on standard error. A
  :class:`app.config.ConfigError` never carries a value, and a
  :class:`MigrationError` names files, steps and roles only, so both are safe
  to print. A database error is printed through ``str``, which for psycopg is
  the server's own message; it can name an object or a role, never a
  credential.
  """
  args = _build_parser().parse_args(argv)
  try:
    report = asyncio.run(_migrate(args.grant_to, Path(args.migrations_root), dry_run=args.dry_run))
  except ConfigError as error:
    print(f"migrate: configuration error: {error}", file=sys.stderr)
    return 2
  except MigrationError as error:
    print(f"migrate: {error}", file=sys.stderr)
    return 1
  except psycopg.Error as error:
    print(f"migrate: database error: {error}", file=sys.stderr)
    return 1
  _print_report(report)
  return 0


if __name__ == "__main__":
  sys.exit(main())
