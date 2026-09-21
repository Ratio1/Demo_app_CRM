"""The schema manifest the image was built with, and the readiness comparison.

Spec §5: "Runtime verifies schema compatibility." Spec §8: "``/health/ready``
checks DB/schema/provisioning, otherwise ``503``; disclose no internals."

The manifest is the ``(migration_id, step_id, checksum)`` triple of every step
in ``migrations/``, which is copied into the image, so a running replica knows
exactly which schema its code was written against. ``/health/ready`` answers
"ready" only when every one of those triples is present **and verified** in
``schema_migrations`` and the database has been provisioned. That single
comparison does three jobs: it keeps an unmigrated database from serving, it
catches a database migrated by a *newer* image — the old replica fails ready
instead of writing against a schema it does not understand — and it is
therefore the coordinated-upgrade mechanism DEPLOY.md documents.

Nothing here writes. Every function is safe on a pooled connection held by the
DML-only runtime role, and every failure is read as "not ready": a readiness
probe that cannot tell must not answer yes.

The reasons a :class:`ReadyReport` carries are for the structured log only.
The HTTP response body is fixed and discloses nothing, so the reason strings
name a condition, never a value from the database.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING, Final, LiteralString

import psycopg

from app.db.journal import DEFAULT_MIGRATIONS_ROOT, load_steps, read_journal

if TYPE_CHECKING:
  from app.db.journal import JournalConnection

__all__ = [
  "ManifestEntry",
  "ReadyReport",
  "SchemaState",
  "expected_manifest",
  "readiness",
  "schema_state",
]

type ManifestEntry = tuple[str, str, str]

_TABLE_EXISTS_SQL: Final[LiteralString] = """
SELECT EXISTS (
  SELECT 1 FROM information_schema.tables
  WHERE table_schema = 'public' AND table_name = %s
)
"""

#: Provisioning predicates, evaluated in order after the schema check passes.
#:
#: Each entry is ``(reason, table, query)``. The table is probed through
#: ``information_schema`` first, so a database that has not reached the slice
#: that creates it reports "not provisioned" instead of raising. Every query
#: returns one boolean column.
#:
#: **Provisional.** ``app_settings`` and ``users`` are created in slice A and
#: their exact column spellings are pinned by that slice's contract step; this
#: tuple is the one place to reconcile them. Spec §4 requires exactly these two
#: conditions: an administrator and the configured public HTTPS origin, both
#: written by ``scripts/manage bootstrap``.
_PROVISIONING_PROBES: Final[tuple[tuple[str, str, LiteralString], ...]] = (
  (
    "origin-not-set",
    "app_settings",
    "SELECT EXISTS (SELECT 1 FROM public.app_settings WHERE key = 'public_origin' AND value <> '')",
  ),
  (
    "no-active-admin",
    "users",
    "SELECT EXISTS (SELECT 1 FROM public.users WHERE role = 'admin' AND is_active = true)",
  ),
)


@cache
def expected_manifest() -> tuple[ManifestEntry, ...]:
  """Return the manifest this build was made with.

  Returns
  -------
  tuple[ManifestEntry, ...]
    ``(migration_id, step_id, checksum)`` for every step in ``migrations/``,
    in application order.

  Raises
  ------
  app.db.journal.MigrationError
    If ``migrations/`` is missing or malformed. That is a broken image, not a
    runtime condition, and it fails loudly.

  Notes
  -----
  The result is cached for the life of the process: the migrations baked into
  an image never change, and a readiness probe should not re-hash them on
  every request. The first call reads and hashes the files, which is why this
  is a function and not a value computed when the module is imported —
  importing ``app`` must not touch the filesystem.
  """
  steps = load_steps(DEFAULT_MIGRATIONS_ROOT)
  return tuple((step.migration_id, step.step_id, step.checksum) for step in steps)


if TYPE_CHECKING:
  #: The manifest as a module attribute, resolved lazily by ``__getattr__``.
  EXPECTED_MANIFEST: tuple[ManifestEntry, ...]


def __getattr__(name: str) -> object:
  """Resolve ``EXPECTED_MANIFEST`` on first access.

  Parameters
  ----------
  name : str
    The attribute being looked up.

  Returns
  -------
  object
    The value of :func:`expected_manifest` for ``EXPECTED_MANIFEST``.

  Raises
  ------
  AttributeError
    For every other name.

  Notes
  -----
  ``CONTRACTS.md`` §4 names both a module constant and an accessor. A module
  ``__getattr__`` (PEP 562) gives the constant its contracted spelling without
  reading the migrations directory at import time, which ``app/__init__.py``
  forbids.
  """
  if name == "EXPECTED_MANIFEST":
    return expected_manifest()
  raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


@dataclass(frozen=True, slots=True)
class SchemaState:
  """What ``schema_migrations`` says about this database.

  Attributes
  ----------
  journal_present : bool
    ``False`` when the journal table does not exist or is not visible to the
    current role, which means *never migrated*.
  verified : tuple[ManifestEntry, ...]
    Triples whose row carries a ``verified_at``.
  unverified : tuple[ManifestEntry, ...]
    Triples recorded without a ``verified_at``. They do not count as applied.
  """

  journal_present: bool
  verified: tuple[ManifestEntry, ...]
  unverified: tuple[ManifestEntry, ...]


@dataclass(frozen=True, slots=True)
class ReadyReport:
  """The readiness verdict and why.

  Attributes
  ----------
  ready : bool
    ``True`` only when the schema matches the manifest and provisioning is
    complete.
  reasons : tuple[str, ...]
    Fixed condition names for the log, such as ``schema-not-migrated`` or
    ``no-active-admin``. Never a value read from the database, and never the
    HTTP response body.
  """

  ready: bool
  reasons: tuple[str, ...]


async def schema_state(conn: JournalConnection) -> SchemaState:
  """Read the journal and split it into verified and unverified triples.

  Parameters
  ----------
  conn : JournalConnection
    Any connection; the function is read-only.

  Returns
  -------
  SchemaState
    ``journal_present`` is ``False`` and both tuples are empty when the
    journal table is absent.
  """
  rows = await read_journal(conn)
  if not rows:
    present = False
    verified: list[ManifestEntry] = []
    unverified: list[ManifestEntry] = []
  else:
    present = True
    verified = [
      (row.migration_id, row.step_id, row.checksum)
      for row in rows.values()
      if row.verified_at is not None
    ]
    unverified = [
      (row.migration_id, row.step_id, row.checksum)
      for row in rows.values()
      if row.verified_at is None
    ]
  return SchemaState(
    journal_present=present,
    verified=tuple(sorted(verified)),
    unverified=tuple(sorted(unverified)),
  )


async def _table_exists(conn: JournalConnection, table: str) -> bool:
  """Return whether ``public.<table>`` is visible to the current role."""
  cursor = await conn.execute(_TABLE_EXISTS_SQL, (table,))
  row = await cursor.fetchone()
  return bool(row is not None and row[0])


async def _provisioning_reasons(conn: JournalConnection) -> list[str]:
  """Return the names of the provisioning conditions that do not hold."""
  reasons: list[str] = []
  for reason, table, query in _PROVISIONING_PROBES:
    if not await _table_exists(conn, table):
      reasons.append(reason)
      continue
    cursor = await conn.execute(query)
    row = await cursor.fetchone()
    if not (row is not None and row[0] is True):
      reasons.append(reason)
  return reasons


async def readiness(conn: JournalConnection) -> ReadyReport:
  """Decide whether this replica may serve against this database.

  Parameters
  ----------
  conn : JournalConnection
    A connection from the pool, held by the DML-only runtime role. Nothing is
    written.

  Returns
  -------
  ReadyReport
    Ready only when every triple of :func:`expected_manifest` is present and
    verified in ``schema_migrations`` and every provisioning condition holds.

  Notes
  -----
  An exact set comparison, not a subset one in either direction. A missing
  triple means this code expects a step the database has not received; an
  extra triple means the database was migrated by a newer image and this
  replica must not write to it. Both are "not ready", which is what makes a
  coordinated upgrade safe: the old replica takes itself out of rotation
  rather than serving against a schema it was not built for.

  Any :class:`psycopg.Error` is caught and reported as ``database-error``:
  a probe that cannot reach or read the database has not established
  readiness, and spec §6 requires a database failure to close access with a
  sanitized answer rather than an open one.
  """
  try:
    expected = set(expected_manifest())
    state = await schema_state(conn)

    if not state.journal_present:
      return ReadyReport(ready=False, reasons=("schema-not-migrated",))

    reasons: list[str] = []
    present = set(state.verified)
    if expected - present:
      reasons.append("schema-behind-manifest")
    if present - expected:
      reasons.append("schema-ahead-of-manifest")
    if state.unverified:
      reasons.append("schema-step-unverified")
    reasons.extend(await _provisioning_reasons(conn))
  except psycopg.Error:
    return ReadyReport(ready=False, reasons=("database-error",))

  return ReadyReport(ready=not reasons, reasons=tuple(reasons))
