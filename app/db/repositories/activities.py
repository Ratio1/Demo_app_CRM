"""``activities`` — append-only child rows, authorized entirely by the parent.

The conventions are ``deals.py``'s, unchanged: ``conn`` first and ``scope``
second on every public function, the ownership
predicate written on the **parent** through
``JOIN public.contacts c ON c.id = a.contact_id``, one ``WHERE`` builder
shared by a page and its count, and a tagged outcome rather than a status
chosen down here.

Two things are specific to this table. There is **no update and no delete
statement anywhere in this module**, because the runtime role holds neither
privilege (``migrations/0005_activities`` step 03): immutability is a grant,
not a missing function. And the author column is nullable, so every read
reaches it through ``LEFT JOIN public.users`` — an inner join would make an
activity vanish from the timeline the moment its author was erased. An
activity must outlive the account that logged it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, LiteralString, cast
from uuid import UUID

from psycopg import sql

from app.db.repositories.deals import parent_state

if TYPE_CHECKING:
  from datetime import date, datetime

  from app.db.pool import PoolConnection
  from app.security.principal import Scope

__all__ = [
  "ACTIVITY_KINDS",
  "DEFAULT_PER_PAGE",
  "MAX_OFFSET",
  "MAX_PER_PAGE",
  "RECENT_LIMIT",
  "SUMMARY_MAX",
  "ActivityFields",
  "ActivityKind",
  "ActivityPage",
  "ActivityRow",
  "CreateOutcome",
  "RecentRow",
  "count_for_contact",
  "insert_activity",
  "list_for_contact",
  "recent_for_dashboard",
]

#: The timeline's page size. Smaller than the 25 of the contact and deal
#: lists: the timeline is a region inside a workspace, not a page of its own.
DEFAULT_PER_PAGE: Final[int] = 10
#: The hard clamp every list surface shares: a larger ``per_page`` is
#: reduced, never refused.
MAX_PER_PAGE: Final[int] = 100
#: The server-side offset clamp: a page past it repeats the last page.
MAX_OFFSET: Final[int] = 10_000
#: The dashboard's recent-activity list.
RECENT_LIMIT: Final[int] = 10
#: ``ck_activities_summary``'s upper bound, mirrored in Python so the CHECK is
#: the second line of defence and never the first.
SUMMARY_MAX: Final[int] = 1000

#: The four values ``ck_activities_kind`` admits, in the order the frozen form
#: renders its radio quad.
type ActivityKind = Literal["note", "call", "email", "meeting"]
ACTIVITY_KINDS: Final[tuple[ActivityKind, ...]] = ("note", "call", "email", "meeting")

#: What :func:`insert_activity` answers. The repository never chooses a status.
type CreateOutcome = Literal["created", "parent_missing", "parent_archived"]

#: The ownership conjunct of a read, aliased on the parent, exactly as
#: ``deals.py`` writes it. Its admin twin is the *absence* of a conjunct.
_READ_OWNED: Final = sql.SQL("AND c.owner_id = %(actor_id)s")
_READ_ANY: Final = sql.SQL("")

#: The dashboard's variant, where the conjunct is the first one in the clause.
_VISIBLE_OWNED: Final = sql.SQL("AND c.owner_id = %(actor_id)s")

#: Every row-returning statement spells its column list out in full, the
#: package convention ``users.py`` set. Alias discipline is absolute — ``a.``
#: for the activity, ``c.`` for the contact, ``u.`` for the author — because
#: ``kind`` and ``created_at`` exist on three tables each.
#:
#: ``LEFT JOIN public.users``: ``created_by_user_id`` is nullable by design
#: (``ON DELETE SET NULL``), and an inner join would silently drop the
#: activities of an erased author from their contact's history.
_LIST_FOR_CONTACT_SQL: Final = sql.SQL("""
SELECT a.id, a.contact_id, a.kind, a.occurred_on, a.summary,
       a.created_by_user_id, u.display_name, a.created_at
  FROM public.activities a
  JOIN public.contacts c ON c.id = a.contact_id
  LEFT JOIN public.users u ON u.id = a.created_by_user_id
 WHERE a.contact_id = %(contact_id)s
   {scope}
 ORDER BY a.occurred_on DESC, a.created_at DESC, a.id DESC
 LIMIT %(limit)s OFFSET %(offset)s
""")

_COUNT_FOR_CONTACT_SQL: Final = sql.SQL("""
SELECT count(*)
  FROM public.activities a
  JOIN public.contacts c ON c.id = a.contact_id
 WHERE a.contact_id = %(contact_id)s
   {scope}
""")

#: The dashboard's recent list. It carries the parent's
#: name and its owner's name, both of which the caller could already read at
#: ``GET /contacts/{id}`` under this same predicate — and **only** activities
#: whose parent is visible **and not archived**, so an archived contact's
#: history does not reappear on the front page after it was archived away.
_RECENT_SQL: Final = sql.SQL("""
SELECT a.id, a.contact_id, c.full_name, o.display_name, a.kind, a.occurred_on,
       a.summary, a.created_by_user_id, u.display_name, a.created_at
  FROM public.activities a
  JOIN public.contacts c ON c.id = a.contact_id
  JOIN public.users    o ON o.id = c.owner_id
  LEFT JOIN public.users u ON u.id = a.created_by_user_id
 WHERE c.archived_at IS NULL
   {scope}
 ORDER BY a.occurred_on DESC, a.created_at DESC, a.id DESC
 LIMIT %(limit)s
""")

#: ``contact_id`` is bound from the argument :func:`parent_state` has just
#: resolved under the scope predicate, in this same transaction; there is no
#: parameter anywhere in this module through which an activity could be moved
#: to another contact afterwards, because no UPDATE exists.
_INSERT_SQL: Final[LiteralString] = """
INSERT INTO public.activities
  (id, contact_id, kind, occurred_on, summary, created_by_user_id, created_at)
VALUES
  (%(id)s, %(contact_id)s, %(kind)s, %(occurred_on)s, %(summary)s, %(author_id)s, %(now)s)
"""


@dataclass(frozen=True, slots=True)
class ActivityRow:
  """One activity as the timeline reads it, with its author's name or ``None``."""

  id: UUID
  contact_id: UUID
  kind: str
  occurred_on: date
  summary: str
  author_id: UUID | None
  author_name: str | None
  created_at: datetime


@dataclass(frozen=True, slots=True)
class RecentRow:
  """One dashboard recent-activity row: the activity plus its parent's facts."""

  id: UUID
  contact_id: UUID
  contact_name: str
  contact_owner_name: str
  kind: str
  occurred_on: date
  summary: str
  author_name: str | None
  created_at: datetime


@dataclass(frozen=True, slots=True)
class ActivityFields:
  """The three writable fields — the dataclass IS the allowlist."""

  kind: str
  occurred_on: date
  summary: str


@dataclass(frozen=True, slots=True)
class ActivityPage:
  """One page of a contact's timeline and the scoped total that goes with it."""

  rows: tuple[ActivityRow, ...]
  total: int
  page: int
  per_page: int


def _read_scope(scope: Scope) -> sql.SQL:
  """Return the ownership conjunct of a read: one of exactly two literals."""
  return _READ_ANY if scope.is_admin else _READ_OWNED


def _dashboard_scope(scope: Scope) -> sql.SQL:
  """Return the dashboard's ownership conjunct, or the empty admin fragment."""
  return _READ_ANY if scope.is_admin else _VISIBLE_OWNED


def _paging(page: int, per_page: int) -> tuple[int, int, int]:
  """Clamp a page request to this module's bounds, as ``deals.py`` does."""
  clamped_page = max(page, 1)
  clamped_per_page = min(max(per_page, 1), MAX_PER_PAGE)
  return clamped_page, clamped_per_page, min((clamped_page - 1) * clamped_per_page, MAX_OFFSET)


def _row_to_activity(row: tuple[object, ...]) -> ActivityRow:
  """Build an :class:`ActivityRow` from one row of the timeline SELECT."""
  author_id = row[5]
  author_name = row[6]
  return ActivityRow(
    id=UUID(str(row[0])),
    contact_id=UUID(str(row[1])),
    kind=str(row[2]),
    occurred_on=cast("date", row[3]),
    summary=str(row[4]),
    author_id=None if author_id is None else UUID(str(author_id)),
    author_name=None if author_name is None else str(author_name),
    created_at=cast("datetime", row[7]),
  )


def _row_to_recent(row: tuple[object, ...]) -> RecentRow:
  """Build a :class:`RecentRow` from one row of the dashboard SELECT."""
  author_name = row[8]
  return RecentRow(
    id=UUID(str(row[0])),
    contact_id=UUID(str(row[1])),
    contact_name=str(row[2]),
    contact_owner_name=str(row[3]),
    kind=str(row[4]),
    occurred_on=cast("date", row[5]),
    summary=str(row[6]),
    author_name=None if author_name is None else str(author_name),
    created_at=cast("datetime", row[9]),
  )


async def count_for_contact(conn: PoolConnection, scope: Scope, *, contact_id: UUID) -> int:
  """Count one contact's activities under the same predicate the page uses."""
  cursor = await conn.execute(
    _COUNT_FOR_CONTACT_SQL.format(scope=_read_scope(scope)),
    {"contact_id": str(contact_id), "actor_id": str(scope.actor_id)},
  )
  row = await cursor.fetchone()
  return 0 if row is None else int(str(row[0]))


async def list_for_contact(
  conn: PoolConnection,
  scope: Scope,
  *,
  contact_id: UUID,
  page: int,
  per_page: int,
) -> ActivityPage:
  """Read one page of a contact's timeline, newest first, with its scoped total.

  Notes
  -----
  **No archive clause**, exactly as ``deals.list_for_contact`` states it: the
  parent read has already decided whether this contact is viewable, and an
  archived contact's workspace must still show the history its owner is about
  to restore (``P-ACTIVITY-TIMELINE-AGENT``).
  """
  scope_fragment = _read_scope(scope)
  clamped_page, clamped_per_page, offset = _paging(page, per_page)
  params: dict[str, object] = {"contact_id": str(contact_id), "actor_id": str(scope.actor_id)}

  cursor = await conn.execute(
    _LIST_FOR_CONTACT_SQL.format(scope=scope_fragment),
    {**params, "limit": clamped_per_page, "offset": offset},
  )
  rows = tuple(_row_to_activity(row) for row in await cursor.fetchall())
  total = await count_for_contact(conn, scope, contact_id=contact_id)
  return ActivityPage(rows=rows, total=total, page=clamped_page, per_page=clamped_per_page)


async def recent_for_dashboard(
  conn: PoolConnection, scope: Scope, *, limit: int
) -> tuple[RecentRow, ...]:
  """Read the newest visible activities across every contact this scope may see."""
  cursor = await conn.execute(
    _RECENT_SQL.format(scope=_dashboard_scope(scope)),
    {"actor_id": str(scope.actor_id), "limit": min(max(limit, 1), MAX_PER_PAGE)},
  )
  return tuple(_row_to_recent(row) for row in await cursor.fetchall())


async def insert_activity(
  conn: PoolConnection,
  scope: Scope,
  *,
  activity_id: UUID,
  contact_id: UUID,
  fields: ActivityFields,
  author_id: UUID,
  now: datetime,
) -> CreateOutcome:
  """Append one activity under a contact the actor may see and that is active.

  Notes
  -----
  The parent is resolved by ``deals.parent_state`` — the **same** statement
  ``POST /contacts/{id}/deals`` uses, so a foreign or missing parent cannot
  answer differently on the two surfaces: the scope predicate decides
  first, the archived state second. This call is the transaction-local
  **guard**; the service's
  own earlier call is the **decision**, taken before any receipt is written.

  ``author_id`` is the actor's own id, never a submitted field: there is no
  parameter through which an activity could be attributed to somebody else.
  """
  state = await parent_state(conn, scope, contact_id=contact_id)
  if state == "missing":
    return "parent_missing"
  if state == "archived":
    return "parent_archived"

  await conn.execute(
    _INSERT_SQL,
    {
      "id": str(activity_id),
      "contact_id": str(contact_id),
      "kind": fields.kind,
      "occurred_on": fields.occurred_on,
      "summary": fields.summary,
      "author_id": str(author_id),
      "now": now,
    },
  )
  return "created"
