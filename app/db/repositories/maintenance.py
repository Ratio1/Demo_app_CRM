"""The **maintenance role's** statements: the demo seed and the demo reset.

Every other repository in this package is scoped — ``conn`` first, a
mandatory :class:`~app.security.principal.Scope` second, the ownership
conjunct written into the SQL. This module is the deliberate exception, and
it is kept apart for exactly that reason: its statements are **unscoped**,
they write rows on behalf of accounts that are not the caller, and two of
them ``DELETE``. Mixing them into ``contacts.py`` or ``deals.py`` would put
an unscoped statement in a file whose whole discipline is that there is not
one.

What keeps that safe is not this module — it is the privilege set. The
runtime role holds no ``DELETE`` on ``contacts``, ``deals`` or
``activities`` at all, so nothing reachable over
HTTP can execute any of this even if it could somehow call it. These
functions run from ``scripts/manage`` alone, as the owner role, in a process
with no session and no request: an infrastructure module takes explicit
ids, never a ``Scope``.

``reset_demo`` deletes in **foreign-key order** — activities, deals,
contacts, then the operational tables — and never touches ``users``,
``app_settings``, ``schema_migrations`` or ``audit_events``: the demo's
business rows go, the accounts, the configuration, the migration journal
and the history of what happened stay (operator decision 7).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, LiteralString

if TYPE_CHECKING:
  from datetime import date, datetime
  from decimal import Decimal
  from uuid import UUID

  from app.db.pool import PoolConnection

__all__ = [
  "DEMO_DELETE_ORDER",
  "count_rows",
  "insert_demo_activity",
  "insert_demo_contact",
  "insert_demo_deal",
  "row_exists",
  "truncate_demo_rows",
]

#: The delete order, foreign keys first. ``activities`` and ``deals`` both
#: reference ``contacts`` with ``ON DELETE RESTRICT``, so the children must go
#: first or the parent delete fails — and failing loudly in the right order is
#: better than a ``CASCADE`` that would silently take rows nobody listed.
#:
#: ``mutation_receipts`` follows the business rows because a receipt points at
#: an object id; ``sessions``, ``login_throttle`` and ``rate_budget`` are
#: operational state that belongs to the demo run rather than to the accounts.
#: ``users``, ``app_settings``, ``schema_migrations`` and ``audit_events`` are
#: **not** in this tuple, and that absence is the contract.
DEMO_DELETE_ORDER: Final[tuple[str, ...]] = (
  "activities",
  "deals",
  "contacts",
  "mutation_receipts",
  "sessions",
  "login_throttle",
  "rate_budget",
)

#: One statement per table, spelled out in full rather than composed from the
#: table name, so nothing here is built by string formatting even under the
#: maintenance role.
_DELETE_SQL: Final[dict[str, LiteralString]] = {
  "activities": "DELETE FROM public.activities",
  "deals": "DELETE FROM public.deals",
  "contacts": "DELETE FROM public.contacts",
  "mutation_receipts": "DELETE FROM public.mutation_receipts",
  "sessions": "DELETE FROM public.sessions",
  "login_throttle": "DELETE FROM public.login_throttle",
  "rate_budget": "DELETE FROM public.rate_budget",
}

_COUNT_SQL: Final[dict[str, LiteralString]] = {
  "activities": "SELECT count(*) FROM public.activities",
  "deals": "SELECT count(*) FROM public.deals",
  "contacts": "SELECT count(*) FROM public.contacts",
}

_EXISTS_SQL: Final[dict[str, LiteralString]] = {
  "activities": "SELECT 1 FROM public.activities WHERE id = %(id)s",
  "deals": "SELECT 1 FROM public.deals WHERE id = %(id)s",
  "contacts": "SELECT 1 FROM public.contacts WHERE id = %(id)s",
}

#: The seed writes complete rows: the demo is data, not a replay of the web
#: path, so `version`, `stage` and every instant are supplied explicitly
#: rather than defaulted — the schema has no DEFAULT clause anywhere.
_INSERT_CONTACT_SQL: Final[LiteralString] = """
INSERT INTO public.contacts
  (id, owner_id, full_name, full_name_lower, company, company_lower, email, email_lower,
   phone, kind, archived_at, version, created_at, updated_at)
VALUES
  (%(id)s, %(owner_id)s, %(full_name)s, %(full_name_lower)s, %(company)s, %(company_lower)s,
   %(email)s, %(email_lower)s, %(phone)s, %(kind)s, NULL, 1, %(now)s, %(now)s)
"""

_INSERT_DEAL_SQL: Final[LiteralString] = """
INSERT INTO public.deals
  (id, contact_id, title, title_lower, amount, close_date, stage,
   stage_changed_at, version, created_at, updated_at)
VALUES
  (%(id)s, %(contact_id)s, %(title)s, %(title_lower)s, %(amount)s, %(close_date)s, %(stage)s,
   %(now)s, 1, %(now)s, %(now)s)
"""

_INSERT_ACTIVITY_SQL: Final[LiteralString] = """
INSERT INTO public.activities
  (id, contact_id, kind, occurred_on, summary, created_by_user_id, created_at)
VALUES
  (%(id)s, %(contact_id)s, %(kind)s, %(occurred_on)s, %(summary)s, %(author_id)s, %(now)s)
"""


async def row_exists(conn: PoolConnection, *, table: str, row_id: UUID) -> bool:
  """Return whether one seeded row is already there (the idempotency probe)."""
  cursor = await conn.execute(_EXISTS_SQL[table], {"id": str(row_id)})
  return await cursor.fetchone() is not None


async def count_rows(conn: PoolConnection, *, table: str) -> int:
  """Return the row count of one demo table, for the command's summary line."""
  cursor = await conn.execute(_COUNT_SQL[table])
  row = await cursor.fetchone()
  return 0 if row is None else int(str(row[0]))


async def insert_demo_contact(
  conn: PoolConnection,
  *,
  contact_id: UUID,
  owner_id: UUID,
  full_name: str,
  company: str,
  email: str,
  phone: str,
  kind: str,
  now: datetime,
) -> None:
  """Write one demo contact, owned by one of the two demo agents."""
  await conn.execute(
    _INSERT_CONTACT_SQL,
    {
      "id": str(contact_id),
      "owner_id": str(owner_id),
      "full_name": full_name,
      "full_name_lower": full_name.lower(),
      "company": company,
      "company_lower": company.lower(),
      "email": email,
      "email_lower": email.lower(),
      "phone": phone,
      "kind": kind,
      "now": now,
    },
  )


async def insert_demo_deal(
  conn: PoolConnection,
  *,
  deal_id: UUID,
  contact_id: UUID,
  title: str,
  amount: Decimal,
  close_date: date,
  stage: str,
  now: datetime,
) -> None:
  """Write one demo deal, already in the stage the seed put it in."""
  await conn.execute(
    _INSERT_DEAL_SQL,
    {
      "id": str(deal_id),
      "contact_id": str(contact_id),
      "title": title,
      "title_lower": title.lower(),
      "amount": amount,
      "close_date": close_date,
      "stage": stage,
      "now": now,
    },
  )


async def insert_demo_activity(
  conn: PoolConnection,
  *,
  activity_id: UUID,
  contact_id: UUID,
  kind: str,
  occurred_on: date,
  summary: str,
  author_id: UUID,
  now: datetime,
) -> None:
  """Write one demo activity, attributed to the contact's own agent."""
  await conn.execute(
    _INSERT_ACTIVITY_SQL,
    {
      "id": str(activity_id),
      "contact_id": str(contact_id),
      "kind": kind,
      "occurred_on": occurred_on,
      "summary": summary,
      "author_id": str(author_id),
      "now": now,
    },
  )


async def truncate_demo_rows(conn: PoolConnection) -> dict[str, int]:
  """Delete every demo business row in foreign-key order, and report the counts.

  Returns
  -------
  dict[str, int]
    Rows removed per table, in :data:`DEMO_DELETE_ORDER`. The caller prints
    the numbers; nothing here decides anything.

  Notes
  -----
  ``DELETE`` and never ``DROP SCHEMA``, ``TRUNCATE`` or ``DROP DATABASE``
  (operator decision 7): the tables, the accounts, the settings, the journal
  and every audit row survive a reset, so the next seed runs against the same
  provisioned database rather than a rebuilt one.
  """
  removed: dict[str, int] = {}
  for table in DEMO_DELETE_ORDER:
    cursor = await conn.execute(_DELETE_SQL[table])
    removed[table] = max(cursor.rowcount, 0)
  return removed
