"""Activities: the parent check, the receipt, the audit — and no edit path.

The shape is :mod:`app.services.deals`'s, with one outcome type fewer.
There is no ``Stale``, because there is nothing to be stale about: an
activity has no ``version`` and no ``UPDATE`` statement, and the runtime
role holds neither privilege. There is no ``StageTerminal`` and no
``SameStage`` either — an append has no graph.

What is unchanged, deliberately: ownership lives on the **parent**
(``PIN C8``), so ``insert_activity`` has no ``owner_id`` parameter and the
author is the session's own actor; the order inside the transaction is
receipt lookup → scoped parent read → archived parent → receipt insert →
business write → audit (``§1(e)``), so a 409 can never become an existence
oracle; and a foreign or missing parent raises
:class:`~app.security.failures.ContactNotFound`, because
``ACCESS_MATRIX.md`` §4.5 rule 2 says the denied object is the contact.
"""

from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING, Final, Literal

import psycopg

from app.db.repositories import activities as activities_repo
from app.db.repositories import contacts as contacts_repo
from app.db.repositories import deals as deals_repo
from app.db.retry import AmbiguousCommit
from app.security.audit import (
  ACTION_ACTIVITY_CREATED,
  OBJECT_ACTIVITY,
  OUTCOME_SUCCESS,
  record,
)
from app.security.failures import ContactNotFound
from app.security.idempotency import (
  commit_receipt,
  decide,
  mint_key,
  payload_sha256,
  replay_after_conflict,
  settle_ambiguous,
)
from app.services.deals import Blocked, RestoreForm

if TYPE_CHECKING:
  from collections.abc import Mapping
  from uuid import UUID

  from app.db.pool import PoolConnection
  from app.db.repositories.activities import ActivityPage, ActivityRow, RecentRow
  from app.db.repositories.receipts import Operation, ReceiptRow
  from app.db.retry import TransactionRunner
  from app.security.clock import Clock
  from app.security.principal import Scope

__all__ = [
  "ACTIVITY_FIELDS",
  "DEFAULT_PER_PAGE",
  "KIND_LABELS",
  "MAX_PER_PAGE",
  "NOTICE_LOGGED",
  "SUMMARY_MAX",
  "ActivityItemView",
  "Applied",
  "Duplicate",
  "Invalid",
  "RecentItemView",
  "TimelineView",
  "log_activity",
  "recent_for_dashboard",
  "timeline_for_contact",
]

DEFAULT_PER_PAGE: Final[int] = activities_repo.DEFAULT_PER_PAGE
MAX_PER_PAGE: Final[int] = activities_repo.MAX_PER_PAGE
SUMMARY_MAX: Final[int] = activities_repo.SUMMARY_MAX

#: The three writable fields, in the order the digest and the frozen form
#: both use. **The tuple is the allowlist**: there is no ``contact_id`` in it
#: because the parent is resolved from its own body field before any of this
#: runs, and no ``created_by_user_id`` because the author is the session.
ACTIVITY_FIELDS: Final[tuple[str, ...]] = ("kind", "occurred_on", "summary")

#: ``UX_FLOWS.md`` §4.6's four labels, in the radio quad's order.
KIND_LABELS: Final[dict[str, str]] = {
  "note": "Note",
  "call": "Call",
  "email": "Email",
  "meeting": "Meeting",
}

#: ``UX_FLOWS.md`` §6.6 — the ``?notice=`` code and its ``CP-52`` copy.
NOTICE_LOGGED: Final = "activity_logged"

#: ``UX_FLOWS.md`` §6.7, named for their copy ids.
CP_76_KIND_MISSING: Final = "Choose a type."
CP_77_SUMMARY_EMPTY: Final = "Write a short summary."
CP_77_SUMMARY_LONG: Final = "Use 1000 characters or fewer."
CP_75_DATE_MALFORMED: Final = "Enter a date as YYYY-MM-DD."

OP_CREATE: Final[Operation] = "activity_create"

#: ``unique_violation``. Classified by SQLSTATE and never by an exception
#: class name (``DECISIONS.md`` §3). ``activities`` carries no UNIQUE
#: constraint besides its primary key on an application-generated UUID, so a
#: ``23505`` inside this transaction *is* ``uq_mutation_receipts_key``.
_UNIQUE_VIOLATION: Final = "23505"

#: ``CP-75``'s shape. ``date.fromisoformat`` accepts week dates, ordinal
#: dates and a compact ``yyyymmdd`` that ``<input type="date">`` never
#: produces, so the pattern runs first and the constructor second.
_ISO_DATE_RE: Final = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")


@dataclass(frozen=True, slots=True)
class ActivityItemView:
  """One timeline entry, as ``CONTRACTS.md`` §8.3's ``timeline.items`` freezes it."""

  id: UUID
  kind: str
  kind_label: str
  occurred_on: date
  summary: str
  author_name: str | None


@dataclass(frozen=True, slots=True)
class TimelineView:
  """The non-URL half of ``CONTRACTS.md`` §8.3's ``timeline`` sub-context."""

  items: tuple[ActivityItemView, ...]
  total: int
  page: int
  per_page: int
  pages: int
  range_start: int
  range_end: int
  has_prev: bool
  has_next: bool


@dataclass(frozen=True, slots=True)
class RecentItemView:
  """One dashboard recent-activity row (``CONTRACTS.md`` §8.2)."""

  id: UUID
  contact_id: UUID
  contact_name: str
  contact_owner_name: str
  kind: str
  kind_label: str
  occurred_on: date
  summary: str
  author_name: str | None


@dataclass(frozen=True, slots=True)
class Applied:
  """The activity was appended (or had already been): ``303`` + ``?notice=``."""

  activity_id: UUID
  contact_id: UUID
  notice: str
  replayed: bool


@dataclass(frozen=True, slots=True)
class Invalid:
  """Field-level validation failed: ``400``, re-render the workspace's form."""

  errors: dict[str, list[str]]
  values: dict[str, str]


@dataclass(frozen=True, slots=True)
class Duplicate:
  """``409`` ``context="duplicate"`` — same key, different payload (``SQL-028``).

  Carries the **contact**, not the activity: an activity has no page of its
  own (``ACCESS_MATRIX.md`` §1.6 gives it no ``GET`` route at all), so the
  409's "see the record" link can only point at the workspace that holds it.
  """

  contact_id: UUID


class _ParentGuardFired(Exception):
  """``insert_activity`` refused although ``parent_state`` had said ``active``.

  A programming error, never a request-shaped one: the guard and the
  decision run in the same transaction and therefore on the same snapshot.
  The transaction unwinds and the answer is the sanitized 500.
  """


@dataclass(frozen=True, slots=True)
class _Normalized:
  """A submission that passed validation: what to write, and what was typed."""

  fields: activities_repo.ActivityFields
  values: dict[str, str]


def _validate(submitted: Mapping[str, str]) -> Invalid | _Normalized:
  """Normalize and check the three writable fields (``UX_FLOWS.md`` §6.7).

  Notes
  -----
  ``summary`` is stripped before it is measured, so a textarea holding
  nothing but whitespace is ``CP-77``'s "empty" rather than a row of blanks
  in somebody's history. The length bound is checked **after** stripping and
  against the same 1000 as ``ck_activities_summary``, which stays the second
  line of defence.
  """
  errors: dict[str, list[str]] = {}

  kind = submitted.get("kind", "").strip()
  if kind not in KIND_LABELS:
    errors["kind"] = [CP_76_KIND_MISSING]

  raw_date = submitted.get("occurred_on", "").strip()
  occurred_on: date | None = None
  if _ISO_DATE_RE.match(raw_date) is None:
    errors["occurred_on"] = [CP_75_DATE_MALFORMED]
  else:
    try:
      occurred_on = date.fromisoformat(raw_date)
    except ValueError:
      errors["occurred_on"] = [CP_75_DATE_MALFORMED]

  summary = submitted.get("summary", "").strip()
  if not summary:
    errors["summary"] = [CP_77_SUMMARY_EMPTY]
  elif len(summary) > SUMMARY_MAX:
    errors["summary"] = [CP_77_SUMMARY_LONG]

  values = {"kind": kind, "occurred_on": raw_date, "summary": summary}
  if errors or occurred_on is None:
    return Invalid(errors=errors, values=values)
  return _Normalized(
    fields=activities_repo.ActivityFields(kind=kind, occurred_on=occurred_on, summary=summary),
    values=values,
  )


def _item(row: ActivityRow) -> ActivityItemView:
  """Build one timeline entry from a repository row."""
  return ActivityItemView(
    id=row.id,
    kind=row.kind,
    kind_label=KIND_LABELS.get(row.kind, row.kind),
    occurred_on=row.occurred_on,
    summary=row.summary,
    author_name=row.author_name,
  )


def _recent(row: RecentRow) -> RecentItemView:
  """Build one dashboard recent-activity entry from a repository row."""
  return RecentItemView(
    id=row.id,
    contact_id=row.contact_id,
    contact_name=row.contact_name,
    contact_owner_name=row.contact_owner_name,
    kind=row.kind,
    kind_label=KIND_LABELS.get(row.kind, row.kind),
    occurred_on=row.occurred_on,
    summary=row.summary,
    author_name=row.author_name,
  )


def _timeline(page: ActivityPage) -> TimelineView:
  """Turn one repository page into the frozen ``timeline`` sub-context."""
  pages = max(1, math.ceil(page.total / page.per_page))
  offset = (page.page - 1) * page.per_page
  rows = tuple(_item(row) for row in page.rows)
  return TimelineView(
    items=rows,
    total=page.total,
    page=page.page,
    per_page=page.per_page,
    pages=pages,
    range_start=offset + 1 if rows else 0,
    range_end=offset + len(rows) if rows else 0,
    has_prev=page.page > 1,
    has_next=page.page < pages,
  )


async def timeline_for_contact(
  runner: TransactionRunner, scope: Scope, *, contact_id: UUID, page: int, per_page: int
) -> TimelineView:
  """Read one page of a contact's timeline (``ACC-401``-``ACC-404``).

  Notes
  -----
  One short ``READ COMMITTED`` transaction, like every other list region.
  **No archive clause**: the parent read has already decided whether this
  contact is viewable, and an archived contact's workspace still shows the
  history its owner is about to restore.
  """

  async def _read(conn: PoolConnection) -> ActivityPage:
    return await activities_repo.list_for_contact(
      conn, scope, contact_id=contact_id, page=page, per_page=per_page
    )

  return _timeline(await runner.read_committed(_read, op="activity-timeline"))


async def recent_for_dashboard(
  runner: TransactionRunner, scope: Scope, *, limit: int
) -> tuple[RecentItemView, ...]:
  """Read the dashboard's recent-activity list, scoped like every other read."""

  async def _read(conn: PoolConnection) -> tuple[RecentRow, ...]:
    return await activities_repo.recent_for_dashboard(conn, scope, limit=limit)

  return tuple(_recent(row) for row in await runner.read_committed(_read, op="activity-recent"))


async def _blocked_parent(conn: PoolConnection, scope: Scope, *, contact_id: UUID) -> Blocked:
  """Build the 409 ``archived_parent`` payload, the same shape deals build."""
  parent = await contacts_repo.get_contact(conn, scope, contact_id=contact_id)
  if parent is None:
    return Blocked(contact_id=contact_id, contact_name="", restore_form=None)
  restore_form = (
    RestoreForm(idempotency_key=mint_key(), version=parent.version)
    if parent.archived_at is not None
    else None
  )
  return Blocked(contact_id=parent.id, contact_name=parent.full_name, restore_form=restore_form)


async def _replay_in_transaction(
  conn: PoolConnection, scope: Scope, *, receipt: ReceiptRow, contact_id: UUID
) -> Applied:
  """Rebuild the stored answer from the receipt, inside the caller's transaction.

  Notes
  -----
  An activity has no scoped single-row read of its own — nothing links to
  one — so the replay re-resolves the **parent** under the scope predicate
  instead. A parent this principal may no longer see answers the ordinary
  404, exactly as a deal replay does when the deal has moved away.
  """
  state = await _parent_state(conn, scope, contact_id=contact_id)
  if state == "missing":
    raise ContactNotFound(contact_id)
  return Applied(
    activity_id=receipt.result_object_id,
    contact_id=contact_id,
    notice=NOTICE_LOGGED,
    replayed=True,
  )


async def _parent_state(
  conn: PoolConnection, scope: Scope, *, contact_id: UUID
) -> Literal["missing", "archived", "active"]:
  """Resolve the parent by the one statement every child surface shares.

  ``deals.parent_state`` is deliberately reused rather than copied: one
  statement means ``POST /activities`` and ``POST /contacts/{id}/deals``
  cannot 404 differently for the same parent (``PIN C3``, ``ACC-407``).
  """
  return await deals_repo.parent_state(conn, scope, contact_id=contact_id)


async def _replay_fresh(
  runner: TransactionRunner, scope: Scope, *, receipt: ReceiptRow, contact_id: UUID
) -> Applied:
  """Rebuild the stored answer in a **fresh** transaction, after a dead one."""

  async def _read(conn: PoolConnection) -> Applied:
    return await _replay_in_transaction(conn, scope, receipt=receipt, contact_id=contact_id)

  return await runner.read_committed(_read, op="activity-replay-reread")


async def log_activity(
  runner: TransactionRunner,
  clock: Clock,
  scope: Scope,
  *,
  contact_id: UUID,
  submitted: Mapping[str, str],
  key: UUID,
  correlation_id: str,
) -> Applied | Invalid | Blocked | Duplicate:
  """Append one activity to one contact's history (``ACC-405``-``ACC-415``).

  Parameters
  ----------
  contact_id : UUID
    The parent, from the form's hidden field — the frozen form posts to
    ``/activities`` and carries it in the body (``UX_FLOWS.md`` §4.6). It is
    re-resolved **inside** the ``SERIALIZABLE`` transaction under the scope
    predicate, so a body naming somebody else's contact is the identical
    404 and never a write.

  Returns
  -------
  Applied | Invalid | Blocked | Duplicate

  Raises
  ------
  ContactNotFound
    For a foreign parent and for a missing one alike (``ACC-407``).

  Notes
  -----
  Validation runs first, but the **parent** is what decides: a field error
  under a foreign parent still answers 404, because the route re-resolves
  the parent before it renders the errors (``ACCESS_MATRIX.md`` §1.1).

  The id and the instant are generated before the transaction, so every
  ``40001`` retry writes the same row and the receipt's
  ``result_object_id`` is stable.
  """
  validated = _validate(submitted)
  if isinstance(validated, Invalid):
    return validated
  fields = validated.fields
  digest = payload_sha256(
    operation=OP_CREATE,
    target_id=contact_id,
    fields=[(name, validated.values[name]) for name in ACTIVITY_FIELDS],
  )
  now = clock.now()
  activity_id = uuid.uuid4()

  async def _work(conn: PoolConnection) -> Applied | Blocked | Duplicate:
    decision = await decide(
      conn, user_id=scope.actor_id, operation=OP_CREATE, key=key, digest=digest
    )
    if decision.receipt is not None:
      if decision.kind == "duplicate":
        return Duplicate(contact_id=contact_id)
      return await _replay_in_transaction(
        conn, scope, receipt=decision.receipt, contact_id=contact_id
      )
    state = await _parent_state(conn, scope, contact_id=contact_id)
    if state == "missing":
      raise ContactNotFound(contact_id)
    if state == "archived":
      return await _blocked_parent(conn, scope, contact_id=contact_id)
    await commit_receipt(
      conn,
      user_id=scope.actor_id,
      operation=OP_CREATE,
      key=key,
      digest=digest,
      status="created",
      object_type="activity",
      object_id=activity_id,
      now=now,
    )
    outcome = await activities_repo.insert_activity(
      conn,
      scope,
      activity_id=activity_id,
      contact_id=contact_id,
      fields=fields,
      author_id=scope.actor_id,
      now=now,
    )
    if outcome != "created":
      raise _ParentGuardFired
    await record(
      conn,
      actor_id=scope.actor_id,
      object_type=OBJECT_ACTIVITY,
      object_id=activity_id,
      action=ACTION_ACTIVITY_CREATED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return Applied(
      activity_id=activity_id, contact_id=contact_id, notice=NOTICE_LOGGED, replayed=False
    )

  try:
    return await runner.serializable(_work, op=OP_CREATE)
  except AmbiguousCommit as error:
    receipt = await settle_ambiguous(
      runner, error, user_id=scope.actor_id, operation=OP_CREATE, key=key, digest=digest
    )
    return await _replay_fresh(runner, scope, receipt=receipt, contact_id=contact_id)
  except psycopg.Error as error:
    if error.sqlstate != _UNIQUE_VIOLATION:
      raise
    decision = await replay_after_conflict(
      runner, user_id=scope.actor_id, operation=OP_CREATE, key=key, digest=digest
    )
    if decision.receipt is None:
      raise
    if decision.kind == "duplicate":
      return Duplicate(contact_id=contact_id)
    return await _replay_fresh(runner, scope, receipt=decision.receipt, contact_id=contact_id)
