"""Deals: the parent check, the stage graph, the version, the receipt, the audit.

Authority: ``contracts/slice-c.md`` §2(a) (this surface and its seven
outcome types), §1(b)/§1(d) (the repository signatures and the statements
behind them), §1(e) (the nine steps of a Slice C mutation and the
transaction map), ``ACCESS_MATRIX.md`` §1.1 (the check order), §3.3/§3.4
(every cell), §5.1-§5.5 (the field, sort and filter allowlists and the
token map), ``UX_FLOWS.md`` §6.7 (every validation string), **PIN C1**-**PIN
C8** (``DECISIONS.md`` §12).

This module holds **no SQL and no URL**, exactly as
:mod:`app.services.contacts` does: it calls
:mod:`app.db.repositories.deals`, decides which of seven outcomes a
submission has, and returns a view model; :mod:`app.routes.deals` turns
that into a status, a ``Location`` and a template. Five rules make the
authorization boundary a property of the code rather than of a review:

*Ownership lives on the parent.* ``deals`` carries no ``owner_id`` and no
``archived_at`` (**PIN C8**): every read and every write is authorized by
the join to ``contacts``, inside the statement, under a mandatory
:class:`~app.security.principal.Scope`. Owner injection on a deal is
therefore structurally impossible rather than allowlisted — there is no
parameter to inject through (``ACC-212``).

*404 is raised, not returned.* :class:`app.security.failures.DealNotFound`
unwinds the transaction and reaches one handler, so the five deal surfaces
cannot drift apart. A **parent** miss raises
:class:`~app.security.failures.ContactNotFound` instead, because
``ACCESS_MATRIX.md`` §4.5 rule 2 says the denied object is the contact.

*The order inside the transaction is fixed* (§2(a) note 3): receipt →
scope read → archived parent → version → graph → receipt insert →
business write → read-back → audit. Scope before archive before version
before graph is what keeps a ``409`` from becoming an existence oracle: a
``stage_terminal`` for a foreign deal cannot occur, because the scope read
answered ``404`` first.

*The graph is decided on the row this transaction read*, never on what was
submitted, and the stage it read is then passed back into the ``UPDATE``'s
own guard (``from_stage``), so the write can only land on the stage the
decision was made about (**PIN C2**).

*Money is :class:`decimal.Decimal` end to end* (**PIN C1**). Parsing,
canonicalization and rendering live in :mod:`app.services.money`; nothing
here builds a float, and the digest is computed over the **canonical**
amount so ``1250`` and ``1250.00`` are one payload.
"""

from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import TYPE_CHECKING, Final, Literal, cast

import psycopg

from app.db.repositories import contacts as contacts_repo
from app.db.repositories import deals as deals_repo
from app.db.retry import AmbiguousCommit
from app.security.audit import (
  ACTION_DEAL_CREATED,
  ACTION_DEAL_STAGE_CHANGED,
  ACTION_DEAL_UPDATED,
  OBJECT_DEAL,
  OUTCOME_SUCCESS,
  record,
)
from app.security.failures import ContactNotFound, DealNotFound
from app.security.idempotency import (
  commit_receipt,
  decide,
  mint_key,
  payload_sha256,
  replay_after_conflict,
  settle_ambiguous,
)
from app.services.money import AmountError, canonical_amount, parse_amount

if TYPE_CHECKING:
  from collections.abc import Mapping, Sequence
  from datetime import datetime
  from uuid import UUID

  from app.db.pool import PoolConnection
  from app.db.repositories.deals import (
    DealPage,
    DealQuery,
    DealRow,
    DealSortKey,
    DealStage,
    SortDir,
    StatusFilter,
  )
  from app.db.repositories.receipts import Operation, ReceiptRow
  from app.db.retry import TransactionRunner
  from app.security.clock import Clock
  from app.security.principal import Scope

__all__ = [
  "DEAL_FIELDS",
  "DEFAULT_PER_PAGE",
  "LATERAL",
  "MAX_PER_PAGE",
  "STAGE_LABELS",
  "STAGE_ORDER",
  "TERMINAL",
  "TITLE_MAX",
  "Applied",
  "Blocked",
  "DealCardView",
  "DealListView",
  "DealRowView",
  "DealView",
  "Duplicate",
  "Invalid",
  "PipelineView",
  "RestoreForm",
  "SameStage",
  "StageColumn",
  "StageTerminal",
  "Stale",
  "build_deal_query",
  "change_stage",
  "create_for_contact",
  "get_for_detail",
  "list_deals",
  "list_for_contact",
  "pipeline",
  "update_deal",
]

#: Re-exported from the repository so ``app/routes/**`` can read them
#: without importing ``app.db.repositories`` itself, which ``ARC-008``
#: forbids. One definition, in the Data lane's module.
DEFAULT_PER_PAGE: Final[int] = deals_repo.DEFAULT_PER_PAGE
MAX_PER_PAGE: Final[int] = deals_repo.MAX_PER_PAGE
STAGE_ORDER: Final[tuple[str, ...]] = deals_repo.STAGE_ORDER

#: The three writable fields of ``ACCESS_MATRIX.md`` §5.1, in the order the
#: digest and the form both use. **The tuple is the allowlist.**
#: ``contact_id`` and ``stage`` are absent *by construction*: there is no
#: parameter for either, which is what makes ``ACC-211`` (no stage on
#: create) and ``ACC-217`` (no re-parenting) structural rather than
#: enforced by a check somebody could forget.
DEAL_FIELDS: Final[tuple[str, ...]] = ("title", "amount", "close_date")

#: ``ACCESS_MATRIX.md`` §5.4, **PIN C2**. Free movement among the three
#: non-terminal stages; ``won`` and ``lost`` are absorbing. The graph lives
#: here and in no statement: a CHECK cannot see the previous value without
#: a trigger, and triggers are banned (``DATA_CONTRACT.md`` §9.1).
LATERAL: Final[frozenset[str]] = frozenset({"new", "qualified", "proposal"})
TERMINAL: Final[frozenset[str]] = frozenset({"won", "lost"})

#: ``UX_FLOWS.md`` §6.7 ``CP-128``'s status labels.
STAGE_LABELS: Final[dict[str, str]] = {
  "new": "New",
  "qualified": "Qualified",
  "proposal": "Proposal",
  "won": "Won",
  "lost": "Lost",
}

#: ``ck_deals_title``'s bound, mirrored in Python so the database CHECK is
#: the second line of defence and never the first.
TITLE_MAX: Final = 160

#: ``UX_FLOWS.md`` §6.7 — the resolved strings, named for their copy ids.
CP_67_TITLE_REQUIRED: Final = "Enter a title."
CP_61_TOO_LONG_160: Final = "Use 160 characters or fewer."
CP_75_DATE_MALFORMED: Final = "Enter a date as YYYY-MM-DD."

OP_CREATE: Final[Operation] = "deal_create"
OP_UPDATE: Final[Operation] = "deal_update"
OP_STAGE: Final[Operation] = "deal_stage_change"

#: ``?notice=`` codes, resolved **per operation** and not from
#: ``result_status`` (§2(a) note 5, finding F-3): all three stage moves
#: record ``result_status='updated'`` on a ``deal``, and
#: :data:`app.security.idempotency.NOTICE_FOR_STATUS` maps ``"updated"`` to
#: ``contact_saved``, so that table cannot tell a move from an edit — or
#: Won from Lost. The stage half is chosen from the **re-read row**.
NOTICE_CREATED: Final = "deal_created"
NOTICE_SAVED: Final = "deal_saved"
NOTICE_WON: Final = "deal_won"
NOTICE_LOST: Final = "deal_lost"
NOTICE_MOVED: Final = "deal_moved"

#: ``unique_violation``. Classified by SQLSTATE string and never by a
#: psycopg exception class name (``DECISIONS.md`` §3). ``deals`` carries no
#: UNIQUE constraint besides its primary key on an application-generated
#: UUID (§1(a) step 01, conjunct 12), so a ``23505`` inside a Slice C
#: business transaction *is* ``uq_mutation_receipts_key`` and needs no
#: constraint-name inspection.
_UNIQUE_VIOLATION: Final = "23505"

#: ``CP-75``'s shape. ``date.fromisoformat`` accepts several spellings a
#: ``<input type="date">`` never produces, so the pattern runs first and the
#: constructor second — the same two-step
#: :func:`app.security.idempotency.parse_canonical` uses for a UUID.
_ISO_DATE_RE: Final = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")

#: The amount a pipeline column with no deals carries. A code constant, so
#: the only Python value on a money path that the engine did not compute is
#: this literal zero (**PIN C1**, ``ACC-302``).
_ZERO_AMOUNT: Final = Decimal("0.00")


class _ConcurrentStale(Exception):
  """The guarded ``UPDATE`` matched no row although the re-read admitted it.

  Raised from inside the transaction body so the transaction **rolls
  back**: the receipt was written one statement earlier (**R62**), and
  committing it beside a business write that did not happen would make a
  later replay report a success that never occurred. The caller re-reads in
  a fresh transaction and answers 409 ``stale`` — §1(e) step 5's belt and
  braces, with nothing left behind.
  """


class _ParentGuardFired(Exception):
  """``insert_deal`` refused although ``parent_state`` had said ``active``.

  A **programming error**, not a request-shaped one (§1(b)): the guard and
  the decision run in the same transaction and therefore on the same
  snapshot, so the only way they can disagree is a caller that skipped the
  decision. The transaction unwinds and the answer is the sanitized 500 —
  the same choice ``reassign_contact`` makes for an agent ``Scope`` that
  reaches an admin-only statement. Never caught in this module.
  """


@dataclass(frozen=True, slots=True)
class DealView:
  """One deal as its detail screen renders it (``CONTRACTS.md`` §8.2).

  Attributes
  ----------
  id, contact_id : UUID
    The record and its immutable parent (``ACC-217``).
  contact_name : str
    ``contacts.full_name``, for the breadcrumb and the parent line.
  contact_is_archived : bool
    Whether the **parent** is archived. A deal has no archived state of its
    own; it inherits its parent's, which is what ``deals/detail.html``'s
    frozen ``contact.is_archived`` key exists for.
  owner_name : str
    ``users.display_name`` of the parent's owner (§8 rule 4).
  is_own : bool
    Whether the viewer owns the parent, for ``CP-32``'s owner line.
  title : str
    The deal's title.
  amount : Decimal
    Never a float, at any point on this path (**PIN C1**).
  close_date : date | None
    The one nullable column.
  stage, stage_label : str
    The stored value and its ``CP-128`` label.
  stage_changed_at : datetime
    Rewritten on every accepted stage change.
  version : int
    The concurrency token every mutation form carries.
  created_at, updated_at : datetime
    Record timestamps.
  can_edit, can_change_stage : bool
    **UI hiding only** — both false under an archived parent, and
    ``can_change_stage`` false in a terminal stage. Every one of them is
    re-decided server-side, and a crafted ``POST`` still meets 409
    ``archived_parent`` or 409 ``stage_terminal`` (``ACCESS_MATRIX.md``
    §1.4).
  lateral_targets : tuple[tuple[str, str], ...]
    ``(value, label)`` for the legal lateral targets **minus the current
    stage**, so ``ACC-219``'s 400 is unreachable through the UI and still
    enforced server-side. Empty in a terminal stage.
  """

  id: UUID
  contact_id: UUID
  contact_name: str
  contact_is_archived: bool
  owner_name: str
  is_own: bool
  title: str
  amount: Decimal
  close_date: date | None
  stage: str
  stage_label: str
  stage_changed_at: datetime
  version: int
  created_at: datetime
  updated_at: datetime
  can_edit: bool
  can_change_stage: bool
  lateral_targets: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class DealCardView:
  """One deal in a list, a pipeline column or a contact's deal region.

  ``CONTRACTS.md`` §8.3 freezes ``deal_card`` and ``deal_row`` as **one**
  shape, so this is one class; :data:`DealRowView` is its other contracted
  name. The ``url`` and ``contact_url`` keys of that shape are added by the
  route, because this module holds no URL.
  """

  id: UUID
  title: str
  amount: Decimal
  close_date: date | None
  stage: str
  stage_label: str
  contact_id: UUID
  contact_name: str
  owner_name: str
  is_own: bool
  parent_archived: bool


#: ``CONTRACTS.md`` §8.3's second name for the identical shape. An alias
#: rather than a second dataclass: two classes with the same fields would
#: be two places for the inventory to drift from.
DealRowView = DealCardView


@dataclass(frozen=True, slots=True)
class DealListView:
  """The non-URL half of ``CONTRACTS.md`` §8.3's ``results`` for deals.

  Attributes
  ----------
  items : tuple[DealCardView, ...]
    The page's rows, already scoped.
  total : int
    The scoped total — the **identical** ``WHERE`` as ``items`` (§1(d)), so
    a foreign row can never change a total or a page count (``ACC-301``,
    ``ACC-302``).
  page, per_page, pages : int
    The pagination position; ``pages`` is at least one.
  range_start, range_end : int
    1-based inclusive bounds of this page, both ``0`` when it is empty.
  has_prev, has_next : bool
    Whether the two paging controls are live; the route turns ``False``
    into a ``None`` URL, which is **R24**'s inert ``<span>``.
  result_state : {"ok", "empty", "no_results"}
    ``UX_FLOWS.md`` §3.22, computed server-side.
  """

  items: tuple[DealCardView, ...]
  total: int
  page: int
  per_page: int
  pages: int
  range_start: int
  range_end: int
  has_prev: bool
  has_next: bool
  result_state: Literal["ok", "empty", "no_results"]


@dataclass(frozen=True, slots=True)
class StageColumn:
  """One pipeline column: an exact aggregate and a bounded card list.

  Attributes
  ----------
  key, label : str
    The stage and its ``CP-128`` label.
  count : int
    ``count(*)`` under the predicate, from the engine (**PIN C6**).
  amount : Decimal
    ``SUM(d.amount)`` under the predicate, from the engine — never a Python
    sum over ``deals`` (``ACC-302``). An empty stage carries
    ``Decimal("0.00")`` from the zero-fill, which is a code constant and
    not arithmetic.
  deals : tuple[DealCardView, ...]
    The column's cards, **capped** at
    :data:`app.db.repositories.deals.PIPELINE_CARDS_PER_STAGE`. The
    aggregate is authoritative, so ``count`` may exceed ``len(deals)``;
    the template has both and can say so (§1(h) ask **A-4**).
  """

  key: str
  label: str
  count: int
  amount: Decimal
  deals: tuple[DealCardView, ...]


@dataclass(frozen=True, slots=True)
class PipelineView:
  """``deals/pipeline.html``'s ``stages`` — always five, in stage order."""

  stages: tuple[StageColumn, ...]


@dataclass(frozen=True, slots=True)
class RestoreForm:
  """The frozen ``{idempotency_key, version}`` of a parent's restore form."""

  idempotency_key: UUID
  version: int


@dataclass(frozen=True, slots=True)
class Applied:
  """The mutation happened (or had already happened): ``303`` + ``?notice=``.

  Attributes
  ----------
  deal_id : UUID
    The deal the ``Location``'s fragment names.
  contact_id : UUID
    The **parent**, which is what the ``Location`` addresses: every deal
    mutation lands on ``/contacts/{contact_id}…#deal-{deal_id}``
    (``UX_FLOWS.md`` §2 step 6). The receipt stores only the deal id, so a
    replay re-reads the deal to find it — which is also where the stage
    that ``deal_moved`` names comes from.
  notice : str
    The ``?notice=`` code, resolved per **operation** (§2(a) note 5).
  replayed : bool
    ``True`` when this answer came from a stored receipt rather than from a
    write. The user sees the same page either way.
  """

  deal_id: UUID
  contact_id: UUID
  notice: str
  replayed: bool


@dataclass(frozen=True, slots=True)
class Invalid:
  """Field-level validation failed: ``400``, re-render the originating form."""

  errors: dict[str, list[str]]


@dataclass(frozen=True, slots=True)
class Stale:
  """``409`` ``context="stale"`` — the deal moved under the editor (**PIN 3**).

  Attributes
  ----------
  deal_id : UUID
    The record.
  current : DealView
    The row as it now stands, re-read under the scope predicate.
  submitted : Mapping[str, str]
    The **normalized** submitted values, so trailing whitespace is never
    reported as a change. A stage change carries its single ``to_stage``.
  version : int
    The **current** version, re-issued in ``keep_form``.
  idempotency_key : UUID
    A **fresh** key: re-posting the submitted one would meet the receipt
    and answer 409 ``duplicate``, which explains nothing.
  """

  deal_id: UUID
  current: DealView
  submitted: Mapping[str, str]
  version: int
  idempotency_key: UUID


@dataclass(frozen=True, slots=True)
class Blocked:
  """``409`` ``context="archived_parent"`` (``ACC-208``/``216``/``222``/``229``).

  Attributes
  ----------
  contact_id : UUID
    The archived parent.
  contact_name : str
    Its ``full_name``, for the heading.
  restore_form : RestoreForm | None
    The parent's real restore ``POST``, when this principal can see the
    contact to restore it; ``None`` when the parent could not be re-read.
  """

  contact_id: UUID
  contact_name: str
  restore_form: RestoreForm | None


@dataclass(frozen=True, slots=True)
class StageTerminal:
  """``409`` ``context="stage_terminal"`` — the deal is closed (``ACC-220``)."""

  deal_id: UUID
  stage_label: str


@dataclass(frozen=True, slots=True)
class SameStage:
  """``400`` — a move to the stage the deal is already in (``ACC-219``).

  Unreachable through the UI, because the ``<select>`` omits the current
  stage (§2(d)); a crafted ``POST`` meets it server-side. *"A no-op is not
  a mutation and gets no receipt"* — and it writes **no deny row** either
  (§2(a) note 7): it is a conflict decision about a row the actor may see,
  not an allowlist rejection.
  """

  deal_id: UUID


@dataclass(frozen=True, slots=True)
class Duplicate:
  """``409`` ``context="duplicate"`` — same key, different payload (``SQL-028``)."""

  deal_id: UUID


@dataclass(frozen=True, slots=True)
class _Normalized:
  """A submission that passed validation: what to write, and what was typed."""

  fields: deals_repo.DealFields
  values: dict[str, str]


def _validate(submitted: Mapping[str, str]) -> Invalid | _Normalized:
  """Normalize and check the three writable fields (``UX_FLOWS.md`` §6.7).

  Parameters
  ----------
  submitted : Mapping[str, str]
    The three wire names of :data:`DEAL_FIELDS`, each present — the route
    supplies ``""`` for a field the body omitted.

  Returns
  -------
  Invalid | _Normalized
    ``Invalid`` carries one list of strings per failing field, keyed by the
    wire name so the error summary can link to the control (**R28**).

  Notes
  -----
  ``title_lower`` is length-checked as well as ``title``: lowercasing can
  lengthen a string — ``'İ'.lower()`` is two characters — so a title that
  passes at 160 characters can produce a ``title_lower`` that violates
  ``ck_deals_title_lower``. Checking the derived value keeps that a field
  error instead of a 500.

  ``close_date`` is checked against the ISO shape **before**
  :meth:`datetime.date.fromisoformat`, which in 3.12 also accepts week
  dates, ordinal dates and a compact ``yyyymmdd`` that ``<input
  type="date">`` never produces. An impossible calendar date — ``2026-02-30``
  — passes the pattern and fails the constructor, and both answer
  ``CP-75``.
  """
  errors: dict[str, list[str]] = {}
  title = submitted.get("title", "").strip()
  title_lower = title.lower()
  if not title:
    errors["title"] = [CP_67_TITLE_REQUIRED]
  elif len(title) > TITLE_MAX or len(title_lower) > TITLE_MAX:
    errors["title"] = [CP_61_TOO_LONG_160]

  amount = parse_amount(submitted.get("amount", ""))
  if isinstance(amount, AmountError):
    errors["amount"] = [amount.message]

  raw_close = submitted.get("close_date", "").strip()
  close_date: date | None = None
  if raw_close:
    if _ISO_DATE_RE.match(raw_close) is None:
      errors["close_date"] = [CP_75_DATE_MALFORMED]
    else:
      try:
        close_date = date.fromisoformat(raw_close)
      except ValueError:
        errors["close_date"] = [CP_75_DATE_MALFORMED]

  if errors or isinstance(amount, AmountError):
    return Invalid(errors=errors)
  return _Normalized(
    fields=deals_repo.DealFields(
      title=title,
      title_lower=title_lower,
      amount=amount,
      close_date=close_date,
    ),
    values={
      "title": title,
      # The **canonical** spelling, not what was typed: it is what the
      # digest hashes, so `1250` resubmitted after `1250.00` replays
      # instead of answering a spurious 409 duplicate (ask A-6).
      "amount": canonical_amount(amount),
      "close_date": "" if close_date is None else close_date.isoformat(),
    },
  )


def _digest_fields(values: Mapping[str, str]) -> Sequence[tuple[str, str]]:
  """Return the declared fields as digest pairs, in :data:`DEAL_FIELDS` order."""
  return [(name, values[name]) for name in DEAL_FIELDS]


def _lateral_targets(stage: str) -> tuple[tuple[str, str], ...]:
  """Return the legal lateral targets for ``stage``, minus ``stage`` itself.

  Parameters
  ----------
  stage : str
    The stage the deal is in, as this transaction read it.

  Returns
  -------
  tuple[tuple[str, str], ...]
    ``(value, label)`` pairs in :data:`STAGE_ORDER` order, or ``()`` for a
    terminal stage — which renders **no control at all**, just ``CP-35``
    (``UX_FLOWS.md`` §4.8). Omitting the current stage is what makes
    ``ACC-219``'s 400 unreachable through the UI while it stays enforced
    server-side for a crafted request.
  """
  if stage in TERMINAL:
    return ()
  return tuple(
    (value, STAGE_LABELS[value]) for value in STAGE_ORDER if value in LATERAL and value != stage
  )


def _view(row: DealRow, scope: Scope) -> DealView:
  """Build the detail screen's deal from a repository row and the viewer's scope."""
  archived_parent = row.parent_archived_at is not None
  return DealView(
    id=row.id,
    contact_id=row.contact_id,
    contact_name=row.contact_name,
    contact_is_archived=archived_parent,
    owner_name=row.owner_name,
    is_own=row.owner_id == scope.actor_id,
    title=row.title,
    amount=row.amount,
    close_date=row.close_date,
    stage=row.stage,
    stage_label=STAGE_LABELS.get(row.stage, row.stage),
    stage_changed_at=row.stage_changed_at,
    version=row.version,
    created_at=row.created_at,
    updated_at=row.updated_at,
    # A-8, implemented conditionally: the detail stays readable under an
    # archived parent and the controls are absent. A crafted POST still
    # meets 409 archived_parent, decided in the transaction.
    can_edit=not archived_parent,
    can_change_stage=not archived_parent and row.stage not in TERMINAL,
    lateral_targets=_lateral_targets(row.stage),
  )


def _card(row: DealRow, scope: Scope) -> DealCardView:
  """Build one list, pipeline or region card from a repository row."""
  return DealCardView(
    id=row.id,
    title=row.title,
    amount=row.amount,
    close_date=row.close_date,
    stage=row.stage,
    stage_label=STAGE_LABELS.get(row.stage, row.stage),
    contact_id=row.contact_id,
    contact_name=row.contact_name,
    owner_name=row.owner_name,
    is_own=row.owner_id == scope.actor_id,
    parent_archived=row.parent_archived_at is not None,
  )


def _notice_for(operation: Operation, stage: str) -> str:
  """Return the ``?notice=`` code for one operation and the row's stage.

  Parameters
  ----------
  operation : Operation
    Which mutation answered.
  stage : str
    The stage of the row **as it was read back**, never a submitted value
    and never a URL value (``CONTRACTS.md`` §8.5 F-2's rule).

  Returns
  -------
  str
    One of the five Slice C codes. Resolved per operation rather than from
    ``result_status``, which records ``updated`` for an edit and for all
    three stage moves alike (finding F-3).
  """
  if operation == OP_CREATE:
    return NOTICE_CREATED
  if operation == OP_UPDATE:
    return NOTICE_SAVED
  if stage == "won":
    return NOTICE_WON
  if stage == "lost":
    return NOTICE_LOST
  return NOTICE_MOVED


def _applied(row: DealRow, *, operation: Operation, replayed: bool) -> Applied:
  """Build the ``303`` answer from a deal row this transaction has read."""
  return Applied(
    deal_id=row.id,
    contact_id=row.contact_id,
    notice=_notice_for(operation, row.stage),
    replayed=replayed,
  )


async def _replay_in_transaction(
  conn: PoolConnection, scope: Scope, *, operation: Operation, receipt: ReceiptRow
) -> Applied:
  """Rebuild the stored answer, re-reading the deal in the caller's transaction.

  Parameters
  ----------
  conn : PoolConnection
    The connection the mutation is running on.
  scope : Scope
    The viewer's scope; the re-read is scoped like every other read.
  operation : Operation
    Which mutation the receipt belongs to.
  receipt : ReceiptRow
    The stored outcome — a status, an object type and an object id.

  Returns
  -------
  Applied

  Raises
  ------
  DealNotFound
    When the recorded deal is no longer visible to this scope, which a
    reassignment of the parent can legitimately produce. Answering ``404``
    is then the honest outcome: the replay describes a record this
    principal may no longer read.

  Notes
  -----
  The re-read is structural, not a workaround (§2(a) note 6): the ``303``
  target is the **parent**, and the receipt stores only the deal id, so the
  parent has to be read anyway. The stage it returns is what
  ``deal_moved``'s ``{stage}`` substitutes.
  """
  row = await deals_repo.get_deal(conn, scope, deal_id=receipt.result_object_id)
  if row is None:
    raise DealNotFound(receipt.result_object_id)
  return _applied(row, operation=operation, replayed=True)


async def _replay_fresh(
  runner: TransactionRunner, scope: Scope, *, operation: Operation, receipt: ReceiptRow
) -> Applied:
  """Rebuild the stored answer in a **fresh** transaction, after a dead one.

  Used on the two recovery paths whose own transaction can carry no further
  statement: a ``23505`` on the receipt insert (which leaves the
  transaction aborted, ``25P02``) and an :class:`AmbiguousCommit` (whose
  transaction is gone).
  """

  async def _read(conn: PoolConnection) -> DealRow | None:
    return await deals_repo.get_deal(conn, scope, deal_id=receipt.result_object_id)

  row = await runner.read_committed(_read, op="deal-replay-reread")
  if row is None:
    raise DealNotFound(receipt.result_object_id)
  return _applied(row, operation=operation, replayed=True)


async def _resolve_conflict(
  runner: TransactionRunner,
  scope: Scope,
  error: psycopg.Error,
  *,
  operation: Operation,
  key: UUID,
  digest: str,
) -> Applied | Duplicate:
  """Answer a ``23505`` on the receipt insert by reading the winner's receipt.

  Raises
  ------
  psycopg.Error
    When the re-read finds no receipt at all. A receipt that provoked a
    ``23505`` a moment ago cannot legitimately be absent, and running the
    mutation a second time is the one thing the receipt exists to prevent —
    so the honest answer is the sanitized 500 the original error produces,
    with its correlation id.
  """
  decision = await replay_after_conflict(
    runner, user_id=scope.actor_id, operation=operation, key=key, digest=digest
  )
  if decision.receipt is None:
    raise error
  if decision.kind == "duplicate":
    return Duplicate(deal_id=decision.receipt.result_object_id)
  return await _replay_fresh(runner, scope, operation=operation, receipt=decision.receipt)


async def _settle(
  runner: TransactionRunner,
  scope: Scope,
  error: AmbiguousCommit,
  *,
  operation: Operation,
  key: UUID,
  digest: str,
) -> Applied:
  """Resolve an ambiguous commit through the receipt (**PIN C5**, ``SQL-013``).

  Returns
  -------
  Applied
    The replayed answer, when the fresh re-read finds this submission's
    receipt: the transaction **landed**, and the honest response is the
    ``303`` it would have produced.

  Raises
  ------
  AmbiguousCommit
    Re-raised by :func:`app.security.idempotency.settle_ambiguous` when the
    receipt is absent — the transaction did **not** land — so
    ``main.py``'s handler renders the 503 whose copy forbids resubmission.
    Never retried: retrying an ambiguous commit is how one submission
    becomes two rows.
  """
  receipt = await settle_ambiguous(
    runner, error, user_id=scope.actor_id, operation=operation, key=key, digest=digest
  )
  return await _replay_fresh(runner, scope, operation=operation, receipt=receipt)


async def _blocked_parent(conn: PoolConnection, scope: Scope, *, contact_id: UUID) -> Blocked:
  """Build the 409 ``archived_parent`` payload for a write the parent refuses.

  Parameters
  ----------
  conn : PoolConnection
    The connection the mutation is running on; the parent is read in the
    **same** transaction that decided it was archived, so the name and the
    version on the restore form describe the state that refused the write.
  scope : Scope
    The viewer's scope. The read is scoped like every other, so this
    function can never disclose a contact the caller could not already
    open — the archived state is the only new fact, and the caller has
    already been told that much.
  contact_id : UUID
    The parent.

  Returns
  -------
  Blocked
    With a **real** restore form (``UX_FLOWS.md`` §3.10's primary action)
    when the parent is readable and still archived, and ``None`` when it is
    not — a control that cannot act is not offered.
  """
  parent = await contacts_repo.get_contact(conn, scope, contact_id=contact_id)
  if parent is None:
    return Blocked(contact_id=contact_id, contact_name="", restore_form=None)
  restore_form = (
    RestoreForm(idempotency_key=mint_key(), version=parent.version)
    if parent.archived_at is not None
    else None
  )
  return Blocked(contact_id=parent.id, contact_name=parent.full_name, restore_form=restore_form)


async def _stale_after_race(
  runner: TransactionRunner,
  scope: Scope,
  *,
  deal_id: UUID,
  submitted: Mapping[str, str],
) -> Stale:
  """Re-read a deal in a fresh transaction to build §1(e) step 5's 409.

  Raises
  ------
  DealNotFound
    If the row is gone. Nothing in this application deletes a deal — the
    runtime role holds no ``DELETE`` on the table at all — so this is
    unreachable; answering 404 rather than inventing a recovery view for a
    record that does not exist is the honest degradation.
  """

  async def _read(conn: PoolConnection) -> DealRow | None:
    return await deals_repo.get_deal(conn, scope, deal_id=deal_id)

  row = await runner.read_committed(_read, op="deal-stale-reread")
  if row is None:
    raise DealNotFound(deal_id)
  current = _view(row, scope)
  return Stale(
    deal_id=deal_id,
    current=current,
    submitted=submitted,
    version=current.version,
    idempotency_key=mint_key(),
  )


def build_deal_query(
  *,
  term: str | None,
  stage: str | None,
  status: str,
  sort: str,
  direction: str,
  page: int,
  per_page: int,
) -> DealQuery:
  """Turn already-validated request values into one repository query.

  Parameters
  ----------
  term : str | None
    The raw ``?q=`` value, or ``None``. Normalized and escaped here, which
    is the one place it happens (§1(d), ``ACCESS_MATRIX.md`` §5.5).
  stage : str | None
    One of the five stages, or ``None``; the route has already answered
    400 for anything else (``ACC-308``).
  status : str
    ``active``, ``archived`` or ``all`` — a filter on the **parent's**
    ``archived_at``, through the join. ``active`` is the default, so
    ``ACC-306`` is the absence of an input rather than a branch a caller
    can forget.
  sort : str
    One of ``ACCESS_MATRIX.md`` §5.2's five deal keys.
  direction : str
    ``asc`` or ``desc``.
  page : int
    A positive integer.
  per_page : int
    A positive integer; clamped to :data:`MAX_PER_PAGE` here (``ACC-309``).

  Returns
  -------
  DealQuery
    Nothing in it is a raw request string: the term is escaped and
    prefix-bounded, and the four enumerated values only *look up* a
    code-authored SQL fragment inside the repository.

  Notes
  -----
  The escape order is binding and is ``!``, then ``%``, then ``_``:
  escaping ``%`` before ``!`` would double-escape the escape character. A
  **single trailing** ``%`` and **no leading one** — prefix-only. The term
  is lowered in Python, never by a SQL function, because the column it is
  compared against is the stored ``title_lower``.
  """
  normalized: str | None = None
  if term is not None:
    cleaned = term.strip().lower()
    if cleaned:
      escaped = cleaned.replace("!", "!!").replace("%", "!%").replace("_", "!_")
      normalized = f"{escaped}%"
  return deals_repo.DealQuery(
    term=normalized,
    stage=None if stage is None else cast("DealStage", stage),
    status=cast("StatusFilter", status),
    sort=cast("DealSortKey", sort),
    direction=cast("SortDir", direction),
    page=page,
    per_page=min(per_page, MAX_PER_PAGE),
  )


async def list_deals(runner: TransactionRunner, scope: Scope, *, query: DealQuery) -> DealListView:
  """Read one page of deals and its scoped total (``ACC-301``-``ACC-306``).

  Notes
  -----
  One short ``READ COMMITTED`` transaction (§1(e) row 6), never a
  ``SERIALIZABLE`` one: a list page taking predicate locks would make every
  concurrent deal edit a ``40001`` candidate for no benefit. The page and
  its count come from the **same** ``WHERE`` builder, so a foreign row can
  never change a total.
  """

  async def _read(conn: PoolConnection) -> DealPage:
    return await deals_repo.list_deals(conn, scope, query=query)

  page = await runner.read_committed(_read, op="deal-list")
  rows = tuple(_card(row, scope) for row in page.rows)
  total = page.total
  per_page = page.per_page
  pages = max(1, math.ceil(total / per_page))
  offset = (page.page - 1) * per_page
  filtered = query.term is not None or query.stage is not None or query.status != "active"
  if rows:
    state: Literal["ok", "empty", "no_results"] = "ok"
  elif total > 0 or filtered:
    state = "no_results"
  else:
    state = "empty"
  return DealListView(
    items=rows,
    total=total,
    page=page.page,
    per_page=per_page,
    pages=pages,
    range_start=offset + 1 if rows else 0,
    range_end=offset + len(rows) if rows else 0,
    has_prev=page.page > 1,
    has_next=page.page < pages,
    result_state=state,
  )


async def pipeline(runner: TransactionRunner, scope: Scope, *, status: str) -> PipelineView:
  """Read the five pipeline columns in one read-only snapshot (**PIN C6**).

  Parameters
  ----------
  runner : TransactionRunner
    The process runner.
  scope : Scope
    The viewer's scope; the predicate is in the aggregate **and** in each
    card statement.
  status : str
    ``active``, ``archived`` or ``all``, on the parent's archived state.

  Returns
  -------
  PipelineView
    Always five columns, in :data:`STAGE_ORDER` order. A stage the
    ``GROUP BY`` omitted is zero-filled from that constant with
    ``Decimal("0.00")`` — bucket fill from a code constant, and the only
    Python arithmetic anywhere near money.

  Notes
  -----
  All six statements run inside **one** ``SERIALIZABLE, READ ONLY``
  transaction (§1(c)): a column's header and its cards are rendered side by
  side, and at ``READ COMMITTED`` a commit between the two statements is
  *visible* as a header that disagrees with its column. Read-only is a
  property of the transaction — a write inside it is refused with
  ``25006`` — and not of this function's good behaviour.
  """
  resolved = cast("StatusFilter", status)

  async def _read(
    conn: PoolConnection,
  ) -> tuple[dict[str, deals_repo.StageBucket], dict[str, tuple[DealRow, ...]]]:
    buckets = await deals_repo.pipeline(conn, scope, status=resolved)
    by_stage: dict[str, deals_repo.StageBucket] = {bucket.stage: bucket for bucket in buckets}
    cards: dict[str, tuple[DealRow, ...]] = {}
    for stage in STAGE_ORDER:
      cards[stage] = await deals_repo.pipeline_cards(
        conn,
        scope,
        status=resolved,
        stage=cast("DealStage", stage),
        limit=deals_repo.PIPELINE_CARDS_PER_STAGE,
      )
    return by_stage, cards

  by_stage, cards = await runner.read_only_serializable(_read, op="deal-pipeline")
  columns: list[StageColumn] = []
  for stage in STAGE_ORDER:
    bucket = by_stage.get(stage)
    columns.append(
      StageColumn(
        key=stage,
        label=STAGE_LABELS[stage],
        count=0 if bucket is None else bucket.count,
        amount=_ZERO_AMOUNT if bucket is None else bucket.amount,
        deals=tuple(_card(row, scope) for row in cards[stage]),
      )
    )
  return PipelineView(stages=tuple(columns))


async def get_for_detail(runner: TransactionRunner, scope: Scope, *, deal_id: UUID) -> DealView:
  """Read one deal for its detail page or its edit form (``ACC-201``-``ACC-203``).

  Raises
  ------
  DealNotFound
    For a foreign deal and for a missing one alike — one statement, one
    code path, one body (**PIN 8**, ``ACC-202``).

  Notes
  -----
  There is **no archive clause**: a deal under an archived parent stays
  readable to a principal who can see the parent (ask **A-8**), and the
  screen renders the archived banner from ``contact.is_archived`` while
  ``can.edit`` and ``can.change_stage`` are false.
  """

  async def _read(conn: PoolConnection) -> DealRow | None:
    return await deals_repo.get_deal(conn, scope, deal_id=deal_id)

  row = await runner.read_committed(_read, op="deal-detail")
  if row is None:
    raise DealNotFound(deal_id)
  return _view(row, scope)


async def list_for_contact(
  runner: TransactionRunner, scope: Scope, *, contact_id: UUID
) -> tuple[DealCardView, ...]:
  """Read one contact's deals for the workspace's ``#deals`` region (**A-15**).

  Notes
  -----
  ``contacts/detail.html``'s frozen ``deals [deal_card]`` carries no paging
  keys, so this asks for one page of :data:`MAX_PER_PAGE` and flattens it.
  At §9's profile a contact with more than 100 deals does not occur; if one
  ever did, the region would show the first 100 — recorded, not hidden.

  **No archive clause**, like the timeline: the parent read has already
  decided whether this contact is viewable, and an archived contact's
  detail must still show what its owner is about to restore.
  """

  async def _read(conn: PoolConnection) -> DealPage:
    return await deals_repo.list_for_contact(
      conn, scope, contact_id=contact_id, page=1, per_page=MAX_PER_PAGE
    )

  page = await runner.read_committed(_read, op="deal-region")
  return tuple(_card(row, scope) for row in page.rows)


async def create_for_contact(
  runner: TransactionRunner,
  clock: Clock,
  scope: Scope,
  *,
  contact_id: UUID,
  submitted: Mapping[str, str],
  key: UUID,
  correlation_id: str,
) -> Applied | Invalid | Blocked | Duplicate:
  """Create one deal under one contact (``ACC-205``-``ACC-211``).

  Parameters
  ----------
  runner : TransactionRunner
    The process runner.
  clock : Clock
    The injected time source; every instant below comes from it.
  scope : Scope
    The actor's scope. **The owner is the parent's owner**: ``insert_deal``
    has no ``owner_id`` parameter and ``deals`` has no such column, so
    ``ACC-212`` is unreachable by construction.
  contact_id : UUID
    The parent, from the **path** — never from the body (§2(d)).
  submitted : Mapping[str, str]
    The three writable fields.
  key : UUID
    The form's idempotency key, already parsed as canonical.
  correlation_id : str
    This request's id, written into the audit row.

  Returns
  -------
  Applied | Invalid | Blocked | Duplicate

  Raises
  ------
  ContactNotFound
    For a foreign parent and for a missing one alike — **PIN C3**'s order,
    and §4.5 rule 2's object: the denial names the *contact*, because that
    is what the caller was refused (``ACC-207``).

  Notes
  -----
  The new id and the instant are generated **before** the transaction, so
  every retry of the body writes the same id and the same timestamps —
  which is what makes the receipt's ``result_object_id`` stable across a
  ``40001`` retry.

  The parent is resolved **inside** the ``SERIALIZABLE`` transaction, so a
  contact archived between the form render and the submit is seen here —
  or provokes a ``40001`` and is seen on the retry (``SQL-029``).
  """
  validated = _validate(submitted)
  if isinstance(validated, Invalid):
    return validated
  fields = validated.fields
  digest = payload_sha256(
    operation=OP_CREATE, target_id=contact_id, fields=_digest_fields(validated.values)
  )
  now = clock.now()
  deal_id = uuid.uuid4()

  async def _work(conn: PoolConnection) -> Applied | Blocked | Duplicate:
    decision = await decide(
      conn, user_id=scope.actor_id, operation=OP_CREATE, key=key, digest=digest
    )
    if decision.receipt is not None:
      if decision.kind == "duplicate":
        return Duplicate(deal_id=decision.receipt.result_object_id)
      return await _replay_in_transaction(
        conn, scope, operation=OP_CREATE, receipt=decision.receipt
      )
    state = await deals_repo.parent_state(conn, scope, contact_id=contact_id)
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
      object_type="deal",
      object_id=deal_id,
      now=now,
    )
    outcome = await deals_repo.insert_deal(
      conn, scope, deal_id=deal_id, contact_id=contact_id, fields=fields, now=now
    )
    if outcome != "created":
      raise _ParentGuardFired
    await record(
      conn,
      actor_id=scope.actor_id,
      object_type=OBJECT_DEAL,
      object_id=deal_id,
      action=ACTION_DEAL_CREATED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return Applied(deal_id=deal_id, contact_id=contact_id, notice=NOTICE_CREATED, replayed=False)

  try:
    return await runner.serializable(_work, op=OP_CREATE)
  except AmbiguousCommit as error:
    return await _settle(runner, scope, error, operation=OP_CREATE, key=key, digest=digest)
  except psycopg.Error as error:
    if error.sqlstate != _UNIQUE_VIOLATION:
      raise
    return await _resolve_conflict(
      runner, scope, error, operation=OP_CREATE, key=key, digest=digest
    )


async def update_deal(
  runner: TransactionRunner,
  clock: Clock,
  scope: Scope,
  *,
  deal_id: UUID,
  expected_version: int,
  submitted: Mapping[str, str],
  key: UUID,
  correlation_id: str,
) -> Applied | Invalid | Stale | Blocked | Duplicate:
  """Edit one deal's three writable fields (``ACC-213``-``ACC-217``).

  Returns
  -------
  Applied | Invalid | Stale | Blocked | Duplicate

  Raises
  ------
  DealNotFound
    Foreign or missing, decided by the scope predicate before the parent's
    archive state is ever consulted — the ordering that keeps the 409 from
    becoming an existence oracle (``ACC-214``).

  Notes
  -----
  There is no ``contact_id`` and no ``stage`` parameter: re-parenting and a
  stage move are not edits (``ACC-217``, §5.3), and the absence of the
  parameter is the enforcement.
  """
  validated = _validate(submitted)
  if isinstance(validated, Invalid):
    return validated
  fields = validated.fields
  values = validated.values
  digest = payload_sha256(
    operation=OP_UPDATE,
    target_id=deal_id,
    version=expected_version,
    fields=_digest_fields(values),
  )
  now = clock.now()

  async def _work(conn: PoolConnection) -> Applied | Stale | Blocked | Duplicate:
    decision = await decide(
      conn, user_id=scope.actor_id, operation=OP_UPDATE, key=key, digest=digest
    )
    if decision.receipt is not None:
      if decision.kind == "duplicate":
        return Duplicate(deal_id=decision.receipt.result_object_id)
      return await _replay_in_transaction(
        conn, scope, operation=OP_UPDATE, receipt=decision.receipt
      )
    row = await deals_repo.get_deal(conn, scope, deal_id=deal_id)
    if row is None:
      raise DealNotFound(deal_id)
    if row.parent_archived_at is not None:
      return await _blocked_parent(conn, scope, contact_id=row.contact_id)
    if row.version != expected_version:
      return Stale(
        deal_id=deal_id,
        current=_view(row, scope),
        submitted=values,
        version=row.version,
        idempotency_key=mint_key(),
      )
    await commit_receipt(
      conn,
      user_id=scope.actor_id,
      operation=OP_UPDATE,
      key=key,
      digest=digest,
      status="updated",
      object_type="deal",
      object_id=deal_id,
      now=now,
    )
    updated = await deals_repo.update_deal_versioned(
      conn,
      scope,
      deal_id=deal_id,
      expected_version=expected_version,
      fields=fields,
      now=now,
    )
    if updated is None:
      raise _ConcurrentStale
    await record(
      conn,
      actor_id=scope.actor_id,
      object_type=OBJECT_DEAL,
      object_id=deal_id,
      action=ACTION_DEAL_UPDATED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return _applied(updated, operation=OP_UPDATE, replayed=False)

  try:
    return await runner.serializable(_work, op=OP_UPDATE)
  except _ConcurrentStale:
    return await _stale_after_race(runner, scope, deal_id=deal_id, submitted=values)
  except AmbiguousCommit as error:
    return await _settle(runner, scope, error, operation=OP_UPDATE, key=key, digest=digest)
  except psycopg.Error as error:
    if error.sqlstate != _UNIQUE_VIOLATION:
      raise
    return await _resolve_conflict(
      runner, scope, error, operation=OP_UPDATE, key=key, digest=digest
    )


async def change_stage(
  runner: TransactionRunner,
  clock: Clock,
  scope: Scope,
  *,
  deal_id: UUID,
  expected_version: int,
  to_stage: str,
  key: UUID,
  correlation_id: str,
) -> Applied | Stale | Blocked | StageTerminal | SameStage | Duplicate:
  """Move one deal along the stage graph (``ACC-218``-``ACC-223``, **PIN C2**).

  Parameters
  ----------
  to_stage : str
    One of the five stages; the route's field allowlist has already
    answered 400 for anything else. ``won`` and ``lost`` arrive here from
    their own dedicated routes as well — there is **one** service function,
    one statement and one receipt vocabulary, so the terminal check cannot
    be forgotten in a second place (§2(a) note 2).

  Returns
  -------
  Applied | Stale | Blocked | StageTerminal | SameStage | Duplicate

  Raises
  ------
  DealNotFound
    Foreign or missing. It is decided **before** the graph, so a
    ``stage_terminal`` 409 for a foreign deal — an existence oracle —
    cannot occur.

  Notes
  -----
  The graph is checked against the stage this transaction **read**, and
  that same stage is then passed to the ``UPDATE`` as ``from_stage``, so
  the write can only land on the stage the decision was made about. The
  business instant is split in two — ``stage_changed_at`` is the fact
  ``DATA_CONTRACT.md`` §3.10 requires to be rewritten on every accepted
  move, ``now`` is ``updated_at`` — exactly as ``archive_contact`` splits
  ``archived_at`` from ``now``.
  """
  digest = payload_sha256(
    operation=OP_STAGE,
    target_id=deal_id,
    version=expected_version,
    fields=[("to_stage", to_stage)],
  )
  now = clock.now()

  async def _work(
    conn: PoolConnection,
  ) -> Applied | Stale | Blocked | StageTerminal | SameStage | Duplicate:
    decision = await decide(
      conn, user_id=scope.actor_id, operation=OP_STAGE, key=key, digest=digest
    )
    if decision.receipt is not None:
      if decision.kind == "duplicate":
        return Duplicate(deal_id=decision.receipt.result_object_id)
      return await _replay_in_transaction(conn, scope, operation=OP_STAGE, receipt=decision.receipt)
    row = await deals_repo.get_deal(conn, scope, deal_id=deal_id)
    if row is None:
      raise DealNotFound(deal_id)
    if row.parent_archived_at is not None:
      return await _blocked_parent(conn, scope, contact_id=row.contact_id)
    if row.version != expected_version:
      return Stale(
        deal_id=deal_id,
        current=_view(row, scope),
        submitted={"to_stage": to_stage},
        version=row.version,
        idempotency_key=mint_key(),
      )
    if row.stage in TERMINAL:
      return StageTerminal(deal_id=deal_id, stage_label=STAGE_LABELS.get(row.stage, row.stage))
    if to_stage == row.stage:
      return SameStage(deal_id=deal_id)
    await commit_receipt(
      conn,
      user_id=scope.actor_id,
      operation=OP_STAGE,
      key=key,
      digest=digest,
      # `ck_mutation_receipts_status` admits no `stage_changed`, so all
      # three moves record `updated` (§1(a), ask A-3). The notice is
      # resolved from the operation and the re-read stage instead.
      status="updated",
      object_type="deal",
      object_id=deal_id,
      now=now,
    )
    moved = await deals_repo.change_stage_versioned(
      conn,
      scope,
      deal_id=deal_id,
      expected_version=expected_version,
      from_stage=row.stage,
      new_stage=to_stage,
      stage_changed_at=now,
      now=now,
    )
    if moved is None:
      raise _ConcurrentStale
    await record(
      conn,
      actor_id=scope.actor_id,
      object_type=OBJECT_DEAL,
      object_id=deal_id,
      action=ACTION_DEAL_STAGE_CHANGED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return _applied(moved, operation=OP_STAGE, replayed=False)

  try:
    return await runner.serializable(_work, op=OP_STAGE)
  except _ConcurrentStale:
    return await _stale_after_race(runner, scope, deal_id=deal_id, submitted={"to_stage": to_stage})
  except AmbiguousCommit as error:
    return await _settle(runner, scope, error, operation=OP_STAGE, key=key, digest=digest)
  except psycopg.Error as error:
    if error.sqlstate != _UNIQUE_VIOLATION:
      raise
    return await _resolve_conflict(runner, scope, error, operation=OP_STAGE, key=key, digest=digest)
