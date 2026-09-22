"""``deals`` — the first child repository, authorized entirely by the parent.

Everything the ``contacts`` repository does holds here unchanged — one
``WHERE`` builder shared by a list and its count, ownership in the SQL and
never in Python, versioned writes that return ``None`` rather than choosing
a status — and three things are new, because ``deals`` is the first table
with a parent:

*The ownership predicate is on the parent.* ``deals`` carries **no**
``owner_id`` and **no** ``archived_at``. Every statement here reaches its
owner through
``JOIN public.contacts c ON c.id = d.contact_id`` and filters on
``c.owner_id`` — which is what makes owner injection on a child structurally
impossible rather than allowlisted, and what makes an admin reassignment one
``UPDATE`` of one row that moves every child with it.

*Money is :class:`decimal.Decimal` end to end*. ``amount`` is
``DECIMAL(12,2)``; psycopg returns it as a :class:`~decimal.Decimal`, every row
mapper in this module **asserts** that at the boundary, and the pipeline's per
stage total is the engine's ``SUM`` — never a Python sum, never a float. No
float conversion, no rounding call and no :class:`~decimal.Decimal` built from
a float appears anywhere in this file; the only literal decimals are the
zero-fill constants the pipeline needs.

*The stage graph is deliberately absent.* :data:`STAGE_ORDER` is the column's
vocabulary and the pipeline's column order, nothing more. The legal-transition
sets belong to the service, which is where the 400/409 answers are
chosen; a repository that knew the graph would be a repository that could
refuse a write, and no function in ``app/db/**`` decides anything.

``Scope`` is imported under ``TYPE_CHECKING`` only, so ``app/db/**`` keeps no
runtime import of ``app/security/**``, and every public function takes one as
its second positional argument — the first *business* argument, which is
where the test suite's own check looks for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Final, Literal, LiteralString, cast
from uuid import UUID

from psycopg import sql

if TYPE_CHECKING:
  from datetime import date, datetime

  from app.db.pool import PoolConnection
  from app.security.principal import Scope

__all__ = [
  "DEFAULT_PER_PAGE",
  "MAX_OFFSET",
  "MAX_PER_PAGE",
  "PIPELINE_CARDS_PER_STAGE",
  "STAGE_ORDER",
  "CreateOutcome",
  "DealFields",
  "DealPage",
  "DealQuery",
  "DealRow",
  "DealSortKey",
  "DealStage",
  "ParentState",
  "SortDir",
  "StageBucket",
  "StatusFilter",
  "change_stage_versioned",
  "dashboard_totals",
  "get_deal",
  "insert_deal",
  "list_deals",
  "list_for_contact",
  "parent_state",
  "pipeline",
  "pipeline_cards",
  "update_deal_versioned",
]

#: The page size — 25 for contacts **and** deals.
DEFAULT_PER_PAGE: Final[int] = 25
#: The hard clamp, the same value the contact list uses: a larger
#: ``per_page`` is reduced, never refused.
MAX_PER_PAGE: Final[int] = 100
#: The server-side offset clamp. A page past it repeats
#: the last reachable window rather than making the database skip unboundedly.
MAX_OFFSET: Final[int] = 10_000
#: The per-stage card cap of the pipeline. Each column gets its own bound, so a
#: busy column cannot eat a shared budget and leave its neighbours rendering
#: empty beside a non-zero header.
PIPELINE_CARDS_PER_STAGE: Final[int] = 50

#: The five values ``ck_deals_stage`` admits, in pipeline column order.
type DealStage = Literal["new", "qualified", "proposal", "won", "lost"]
STAGE_ORDER: Final[tuple[DealStage, ...]] = ("new", "qualified", "proposal", "won", "lost")

#: The five sort keys the deal list allows, default ``created_at``. The
#: contact list's default is ``updated_at``; they differ deliberately.
type DealSortKey = Literal["title", "amount", "close_date", "stage", "created_at"]
type SortDir = Literal["asc", "desc"]
#: The archive filter. On **every** deal surface it filters the PARENT
#: contact's ``archived_at`` through the join: ``status`` is never a
#: column, and ``deals`` has none.
type StatusFilter = Literal["active", "archived", "all"]

#: What :func:`parent_state` answers. ``missing`` covers foreign **and**
#: missing — one code path — and the caller maps it to the identical 404.
type ParentState = Literal["missing", "archived", "active"]
#: What :func:`insert_deal` answers. The repository never chooses a status.
type CreateOutcome = Literal["created", "parent_missing", "parent_archived"]

#: The ownership conjunct of a **read**, aliased on the parent, as
#: ``P-DEAL-SCOPE-AGENT`` writes it. Its admin twin
#: is the *absence* of a conjunct, not a widened one. The same pair is composed
#: into the correlated ``EXISTS`` of both versioned writes, where the alias is
#: also ``c``.
_READ_OWNED: Final = sql.SQL("AND c.owner_id = %(actor_id)s")
_READ_ANY: Final = sql.SQL("")

_VISIBLE_OWNED: Final = sql.SQL("c.owner_id = %(actor_id)s")
_VISIBLE_STAGE: Final = sql.SQL("d.stage = %(stage)s")

#: Prefix-only search over the one normalized deal column, **parenthesised**.
#: One column and one comparison make the parentheses redundant *today*; they
#: are written anyway, inside the constant, so that a second searchable column
#: can never be added beside an unparenthesised ``OR`` next to the ownership
#: conjunct — the classic scope bypass. No leading
#: ``%``, no ``ILIKE``, no ``~``, no ``SIMILAR TO``, no ``COLLATE``; the
#: service escapes ``!``, ``%`` and ``_`` in that order and appends
#: the single trailing ``%``.
_VISIBLE_SEARCH: Final = sql.SQL("(d.title_lower LIKE %(term)s ESCAPE '!')")

#: ``status`` selects a fragment; the submitted string never reaches SQL, and
#: the conjunct is on the **parent** — ``deals`` has no ``archived_at``.
#:
#: The three keys are spelled out and the lookup is indexed rather than
#: ``.get``-ed, so a value outside the enum raises ``KeyError`` — a programming
#: error, exactly as an out-of-allowlist sort key is — instead of silently
#: reading as ``all`` and widening the result to the deals of archived
#: contacts. ``active`` being the default is what makes "deals under
#: archived contacts are hidden by default" the absence of an input rather
#: than a branch a caller can forget.
_ARCHIVE_FRAGMENTS: Final[dict[StatusFilter, sql.SQL | None]] = {
  "active": sql.SQL("c.archived_at IS NULL"),
  "archived": sql.SQL("c.archived_at IS NOT NULL"),
  "all": None,
}

#: The ten allowed orderings, each a module-level literal with a deterministic
#: tiebreaker on ``d.id``. The submitted ``sort``/``dir`` strings only *look
#: up* a fragment; no request text ever reaches an ``ORDER BY``, and a
#: ``KeyError`` here is a programming error — the service has already answered
#: 400 for a value outside the allowlist.
#:
#: The tiebreaker follows the sort direction, for the reason ``contacts.py``
#: gives: a mixed-direction tiebreaker forbids a backwards index walk for no
#: gain in determinism.
#:
#: ``title`` orders by the normalized ``title_lower`` rather than by the raw
#: column, which is the choice ``contacts.py`` made for ``name``: the raw
#: column's order is collation-dependent, the normalized one is not, and
#: neither is index-served in agent scope anyway: every agent-scope deal
#: ordering is a sort above a join, by construction.
_ORDER_BY: Final[dict[tuple[DealSortKey, SortDir], sql.SQL]] = {
  ("title", "asc"): sql.SQL("d.title_lower ASC, d.id ASC"),
  ("title", "desc"): sql.SQL("d.title_lower DESC, d.id DESC"),
  ("amount", "asc"): sql.SQL("d.amount ASC, d.id ASC"),
  ("amount", "desc"): sql.SQL("d.amount DESC, d.id DESC"),
  ("close_date", "asc"): sql.SQL("d.close_date ASC, d.id ASC"),
  ("close_date", "desc"): sql.SQL("d.close_date DESC, d.id DESC"),
  ("stage", "asc"): sql.SQL("d.stage ASC, d.id ASC"),
  ("stage", "desc"): sql.SQL("d.stage DESC, d.id DESC"),
  ("created_at", "asc"): sql.SQL("d.created_at ASC, d.id ASC"),
  ("created_at", "desc"): sql.SQL("d.created_at DESC, d.id DESC"),
}

#: Every row-returning statement spells its column list out in full rather than
#: sharing a fragment — the package convention ``users.py`` set, for the reason
#: it gives: every SELECT names its columns and SQL assembled
#: from pieces is exactly the shape a reviewer should not have to think about.
#: :func:`_row_to_deal` unpacks all four of them, so the four lists must stay
#: identical; they are adjacent here so a drift is visible.
#:
#: Alias discipline is absolute — ``d.`` for deal columns, ``c.`` for contact
#: columns, ``u.`` for the owner — because ``kind`` is a name that exists on
#: three tables and an unqualified column in a joined statement is an
#: ambiguous-column error waiting for the next table.
#:
#: The ``u`` join carries ``deal_card.owner_name``.
#: Both joins are over ``NOT NULL`` foreign keys, so neither can change a row
#: count, which is why the list and its count may both carry ``u`` — they must
#: be the same statement but for the select list — and why the pipeline's
#: aggregate may omit it.
_GET_DEAL_SQL: Final = sql.SQL("""
SELECT d.id, d.contact_id, c.full_name, c.owner_id, u.display_name, c.archived_at,
       d.title, d.amount, d.close_date, d.stage, d.stage_changed_at,
       d.version, d.created_at, d.updated_at
  FROM public.deals d
  JOIN public.contacts c ON c.id = d.contact_id
  JOIN public.users    u ON u.id = c.owner_id
 WHERE d.id = %(deal_id)s
   {scope}
""")

_LIST_DEALS_SQL: Final = sql.SQL("""
SELECT d.id, d.contact_id, c.full_name, c.owner_id, u.display_name, c.archived_at,
       d.title, d.amount, d.close_date, d.stage, d.stage_changed_at,
       d.version, d.created_at, d.updated_at
  FROM public.deals d
  JOIN public.contacts c ON c.id = d.contact_id
  JOIN public.users    u ON u.id = c.owner_id
 {where}
 ORDER BY {order_by}
 LIMIT %(limit)s OFFSET %(offset)s
""")

_LIST_FOR_CONTACT_SQL: Final = sql.SQL("""
SELECT d.id, d.contact_id, c.full_name, c.owner_id, u.display_name, c.archived_at,
       d.title, d.amount, d.close_date, d.stage, d.stage_changed_at,
       d.version, d.created_at, d.updated_at
  FROM public.deals d
  JOIN public.contacts c ON c.id = d.contact_id
  JOIN public.users    u ON u.id = c.owner_id
 WHERE d.contact_id = %(contact_id)s
   {scope}
 ORDER BY d.created_at DESC, d.id DESC
 LIMIT %(limit)s OFFSET %(offset)s
""")

_PIPELINE_CARDS_SQL: Final = sql.SQL("""
SELECT d.id, d.contact_id, c.full_name, c.owner_id, u.display_name, c.archived_at,
       d.title, d.amount, d.close_date, d.stage, d.stage_changed_at,
       d.version, d.created_at, d.updated_at
  FROM public.deals d
  JOIN public.contacts c ON c.id = d.contact_id
  JOIN public.users    u ON u.id = c.owner_id
 {where}
 ORDER BY d.amount DESC, d.id ASC
 LIMIT %(limit)s
""")

_COUNT_DEALS_SQL: Final = sql.SQL("""
SELECT count(*)
  FROM public.deals d
  JOIN public.contacts c ON c.id = d.contact_id
  JOIN public.users    u ON u.id = c.owner_id
 {where}
""")

_COUNT_FOR_CONTACT_SQL: Final = sql.SQL("""
SELECT count(*)
  FROM public.deals d
  JOIN public.contacts c ON c.id = d.contact_id
  JOIN public.users    u ON u.id = c.owner_id
 WHERE d.contact_id = %(contact_id)s
   {scope}
""")

#: The count and the € total per stage are computed **in SQL**, under the
#: predicate, never summed in Python. ``COALESCE(SUM(...), CAST(0 AS
#: DECIMAL(12,2)))`` so an empty set renders ``0.00`` and not blank; psycopg
#: returns both the ``SUM`` and the coalesced empty case as
#: :class:`~decimal.Decimal`. No ``u`` join: the statement returns no user
#: column and the join is count-neutral.
_PIPELINE_AGGREGATE_SQL: Final = sql.SQL("""
SELECT d.stage, count(*) AS deal_count,
       COALESCE(SUM(d.amount), CAST(0 AS DECIMAL(12,2))) AS stage_amount
  FROM public.deals d
  JOIN public.contacts c ON c.id = d.contact_id
 {where}
 GROUP BY d.stage
""")

#: The dashboard aggregate, **one statement for all four numbers**. Every
#: count and every sum is the engine's under the one predicate: nothing on
#: this path is summed, filtered or bucketed in Python. ``SUM(CASE ...)``
#: rather than ``count(*) FILTER (WHERE ...)`` because the portable SQL
#: subset has no ``FILTER`` clause, and rather than a
#: ``GROUP BY d.stage`` whose five rows Python would then have to add up.
#:
#: The archive conjunct is written in, not selected: an archived contact's
#: deals are off the dashboard exactly as they are off the default lists
#:. The ownership conjunct is on the **parent**, like every other
#: statement in this module.
_DASHBOARD_TOTALS_SQL: Final = sql.SQL("""
SELECT COALESCE(SUM(CASE WHEN d.stage IN ('new', 'qualified', 'proposal')
                         THEN 1 ELSE 0 END), 0) AS open_count,
       COALESCE(SUM(CASE WHEN d.stage IN ('new', 'qualified', 'proposal')
                         THEN d.amount ELSE CAST(0 AS DECIMAL(12,2)) END),
                CAST(0 AS DECIMAL(12,2))) AS open_amount,
       COALESCE(SUM(CASE WHEN d.stage = 'won' THEN 1 ELSE 0 END), 0) AS won_count,
       COALESCE(SUM(CASE WHEN d.stage = 'won'
                         THEN d.amount ELSE CAST(0 AS DECIMAL(12,2)) END),
                CAST(0 AS DECIMAL(12,2))) AS won_amount
  FROM public.deals d
  JOIN public.contacts c ON c.id = d.contact_id
 WHERE c.archived_at IS NULL
   {scope}
""")

#: ``P-CONTACT-SCOPE-*`` with the select list narrowed to the one fact the
#: caller may learn. **No archive clause, by design**: the archive state is the
#: ANSWER, not a filter, and the order is fixed — scope predicate first
#: (0 rows -> ``missing`` -> the identical 404), archived state second
#: (-> ``archived`` -> 409 ``archived_parent``). The statement returns one
#: boolean and no other column — not the owner, not the name, not a count — so
#: a caller that mishandled it still could not leak anything beyond the
#: distinction it exists to make.
_PARENT_STATE_SQL: Final = sql.SQL("""
SELECT (c.archived_at IS NOT NULL) AS parent_archived
  FROM public.contacts c
 WHERE c.id = %(contact_id)s
   {scope}
""")

#: ``stage`` is the **literal** ``'new'`` and ``version`` the literal ``1``:
#: a stage is never accepted on create, and putting it in the
#: statement rather than in a parameter means there is no parameter through
#: which a request value could arrive. ``contact_id`` is bound from the
#: argument :func:`parent_state` has just resolved under the scope predicate,
#: in this same transaction.
_INSERT_DEAL_SQL: Final[LiteralString] = """
INSERT INTO public.deals
  (id, contact_id, title, title_lower, amount, close_date, stage,
   stage_changed_at, version, created_at, updated_at)
VALUES
  (%(id)s, %(contact_id)s, %(title)s, %(title_lower)s, %(amount)s, %(close_date)s, 'new',
   %(now)s, 1, %(now)s, %(now)s)
"""

#: The ``SET`` list is fixed literal text and carries neither ``contact_id``
#: nor ``stage``. ``version = version + 1`` rides the same
#: statement; no trigger, ever.
#:
#: The ownership predicate is a correlated ``EXISTS`` and not ``UPDATE … FROM``,
#: which is a PostgreSQL extension this codebase's portability rules do not
#: admit. The
#: ``UPDATE`` is aliased (``AS d``) so ``d.contact_id`` inside the subquery is
#: explicit; the unaliased form resolves correctly too, but relies on a scoping
#: rule a reviewer should not have to know.
#:
#: ``c.archived_at IS NULL`` is belt-and-braces: editing a deal
#: under an archived parent matches zero rows, and the service's re-read is
#: what turns that into the **409 ``archived_parent``** context rather than 409
#: ``stale``.
_UPDATE_DEAL_SQL: Final = sql.SQL("""
UPDATE public.deals AS d
   SET title       = %(title)s,
       title_lower = %(title_lower)s,
       amount      = %(amount)s,
       close_date  = %(close_date)s,
       version     = version + 1,
       updated_at  = %(now)s
 WHERE d.id = %(deal_id)s
   AND d.version = %(version)s
   AND EXISTS (SELECT 1
                 FROM public.contacts c
                WHERE c.id = d.contact_id
                  AND c.archived_at IS NULL
                  {scope})
""")

#: ``AND d.stage = %(from_stage)s`` is the graph's guard rail in the statement.
#: The service checked the move against the stage it **read in this
#: transaction**; this conjunct means the write can only land on that same
#: stage. It is redundant with the version guard today and is kept for the
#: reason ``archived_at IS NULL`` is kept above: a statement should be correct
#: on its own terms, not only in the presence of a correct caller.
#:
#: Won and Lost are this same statement. They differ only in ``new_stage``
#: and in the confirmation step on the way in; there is no second SQL shape,
#: no ``won_at`` column and no ``is_won`` flag.
_CHANGE_STAGE_SQL: Final = sql.SQL("""
UPDATE public.deals AS d
   SET stage            = %(new_stage)s,
       stage_changed_at = %(stage_changed_at)s,
       version          = version + 1,
       updated_at       = %(now)s
 WHERE d.id = %(deal_id)s
   AND d.version = %(version)s
   AND d.stage = %(from_stage)s
   AND EXISTS (SELECT 1
                 FROM public.contacts c
                WHERE c.id = d.contact_id
                  AND c.archived_at IS NULL
                  {scope})
""")


@dataclass(frozen=True, slots=True)
class DealRow:
  """One deal as every read returns it, with the parent facts the caller needs.

  Attributes
  ----------
  id : UUID
    The deal's application-generated id.
  contact_id : UUID
    The parent. Present on every row because every render links to it, and
    **absent from** :class:`DealFields`, because that dataclass's field list is
    the writable-field allowlist.
  contact_name : str
    ``contacts.full_name`` of the parent, from the join — ``deal_card``'s
    ``contact_name``.
  owner_id : UUID
    ``contacts.owner_id``: the **only** ownership column, and it is on the
    parent. ``deals`` has none.
  owner_name : str
    ``users.display_name`` of the owner. ``is_own`` is derived by the service.
  parent_archived_at : datetime | None
    ``contacts.archived_at``. Not decoration: it is what lets the service
    answer **409 ``archived_parent``** instead of 409 ``stale`` after a
    zero-row ``UPDATE``, and what makes ``can.edit``/``can.change_stage`` false
    on the detail of a deal whose parent is archived.
  title : str
    As typed. The search key is the normalized ``title_lower``, which no read
    returns.
  amount : Decimal
    Always a :class:`~decimal.Decimal`, asserted at this boundary. Never a
    float, at any point on any money path.
  close_date : date | None
    The only nullable column on ``deals``.
  stage : str
    One of the five ``ck_deals_stage`` admits. The transition *graph* is the
    service's.
  stage_changed_at : datetime
    Rewritten on every accepted stage change, from the caller's clock.
  version : int
    The optimistic-concurrency guard every write carries.
  created_at : datetime
    From the caller's injected clock, never a server clock.
  updated_at : datetime
    Likewise.
  """

  id: UUID
  contact_id: UUID
  contact_name: str
  owner_id: UUID
  owner_name: str
  parent_archived_at: datetime | None
  title: str
  amount: Decimal
  close_date: date | None
  stage: str
  stage_changed_at: datetime
  version: int
  created_at: datetime
  updated_at: datetime


@dataclass(frozen=True, slots=True)
class DealFields:
  """The three writable fields, with the normalized companion of the searchable one.

  ``title``, ``amount`` and ``close_date`` are writable on create and on
  edit, and nothing else is. **This dataclass's field list is the
  allowlist**: the ``SET`` list is fixed literal text and there is no parameter
  anywhere in this module through which a request could change a deal's parent
  or its stage — a submitted ``contact_id`` is a crafted-request ``400``,
  and here it is structurally impossible as well.

  Attributes
  ----------
  title : str
    1..160 characters.
  title_lower : str
    ``title`` normalized — the search key.
  amount : Decimal
    Non-negative, at most two decimal places. The column's CHECK is the second
    line for the **sign** only: ``DECIMAL(12,2)`` *rounds* a third decimal
    rather than refusing it, so the service's strict pattern is the only
    control for scale.
  close_date : date | None
    ``None`` is a real value here, not "unset".
  """

  title: str
  title_lower: str
  amount: Decimal
  close_date: date | None


@dataclass(frozen=True, slots=True)
class DealQuery:
  """One already-validated list request. Nothing here is a raw request string.

  Attributes
  ----------
  term : str | None
    The search term, already escaped for ``!``, ``%`` and ``_`` in that order,
    with a single trailing ``%`` appended. ``None`` means no search.
  stage : DealStage | None
    ``None`` means no stage filter.
  status : StatusFilter
    The **parent's** archive filter. ``active`` is the default; ``all``
    contributes no conjunct at all.
  sort : DealSortKey
    Looks up an ``ORDER BY`` fragment; never reaches SQL as text.
  direction : SortDir
    Likewise.
  page : int
    1-based. A non-positive or non-integer page is a **400** in the service and
    never arrives here; a page past the end is an ordinary empty result.
  per_page : int
    Clamped to :data:`MAX_PER_PAGE` here as well as in the service, because the
    constant lives in this module.
  """

  term: str | None
  stage: DealStage | None
  status: StatusFilter
  sort: DealSortKey
  direction: SortDir
  page: int
  per_page: int


@dataclass(frozen=True, slots=True)
class DealPage:
  """One page of deals and the scoped total that goes with it.

  Attributes
  ----------
  rows : tuple[DealRow, ...]
    The page, in the requested order.
  total : int
    The count under the **identical** ``WHERE``, from the identical builder, so
    it can never include a row the page's predicate excludes.
  page : int
    The page actually served, 1-based.
  per_page : int
    The page size actually applied, after the clamp.
  """

  rows: tuple[DealRow, ...]
  total: int
  page: int
  per_page: int


@dataclass(frozen=True, slots=True)
class DealTotals:
  """The dashboard's two deal tiles: counts and € totals, both from the engine.

  Attributes
  ----------
  open_count, open_amount : int, Decimal
    The three non-terminal stages (``new``, ``qualified``, ``proposal``).
  won_count, won_amount : int, Decimal
    Stage ``won``. ``lost`` is on neither tile and is not returned at all:
    the dashboard has three tiles and a fourth was deliberately not added.
  """

  open_count: int
  open_amount: Decimal
  won_count: int
  won_amount: Decimal


@dataclass(frozen=True, slots=True)
class StageBucket:
  """One pipeline column's exact aggregate — never ``len(rows)``, never a Python sum.

  Attributes
  ----------
  stage : DealStage
    The column, taken from :data:`STAGE_ORDER` rather than from a row, so a
    zero-filled column and a populated one carry the same typed value.
  count : int
    The engine's ``count(*)`` under the predicate.
  amount : Decimal
    The engine's ``SUM(d.amount)``, or ``Decimal("0.00")`` for a stage the
    ``GROUP BY`` omitted because it held nothing.
  """

  stage: DealStage
  count: int
  amount: Decimal


def _as_decimal(value: object, *, column: str) -> Decimal:
  """Return ``value`` as a :class:`~decimal.Decimal`, or refuse it.

  Parameters
  ----------
  value : object
    A money column as psycopg returned it.
  column : str
    The column's name, for the message. Never a value.

  Returns
  -------
  Decimal
    The same object.

  Raises
  ------
  TypeError
    If the driver ever hands back anything else — a float, a string, ``None``.
    This is the runtime half of the no-float rule, at the repository
    boundary: the test suite proves no float is *constructed* on a money
    path, and this proves none *arrives* on one. It cannot be a :func:`typing.cast`, because a cast
    asserts to the type checker exactly the thing that would be false.
  """
  if not isinstance(value, Decimal):
    raise TypeError(f"{column} must be a decimal.Decimal, got {type(value).__name__}")
  return value


def _row_to_deal(row: tuple[object, ...]) -> DealRow:
  """Build a :class:`DealRow` from one row of the deal SELECT.

  Parameters
  ----------
  row : tuple[object, ...]
    The tuple as psycopg returned it, in the order of the SELECT list.

  Returns
  -------
  DealRow
    The row with its ``TEXT`` ids converted back to :class:`uuid.UUID`. This is
    the module's single conversion point in that direction
   , and the reason the list, the detail read, the
    per-contact region, the pipeline cards and every mutation's read-back
    cannot disagree about a column's meaning.

  Raises
  ------
  TypeError
    If ``amount`` is not a :class:`~decimal.Decimal`.
  """
  parent_archived_at = row[5]
  close_date = row[8]
  return DealRow(
    id=UUID(str(row[0])),
    contact_id=UUID(str(row[1])),
    contact_name=str(row[2]),
    owner_id=UUID(str(row[3])),
    owner_name=str(row[4]),
    parent_archived_at=None if parent_archived_at is None else cast("datetime", parent_archived_at),
    title=str(row[6]),
    amount=_as_decimal(row[7], column="deals.amount"),
    close_date=None if close_date is None else cast("date", close_date),
    stage=str(row[9]),
    stage_changed_at=cast("datetime", row[10]),
    version=int(str(row[11])),
    created_at=cast("datetime", row[12]),
    updated_at=cast("datetime", row[13]),
  )


def _read_scope(scope: Scope) -> sql.SQL:
  """Return the ownership conjunct of a read, one of exactly two literals.

  Parameters
  ----------
  scope : Scope
    The caller's authorization scope.

  Returns
  -------
  sql.SQL
    ``AND c.owner_id = %(actor_id)s`` for an agent; the empty fragment for an
    admin, whose scope is unfiltered. Never a single fragment parameterized by
    an ``is_admin`` boolean.

  Notes
  -----
  The same pair serves the reads *and* the correlated ``EXISTS`` of both
  versioned writes, because the parent is aliased ``c`` in each — which is the
  the whole point of keeping ownership on the parent: there is no
  deal-side ownership conjunct to get wrong.
  """
  return _READ_ANY if scope.is_admin else _READ_OWNED


def _visible_where(scope: Scope, query: DealQuery) -> tuple[sql.Composed, dict[str, object]]:
  """Compose the ``WHERE`` of a deal list, and the parameters that go with it.

  Parameters
  ----------
  scope : Scope
    The caller's authorization scope. An agent gets the ownership conjunct on
    the **parent**; an admin gets no conjunct rather than a widened one.
  query : DealQuery
    The already-validated request.

  Returns
  -------
  tuple[sql.Composed, dict[str, object]]
    The fragment — including the ``WHERE`` keyword, or **empty** when no
    conjunct applies — and the parameters the fragment binds.

  Raises
  ------
  KeyError
    If ``query.status`` is outside the enum — a programming error, the same
    answer an out-of-allowlist sort key gets, and deliberately not a silent
    widening to ``all``.

  Notes
  -----
  This is the single place a deal predicate is built, which is what makes
  "a count can never see a row the list cannot" a property of the code:
  :func:`list_deals` hands the very same object to both of its statements, and
  the pipeline's aggregate and its five card statements are fed from it too.

  The empty case is real and reachable: an admin asking for ``status=all`` with
  no stage filter and no search has no conjunct at all, so the fragment is
  empty and the statement carries no ``WHERE`` keyword — not a dangling one.
  """
  conjuncts: list[sql.Composable] = []
  params: dict[str, object] = {}

  if not scope.is_admin:
    conjuncts.append(_VISIBLE_OWNED)
    params["actor_id"] = str(scope.actor_id)

  archive = _ARCHIVE_FRAGMENTS[query.status]
  if archive is not None:
    conjuncts.append(archive)

  if query.stage is not None:
    conjuncts.append(_VISIBLE_STAGE)
    params["stage"] = query.stage

  if query.term is not None:
    conjuncts.append(_VISIBLE_SEARCH)
    params["term"] = query.term

  if not conjuncts:
    return sql.Composed([]), params
  return sql.SQL("WHERE ") + sql.SQL("\n   AND ").join(conjuncts), params


def _pipeline_query(*, status: StatusFilter, stage: DealStage | None) -> DealQuery:
  """Build the :class:`DealQuery` the pipeline statements' predicate is composed from.

  Parameters
  ----------
  status : StatusFilter
    The parent's archive filter — the pipeline's only input; that surface
    allows no ``sort``, no ``dir`` and no ``page``.
  stage : DealStage | None
    The column being read, or ``None`` for the aggregate, which groups.

  Returns
  -------
  DealQuery
    With the sort and pagination fields at their module defaults, because
    neither pipeline statement reads them: the aggregate has no ``ORDER BY``
    and no ``LIMIT``, and a card statement's order is fixed with its ``LIMIT``
    bound from :data:`PIPELINE_CARDS_PER_STAGE`.

  Notes
  -----
  One builder, one predicate. A second dataclass carrying only the three fields
  :func:`_visible_where` actually reads would have to be kept in step with this
  one forever.
  """
  return DealQuery(
    term=None,
    stage=stage,
    status=status,
    sort="created_at",
    direction="desc",
    page=1,
    per_page=MAX_PER_PAGE,
  )


def _paging(page: int, per_page: int) -> tuple[int, int, int]:
  """Clamp a page request to the module's bounds.

  Parameters
  ----------
  page : int
    1-based page number.
  per_page : int
    Requested page size.

  Returns
  -------
  tuple[int, int, int]
    ``(page, per_page, offset)`` after the clamps: ``per_page`` to
    :data:`MAX_PER_PAGE` (reduced, never refused) and ``offset`` to
    :data:`MAX_OFFSET`, so a page past the end repeats the last reachable
    window rather than making the database skip unboundedly.
  """
  clamped_page = max(page, 1)
  clamped_per_page = min(max(per_page, 1), MAX_PER_PAGE)
  return clamped_page, clamped_per_page, min((clamped_page - 1) * clamped_per_page, MAX_OFFSET)


async def _count(conn: PoolConnection, statement: sql.Composed, params: dict[str, object]) -> int:
  """Run a scoped ``count(*)`` and return it.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's transaction.
  statement : sql.Composed
    The already-composed count statement.
  params : dict[str, object]
    Exactly the parameters its predicate binds.

  Returns
  -------
  int
    The count, or ``0`` if the cursor somehow returned no row.
  """
  cursor = await conn.execute(statement, params)
  row = await cursor.fetchone()
  return 0 if row is None else int(str(row[0]))


async def list_deals(conn: PoolConnection, scope: Scope, *, query: DealQuery) -> DealPage:
  """Read one page of deals and its scoped total.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's short ``READ COMMITTED`` transaction. A
    list page never runs at ``SERIALIZABLE``: taking predicate locks over a
    whole list would make every concurrent deal edit a ``40001`` candidate for
    no benefit.
  scope : Scope
    The caller's authorization scope, mandatory.
  query : DealQuery
    The already-validated request.

  Returns
  -------
  DealPage
    The rows, the total under the identical predicate, and the page and page
    size actually applied.

  Notes
  -----
  Two statements, not one, and they share the **same fragment object**: a
  ``count(*)`` can therefore never see a row the page's predicate excludes.
  ``count(*) OVER ()`` would make it one round trip, but a window function
  is outside the portable SQL subset this codebase keeps to.

  The honest consequence, stated rather than hidden: at ``READ COMMITTED`` the
  two statements are two snapshots, so a row committed between them can make
  ``total`` disagree with the page by one. Only the **pipeline** is pinned
  exact, and it gets its own ``SERIALIZABLE, READ ONLY`` transaction, because a
  column header and its cards are read as a reconciliation while a total and a
  page are not.
  """
  where, params = _visible_where(scope, query)
  page, per_page, offset = _paging(query.page, query.per_page)

  cursor = await conn.execute(
    _LIST_DEALS_SQL.format(where=where, order_by=_ORDER_BY[query.sort, query.direction]),
    {**params, "limit": per_page, "offset": offset},
  )
  rows = tuple(_row_to_deal(row) for row in await cursor.fetchall())

  total = await _count(conn, _COUNT_DEALS_SQL.format(where=where), params)
  return DealPage(rows=rows, total=total, page=page, per_page=per_page)


async def pipeline(
  conn: PoolConnection, scope: Scope, *, status: StatusFilter
) -> tuple[StageBucket, ...]:
  """Read the five pipeline columns' exact counts and € totals.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE, READ ONLY`` transaction,
    so a column's header and its cards cannot disagree about what exists.
  scope : Scope
    The caller's authorization scope, mandatory.
  status : StatusFilter
    The parent's archive filter.

  Returns
  -------
  tuple[StageBucket, ...]
    **Always five buckets**, in :data:`STAGE_ORDER`.

  Notes
  -----
  One ``GROUP BY d.stage`` statement with ``count(*)`` and
  ``COALESCE(SUM(d.amount), CAST(0 AS DECIMAL(12,2)))`` under the shared
  predicate. ``GROUP BY`` omits a stage that holds
  nothing, so the missing columns are zero-filled here from
  :data:`STAGE_ORDER` — bucket fill from a code constant, **not** a Python sum.
  A stage's ``amount`` is therefore either the engine's ``SUM`` or the constant
  ``Decimal("0.00")``, and no float is involved at any point.

  A stage outside the five cannot exist (``ck_deals_stage``), so the lookup
  below cannot silently drop a populated column.
  """
  where, params = _visible_where(scope, _pipeline_query(status=status, stage=None))
  cursor = await conn.execute(_PIPELINE_AGGREGATE_SQL.format(where=where), params)

  grouped: dict[str, tuple[int, Decimal]] = {
    str(row[0]): (int(str(row[1])), _as_decimal(row[2], column="SUM(deals.amount)"))
    for row in await cursor.fetchall()
  }
  return tuple(
    StageBucket(stage=stage, count=grouped[stage][0], amount=grouped[stage][1])
    if stage in grouped
    else StageBucket(stage=stage, count=0, amount=Decimal("0.00"))
    for stage in STAGE_ORDER
  )


async def pipeline_cards(
  conn: PoolConnection,
  scope: Scope,
  *,
  status: StatusFilter,
  stage: DealStage,
  limit: int,
) -> tuple[DealRow, ...]:
  """Read one pipeline column's cards.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the same ``SERIALIZABLE, READ ONLY`` transaction as
    :func:`pipeline`.
  scope : Scope
    The caller's authorization scope, mandatory.
  status : StatusFilter
    The parent's archive filter, from the same builder as the aggregate.
  stage : DealStage
    The column to read.
  limit : int
    The column's own cap, clamped to :data:`MAX_PER_PAGE`. The caller passes
    :data:`PIPELINE_CARDS_PER_STAGE`.

  Returns
  -------
  tuple[DealRow, ...]
    In ``amount DESC, id ASC``, a fixed order. The pipeline
    surface allows no ``sort``, no ``dir`` and no ``page``, so the order
    is literal text and nothing selects it.

  Notes
  -----
  One statement per stage, and five calls rather than one statement: top-N-per
  group needs a window function or ``LATERAL``, and the portable SQL subset
  this codebase keeps to has neither. A single rows statement with a global
  ``LIMIT`` would let a busy
  column eat the budget and render its neighbours empty beside a non-zero
  header — a *visibly* wrong screen. Each column gets its own bound and uses
  ``ix_deals_stage_close``'s leading column.

  The cap makes a column's card list a **bounded** view of an **exact** header:
  the aggregate is authoritative, and saying a column is capped is the
  template's job.
  """
  where, params = _visible_where(scope, _pipeline_query(status=status, stage=stage))
  cursor = await conn.execute(
    _PIPELINE_CARDS_SQL.format(where=where),
    {**params, "limit": min(max(limit, 1), MAX_PER_PAGE)},
  )
  return tuple(_row_to_deal(row) for row in await cursor.fetchall())


async def get_deal(conn: PoolConnection, scope: Scope, *, deal_id: UUID) -> DealRow | None:
  """Read one deal under the **scope-only** predicate.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's transaction.
  scope : Scope
    The caller's authorization scope, mandatory.
  deal_id : UUID
    Which deal.

  Returns
  -------
  DealRow | None
    ``None`` for a foreign deal **and** for a missing one: the two are one code
    path, which is what makes the 404 byte-identical for the same principal,
    modulo the correlation id.

  Notes
  -----
  There is deliberately **no archive clause**. This read is also the re-read
  every deal mutation branches on, and it must *see* the parent's archived
  state rather than be filtered by it: it is what turns a zero-row
  ``UPDATE`` into the right answer — 404, 409 ``stale`` or 409
  ``archived_parent``.
  """
  cursor = await conn.execute(
    _GET_DEAL_SQL.format(scope=_read_scope(scope)),
    {"deal_id": str(deal_id), "actor_id": str(scope.actor_id)},
  )
  row = await cursor.fetchone()
  return None if row is None else _row_to_deal(row)


async def list_for_contact(
  conn: PoolConnection,
  scope: Scope,
  *,
  contact_id: UUID,
  page: int,
  per_page: int,
) -> DealPage:
  """Read one contact's deals, newest first.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's short ``READ COMMITTED`` transaction.
  scope : Scope
    The caller's authorization scope, mandatory.
  contact_id : UUID
    The parent.
  page : int
    1-based.
  per_page : int
    Clamped to :data:`MAX_PER_PAGE`.

  Returns
  -------
  DealPage
    The rows and the scoped total under the identical predicate.

  Notes
  -----
  **No archive clause either.** The parent read has already decided whether
  this contact is viewable, and an archived contact's detail must still show
  what its owner is about to restore — exactly the rule
  ``P-ACTIVITY-TIMELINE-AGENT`` states for the timeline.
  """
  scope_fragment = _read_scope(scope)
  clamped_page, clamped_per_page, offset = _paging(page, per_page)
  params: dict[str, object] = {
    "contact_id": str(contact_id),
    "actor_id": str(scope.actor_id),
  }

  cursor = await conn.execute(
    _LIST_FOR_CONTACT_SQL.format(scope=scope_fragment),
    {**params, "limit": clamped_per_page, "offset": offset},
  )
  rows = tuple(_row_to_deal(row) for row in await cursor.fetchall())

  total = await _count(conn, _COUNT_FOR_CONTACT_SQL.format(scope=scope_fragment), params)
  return DealPage(rows=rows, total=total, page=clamped_page, per_page=clamped_per_page)


async def parent_state(conn: PoolConnection, scope: Scope, *, contact_id: UUID) -> ParentState:
  """Resolve a candidate parent to one of three states, and nothing more.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's transaction — the **same** transaction as
    the write it guards, so a contact archived between the form render and the
    submit is either seen or raises ``40001`` and is seen on the retry
   .
  scope : Scope
    The caller's authorization scope, mandatory.
  contact_id : UUID
    The candidate parent.

  Returns
  -------
  ParentState
    ``missing`` for a foreign **or** absent contact — one code path, which is
    what makes the create form's 404 byte-identical to the submit's;
    ``archived``
    for an own archived one; ``active`` otherwise.

  Notes
  -----
  This is the one function ``GET /contacts/{id}/deals/new`` and
  ``POST /contacts/{id}/deals`` share, so the form's 404 cannot diverge from
  the submit's. The order the caller then applies is fixed: scope first,
  archived state second.
  """
  cursor = await conn.execute(
    _PARENT_STATE_SQL.format(scope=_read_scope(scope)),
    {"contact_id": str(contact_id), "actor_id": str(scope.actor_id)},
  )
  row = await cursor.fetchone()
  if row is None:
    return "missing"
  return "archived" if row[0] is True else "active"


async def insert_deal(
  conn: PoolConnection,
  scope: Scope,
  *,
  deal_id: UUID,
  contact_id: UUID,
  fields: DealFields,
  now: datetime,
) -> CreateOutcome:
  """Create one deal under a contact the actor may see, at stage ``new``.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  scope : Scope
    The caller's authorization scope. **This is where the parent check gets its
    predicate**; the deal itself carries no owner column.
  deal_id : UUID
    The application-generated id (``A3``).
  contact_id : UUID
    The parent.
  fields : DealFields
    The three writable fields and the normalized companion of the searchable
    one.
  now : datetime
    The caller's instant, written to ``stage_changed_at``, ``created_at`` and
    ``updated_at`` alike.

  Returns
  -------
  CreateOutcome
    ``parent_missing`` (the identical 404), ``parent_archived`` (a 409) or
    ``created``. **Nothing is written** unless the
    answer is ``created``.

  Raises
  ------
  TypeError
    If ``fields.amount`` is not a :class:`~decimal.Decimal`.

  Notes
  -----
  A tagged outcome rather than an exception or a bare ``None``: three outcomes
  must be **distinguishable to the service** and two of them
  **indistinguishable in the response**. A repository exception would put the
  choice of status one layer too low; a bare ``None`` would collapse the 404
  and the 409 into one. The tag carries exactly that distinction and **no
  existence information beyond it** — in particular it never says whose contact
  a ``missing`` one is, or whether it exists at all.

  The parent is checked here as well as by the service's own earlier call, and
  the two are not the same check: the service's is the **decision**, taken
  before any receipt row is written; this one is a **guard**, in the same
  transaction and therefore the same snapshot, which exists so the ``INSERT``
  cannot be issued by a caller that skipped the decision.
  """
  state = await parent_state(conn, scope, contact_id=contact_id)
  if state == "missing":
    return "parent_missing"
  if state == "archived":
    return "parent_archived"

  await conn.execute(
    _INSERT_DEAL_SQL,
    {
      "id": str(deal_id),
      "contact_id": str(contact_id),
      "title": fields.title,
      "title_lower": fields.title_lower,
      "amount": _as_decimal(fields.amount, column="DealFields.amount"),
      "close_date": fields.close_date,
      "now": now,
    },
  )
  return "created"


async def update_deal_versioned(
  conn: PoolConnection,
  scope: Scope,
  *,
  deal_id: UUID,
  expected_version: int,
  fields: DealFields,
  now: datetime,
) -> DealRow | None:
  """Edit the three writable fields of one deal under an active parent.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  scope : Scope
    The caller's authorization scope, inlined into the statement's correlated
    ``EXISTS``.
  deal_id : UUID
    Which deal.
  expected_version : int
    The version the submitted form carried.
  fields : DealFields
    The new values and the normalized companion.
  now : datetime
    The caller's instant, written to ``updated_at``.

  Returns
  -------
  DealRow | None
    The row as the database now holds it, or ``None`` when **no row matched** —
    foreign, missing, stale, or under an archived parent, four situations
    conflated on purpose. The caller re-reads with :func:`get_deal` and decides
    which 404 or which 409 context that was; this function never chooses a
    status.

  Raises
  ------
  TypeError
    If ``fields.amount`` is not a :class:`~decimal.Decimal`.

  Notes
  -----
  ``contact_id`` and ``stage`` appear in no ``SET`` list here, and there is no
  parameter for either: re-parenting is an ownership move by another name,
  and the stage has its own guarded statement.

  The row is read back with the ordinary ``get_deal`` statement inside the same
  transaction rather than with a ``RETURNING`` clause: no statement in this
  codebase uses ``RETURNING``, and keeping the tree uniform is what makes
  the portability claim one claim instead of two.
  """
  cursor = await conn.execute(
    _UPDATE_DEAL_SQL.format(scope=_read_scope(scope)),
    {
      "deal_id": str(deal_id),
      "version": expected_version,
      "actor_id": str(scope.actor_id),
      "title": fields.title,
      "title_lower": fields.title_lower,
      "amount": _as_decimal(fields.amount, column="DealFields.amount"),
      "close_date": fields.close_date,
      "now": now,
    },
  )
  if cursor.rowcount != 1:
    return None
  return await get_deal(conn, scope, deal_id=deal_id)


async def change_stage_versioned(
  conn: PoolConnection,
  scope: Scope,
  *,
  deal_id: UUID,
  expected_version: int,
  from_stage: str,
  new_stage: str,
  stage_changed_at: datetime,
  now: datetime,
) -> DealRow | None:
  """Move one deal from the stage the caller read to the stage it decided on.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  scope : Scope
    The caller's authorization scope, inlined into the correlated ``EXISTS``.
  deal_id : UUID
    Which deal.
  expected_version : int
    The version the submitted form carried.
  from_stage : str
    The stage the caller read **in this transaction**, and the statement's own
    guard rail.
  new_stage : str
    The target. The graph was checked by the service against ``from_stage``
   ; this function enforces neither the graph nor the terminal
    rule, because a repository that could refuse a write would be a repository
    that decides.
  stage_changed_at : datetime
    Rewritten on every accepted stage change; it is a business fact, not a
    row-touch timestamp.
  now : datetime
    The caller's instant, written to ``updated_at``.

  Returns
  -------
  DealRow | None
    The row as the database now holds it, or ``None`` when no row matched —
    foreign, missing, stale, moved out from under the caller, or under an
    archived parent, conflated on purpose.

  Notes
  -----
  ``stage_changed_at`` and ``now`` are two parameters although every caller
  passes the same instant: one is the business fact, the other is
  ``updated_at``. A single parameter would let a future back-dated stage change
  silently rewrite ``updated_at`` — exactly the reason ``archive_contact``
  splits ``archived_at`` from ``now``.

  Won and Lost reach this same statement with ``new_stage='won'``/``'lost'``.
  Moving *out of* a terminal stage never reaches SQL at all: the service
  answers 409 ``stage_terminal`` from the row it read, and a move
  to the current stage answers 400 — a no-op is not a mutation
  and gets no receipt.
  """
  cursor = await conn.execute(
    _CHANGE_STAGE_SQL.format(scope=_read_scope(scope)),
    {
      "deal_id": str(deal_id),
      "version": expected_version,
      "actor_id": str(scope.actor_id),
      "from_stage": from_stage,
      "new_stage": new_stage,
      "stage_changed_at": stage_changed_at,
      "now": now,
    },
  )
  if cursor.rowcount != 1:
    return None
  return await get_deal(conn, scope, deal_id=deal_id)


async def dashboard_totals(conn: PoolConnection, scope: Scope) -> DealTotals:
  """Read the open and won deal counts and € totals in one scoped statement.

  Raises
  ------
  TypeError
    If either sum arrives as anything but a :class:`~decimal.Decimal`
    (the runtime half of the no-float rule, at the repository boundary).
  """
  cursor = await conn.execute(
    _DASHBOARD_TOTALS_SQL.format(scope=_read_scope(scope)),
    {"actor_id": str(scope.actor_id)},
  )
  row = await cursor.fetchone()
  if row is None:  # pragma: no cover - an aggregate always returns one row
    return DealTotals(
      open_count=0, open_amount=Decimal("0.00"), won_count=0, won_amount=Decimal("0.00")
    )
  return DealTotals(
    open_count=int(str(row[0])),
    open_amount=_as_decimal(row[1], column="SUM(deals.amount) open"),
    won_count=int(str(row[2])),
    won_amount=_as_decimal(row[3], column="SUM(deals.amount) won"),
  )
