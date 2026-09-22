"""``contacts`` — the first business repository, and the first ``Scope`` consumer.

`contracts/slice-b.md` §1(b) and §1(c). Every public function takes a
mandatory :class:`app.security.principal.Scope` as its first *business*
argument (``PIN 7``, ``ARC-001``), and the ownership predicate it carries is
**in the SQL** — in the list, in the count, in the search, in the detail read
and in every ``UPDATE``. There is no Python post-filter anywhere in this
module, because a post-filter still leaks existence through counts and
pagination totals (``PLAN.md`` §5).

Four shapes carry that, and each is a property of the code rather than of a
review:

*One ``WHERE`` builder.* :func:`_visible_where` composes the list's predicate
and the count consumes the identical fragment, so a count can never see a row
the list cannot (``DATA_CONTRACT.md`` §6.6). The ownership conjunct is one of
exactly **two** module-level literals chosen by ``scope.is_admin`` — never
``(%(admin)s OR c.owner_id = %(actor_id)s)``, which would put the whole
authorization decision inside one bound parameter and deny the planner
``ix_contacts_owner_archived_name`` for the agent case.

*The search ``OR`` is parenthesised inside the fragment constant.* An
unparenthesised ``OR`` beside the ownership conjunct makes every row of every
owner match — the classic scope bypass (``ACC-103``, ``SQL-032``). The
parentheses live in the constant, so no edit to the builder can lose them.

*Every write is versioned.* ``WHERE id = %(contact_id)s AND version =
%(version)s`` with ``version = version + 1`` in the same statement (§4.1); no
trigger, ever. Zero rows matched is reported as ``None`` and conflates
foreign, missing, stale and wrong-archive-state **on purpose**, so that no
single statement is an existence oracle. The service re-reads under the
scope-only predicate and decides which 404 or which 409 context that was
(§4.3, ``PIN 3``, ``PIN 4``).

*Nothing is deleted.* Archive sets ``archived_at``; the runtime role holds no
``DELETE`` on this table at all (migration ``0003`` step 05), so an archive
written as a delete would fail with ``42501`` rather than lose a row.

``Scope`` is imported under ``TYPE_CHECKING`` only: the annotations need the
type, and ``scope.actor_id`` / ``scope.is_admin`` are plain attribute reads at
runtime. That keeps ``app/db/**`` free of any runtime import of
``app/security/**`` (§1(b) B3).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, LiteralString, cast
from uuid import UUID

from psycopg import sql

if TYPE_CHECKING:
  from datetime import datetime

  from app.db.pool import PoolConnection
  from app.security.principal import Scope

__all__ = [
  "DEFAULT_PER_PAGE",
  "MAX_OFFSET",
  "MAX_PER_PAGE",
  "ContactFields",
  "ContactKind",
  "ContactPage",
  "ContactQuery",
  "ContactRow",
  "SortDir",
  "SortKey",
  "StatusFilter",
  "archive_contact",
  "get_contact",
  "insert_contact",
  "list_contacts",
  "reassign_contact",
  "restore_contact",
  "update_contact",
]

#: ``UX_FLOWS.md``'s pinned page size for contacts.
DEFAULT_PER_PAGE: Final[int] = 25
#: ``ACC-112``'s hard clamp: a larger ``per_page`` is reduced, never refused.
MAX_PER_PAGE: Final[int] = 100
#: ``DATA_CONTRACT.md`` §6.6's server-side offset clamp. A page past it repeats
#: the last reachable window rather than making the database skip unboundedly.
MAX_OFFSET: Final[int] = 10_000

#: The five sort keys ``ACCESS_MATRIX.md`` §5.2 allows, default ``updated_at``.
type SortKey = Literal["name", "company", "email", "created_at", "updated_at"]
type SortDir = Literal["asc", "desc"]
#: The lead/customer column is ``kind``; the request token ``status`` is the
#: archive filter and reaches ``archived_at`` (§3.9's token map).
type ContactKind = Literal["lead", "customer"]
type StatusFilter = Literal["active", "archived", "all"]

#: The ownership conjunct of a **read**, aliased, as ``P-CONTACT-SCOPE-AGENT``
#: and ``P-CONTACT-VISIBLE-AGENT`` write it (§6.6). Its admin twin is the
#: absence of a conjunct, not a widened one.
_READ_OWNED: Final = sql.SQL("AND c.owner_id = %(actor_id)s")
_READ_ANY: Final = sql.SQL("")

#: The same for an ``UPDATE``, which names no alias: the statement is
#: ``UPDATE public.contacts``, so its columns are unqualified.
_WRITE_OWNED: Final = sql.SQL("AND owner_id = %(actor_id)s")
_WRITE_ANY: Final = sql.SQL("")

_VISIBLE_OWNED: Final = sql.SQL("c.owner_id = %(actor_id)s")
_VISIBLE_KIND: Final = sql.SQL("c.kind = %(kind)s")

#: Prefix-only search over the three normalized columns, OR-ed **inside one
#: pair of parentheses** and reusing a single bound parameter. No leading
#: ``%``, no ``ILIKE``, no ``~``, no ``SIMILAR TO``, no ``COLLATE`` (§6.6,
#: §9.1). The service escapes ``!``, ``%`` and ``_`` in that order and appends
#: the single trailing ``%``.
_VISIBLE_SEARCH: Final = sql.SQL(
  "(   c.full_name_lower LIKE %(term)s ESCAPE '!'\n"
  "        OR c.company_lower   LIKE %(term)s ESCAPE '!'\n"
  "        OR c.email_lower     LIKE %(term)s ESCAPE '!')"
)

#: ``status`` selects a fragment; the submitted string never reaches SQL.
#: ``all`` maps to ``None`` — **no** conjunct — which is why ``active`` being
#: the default makes ``PIN 4``'s "archived hidden by default" the absence of an
#: input rather than a branch a caller can forget.
#:
#: The three keys are spelled out and the lookup is indexed rather than
#: ``.get``-ed, so that a value outside the enum raises ``KeyError`` — a
#: programming error, exactly as an out-of-allowlist sort key is — instead of
#: silently reading as ``all`` and widening the result to archived rows. The
#: service has already answered 400 for such a value (``ACC-109``); this is the
#: failure mode of the one filter that could otherwise fail *open*.
_ARCHIVE_FRAGMENTS: Final[dict[StatusFilter, sql.SQL | None]] = {
  "active": sql.SQL("c.archived_at IS NULL"),
  "archived": sql.SQL("c.archived_at IS NOT NULL"),
  "all": None,
}

#: The ten allowed orderings, each a module-level literal with a deterministic
#: tiebreaker on ``c.id``. The submitted ``sort``/``dir`` strings only *look
#: up* a fragment; no request text ever reaches an ``ORDER BY``. A ``KeyError``
#: here is a programming error — the service has already answered 400 for a
#: value outside the allowlist (``ACC-110``, ``ACC-111``).
#:
#: The tiebreaker follows the sort direction rather than being pinned to
#: ``ASC``: PostgreSQL can walk ``ix_contacts_owner_archived_name`` backwards
#: only when *every* ``ORDER BY`` column is reversed together, so
#: ``full_name_lower DESC, id ASC`` would force a sort that
#: ``full_name_lower DESC, id DESC`` does not. Determinism is identical.
_ORDER_BY: Final[dict[tuple[SortKey, SortDir], sql.SQL]] = {
  ("name", "asc"): sql.SQL("c.full_name_lower ASC, c.id ASC"),
  ("name", "desc"): sql.SQL("c.full_name_lower DESC, c.id DESC"),
  ("company", "asc"): sql.SQL("c.company_lower ASC, c.id ASC"),
  ("company", "desc"): sql.SQL("c.company_lower DESC, c.id DESC"),
  ("email", "asc"): sql.SQL("c.email_lower ASC, c.id ASC"),
  ("email", "desc"): sql.SQL("c.email_lower DESC, c.id DESC"),
  ("created_at", "asc"): sql.SQL("c.created_at ASC, c.id ASC"),
  ("created_at", "desc"): sql.SQL("c.created_at DESC, c.id DESC"),
  ("updated_at", "asc"): sql.SQL("c.updated_at ASC, c.id ASC"),
  ("updated_at", "desc"): sql.SQL("c.updated_at DESC, c.id DESC"),
}

#: The three reads spell their column list out in full rather than sharing a
#: fragment — the package convention ``users.py`` set, for the reason it gives:
#: every SELECT names its columns (``ARC-011``) and SQL assembled from pieces
#: is exactly the shape a reviewer should not have to think about.
#: :func:`_row_to_contact` unpacks both of the row-returning ones, so the two
#: lists must stay identical; they are adjacent here so a drift is visible.
#:
#: ``u.display_name`` is amendment **A-8**: ``CONTRACTS.md`` §8.2/§8.3 freeze
#: ``owner_name`` on both the detail and the row, and the join is over a
#: ``NOT NULL`` foreign key, so it cannot change the row count and the count
#: statement's identical ``WHERE`` still holds.
_GET_CONTACT_SQL: Final = sql.SQL("""
SELECT c.id, c.owner_id, u.display_name, c.full_name, c.company, c.email, c.phone,
       c.kind, c.archived_at, c.version, c.created_at, c.updated_at
  FROM public.contacts c
  JOIN public.users u ON u.id = c.owner_id
 WHERE c.id = %(contact_id)s
   {scope}
""")

_LIST_CONTACTS_SQL: Final = sql.SQL("""
SELECT c.id, c.owner_id, u.display_name, c.full_name, c.company, c.email, c.phone,
       c.kind, c.archived_at, c.version, c.created_at, c.updated_at
  FROM public.contacts c
  JOIN public.users u ON u.id = c.owner_id
 {where}
 ORDER BY {order_by}
 LIMIT %(limit)s OFFSET %(offset)s
""")

_COUNT_CONTACTS_SQL: Final = sql.SQL("""
SELECT count(*)
  FROM public.contacts c
  JOIN public.users u ON u.id = c.owner_id
 {where}
""")

_INSERT_CONTACT_SQL: Final[LiteralString] = """
INSERT INTO public.contacts
  (id, owner_id, full_name, full_name_lower, company, company_lower,
   email, email_lower, phone, kind, archived_at, version, created_at, updated_at)
VALUES
  (%(id)s, %(owner_id)s, %(full_name)s, %(full_name_lower)s, %(company)s, %(company_lower)s,
   %(email)s, %(email_lower)s, %(phone)s, %(kind)s, NULL, 1, %(now)s, %(now)s)
"""

_UPDATE_CONTACT_SQL: Final = sql.SQL("""
UPDATE public.contacts
   SET full_name       = %(full_name)s,
       full_name_lower = %(full_name_lower)s,
       company         = %(company)s,
       company_lower   = %(company_lower)s,
       email           = %(email)s,
       email_lower     = %(email_lower)s,
       phone           = %(phone)s,
       kind            = %(kind)s,
       version         = version + 1,
       updated_at      = %(now)s
 WHERE id = %(contact_id)s
   AND version = %(version)s
   AND archived_at IS NULL
   {scope}
""")

_ARCHIVE_CONTACT_SQL: Final = sql.SQL("""
UPDATE public.contacts
   SET archived_at = %(archived_at)s,
       version     = version + 1,
       updated_at  = %(now)s
 WHERE id = %(contact_id)s
   AND version = %(version)s
   AND archived_at IS NULL
   {scope}
""")

_RESTORE_CONTACT_SQL: Final = sql.SQL("""
UPDATE public.contacts
   SET archived_at = NULL,
       version     = version + 1,
       updated_at  = %(now)s
 WHERE id = %(contact_id)s
   AND version = %(version)s
   AND archived_at IS NOT NULL
   {scope}
""")

#: Admin only, so there is no ownership conjunct at all and none is composed.
#: ``archived_at IS NULL`` is ``R25``: reassignment is denied while a contact
#: is archived — restore first.
_REASSIGN_CONTACT_SQL: Final[LiteralString] = """
UPDATE public.contacts
   SET owner_id   = %(new_owner_id)s,
       version    = version + 1,
       updated_at = %(now)s
 WHERE id = %(contact_id)s
   AND version = %(version)s
   AND archived_at IS NULL
"""


@dataclass(frozen=True, slots=True)
class ContactRow:
  """One contact as every read returns it — display columns only.

  Attributes
  ----------
  id : UUID
    The contact's application-generated id.
  owner_id : UUID
    Whose contact. The **only** ownership column in the business schema:
    deals and activities reach their owner by the join to this table.
  owner_name : str
    ``users.display_name`` of the owner, from the join (amendment **A-8**).
    ``CONTRACTS.md`` §8.2/§8.3 freeze ``contact.owner_name``, and a second
    lookup per row would be an N+1; the join is over a ``NOT NULL`` foreign
    key, so it can never change the row count.
  full_name : str
    As typed. The sort and search key is the normalized ``full_name_lower``,
    which no read returns.
  company : str
    As typed; may be empty.
  email : str
    As typed. **No unique constraint of any kind** exists on this column
    (``T-36``, ``SQL-022``).
  phone : str
    As typed; may be empty.
  kind : str
    ``lead`` or ``customer``.
  archived_at : datetime | None
    ``None`` for an active contact. The only archive flag in the schema, and
    the only nullable column on the table (§4.2).
  version : int
    The optimistic-concurrency guard every write carries.
  created_at : datetime
    From the caller's injected clock, never a server clock.
  updated_at : datetime
    Likewise.
  """

  id: UUID
  owner_id: UUID
  owner_name: str
  full_name: str
  company: str
  email: str
  phone: str
  kind: str
  archived_at: datetime | None
  version: int
  created_at: datetime
  updated_at: datetime


@dataclass(frozen=True, slots=True)
class ContactFields:
  """The five writable fields, with their normalized companions.

  ``ACCESS_MATRIX.md`` §5.1 allows ``name``, ``company``, ``email``, ``phone``
  and ``kind`` on create and on edit, and nothing else. The service normalizes
  in Python and fills both halves of each pair; the repository writes what it
  is given and allowlists nothing, because **this dataclass's field list is
  the allowlist**. That is why a mass-assignment bug cannot exist in this
  module: the ``SET`` list is fixed literal text and there is no parameter
  through which an unexpected column name could arrive.

  Attributes
  ----------
  full_name : str
    1..160 characters.
  full_name_lower : str
    ``full_name`` normalized — the sort and search key.
  company : str
    0..160 characters.
  company_lower : str
    Its normalized companion.
  email : str
    3..254 characters, containing an ``@`` with something on either side.
  email_lower : str
    Its normalized companion.
  phone : str
    0..32 characters.
  kind : ContactKind
    ``lead`` or ``customer``.
  """

  full_name: str
  full_name_lower: str
  company: str
  company_lower: str
  email: str
  email_lower: str
  phone: str
  kind: ContactKind


@dataclass(frozen=True, slots=True)
class ContactQuery:
  """One already-validated list request. Nothing here is a raw request string.

  Attributes
  ----------
  term : str | None
    The search term, already normalized and escaped for ``!``, ``%`` and
    ``_`` in that order, with a single trailing ``%`` appended. ``None``
    means no search. It is bound as a parameter and reused by all three
    comparisons.
  kind : ContactKind | None
    ``None`` means no ``kind`` filter.
  status : StatusFilter
    The archive filter. ``active`` is the default and hides archived rows;
    ``all`` contributes no conjunct at all.
  sort : SortKey
    Looks up an ``ORDER BY`` fragment; never reaches SQL as text.
  direction : SortDir
    Likewise.
  page : int
    1-based. A non-positive or non-integer page is a **400** in the service
    and never arrives here; a page past the end is an ordinary empty result.
  per_page : int
    Clamped to :data:`MAX_PER_PAGE` here as well as in the service, because
    the constant lives in this module.
  """

  term: str | None
  kind: ContactKind | None
  status: StatusFilter
  sort: SortKey
  direction: SortDir
  page: int
  per_page: int


@dataclass(frozen=True, slots=True)
class ContactPage:
  """One page of contacts and the scoped total that goes with it.

  Attributes
  ----------
  rows : tuple[ContactRow, ...]
    The page, in the requested order.
  total : int
    The count under the **identical** ``WHERE``, from the identical builder,
    so it can never include a row the page's predicate excludes.
  page : int
    The page actually served, 1-based.
  per_page : int
    The page size actually applied, after the clamp.
  """

  rows: tuple[ContactRow, ...]
  total: int
  page: int
  per_page: int


def _row_to_contact(row: tuple[object, ...]) -> ContactRow:
  """Build a :class:`ContactRow` from one row of the contact SELECT.

  Parameters
  ----------
  row : tuple[object, ...]
    The tuple as psycopg returned it, in the order of the SELECT list.

  Returns
  -------
  ContactRow
    The row with its ``TEXT`` ids converted back to :class:`uuid.UUID`. This
    is the module's single conversion point in that direction
    (``DATA_CONTRACT.md`` §2.2), and the reason the list, the detail read and
    every mutation's read-back cannot disagree about a column's meaning.
  """
  archived_at = row[8]
  return ContactRow(
    id=UUID(str(row[0])),
    owner_id=UUID(str(row[1])),
    owner_name=str(row[2]),
    full_name=str(row[3]),
    company=str(row[4]),
    email=str(row[5]),
    phone=str(row[6]),
    kind=str(row[7]),
    archived_at=None if archived_at is None else cast("datetime", archived_at),
    version=int(str(row[9])),
    created_at=cast("datetime", row[10]),
    updated_at=cast("datetime", row[11]),
  )


def _read_scope(scope: Scope) -> sql.SQL:
  """Return the ownership conjunct of a **read**, one of exactly two literals.

  Parameters
  ----------
  scope : Scope
    The caller's authorization scope.

  Returns
  -------
  sql.SQL
    ``AND c.owner_id = %(actor_id)s`` for an agent; the empty fragment for an
    admin, whose scope is unfiltered.
  """
  return _READ_ANY if scope.is_admin else _READ_OWNED


def _write_scope(scope: Scope) -> sql.SQL:
  """Return the ownership conjunct of an ``UPDATE``, one of exactly two literals.

  Parameters
  ----------
  scope : Scope
    The caller's authorization scope.

  Returns
  -------
  sql.SQL
    ``AND owner_id = %(actor_id)s`` for an agent; the empty fragment for an
    admin. Unaliased, because the statement is ``UPDATE public.contacts``.

  Notes
  -----
  The conjunct is in the ``UPDATE`` itself and not only in the re-read the
  service does first (``ACC-014``). The re-read decides the *status*; this
  conjunct means that a service which skipped it still cannot write a foreign
  row.
  """
  return _WRITE_ANY if scope.is_admin else _WRITE_OWNED


def _visible_where(scope: Scope, query: ContactQuery) -> tuple[sql.Composed, dict[str, object]]:
  """Compose the ``WHERE`` of a contact list, and the parameters that go with it.

  Parameters
  ----------
  scope : Scope
    The caller's authorization scope. An agent gets the ownership conjunct;
    an admin gets no conjunct rather than a widened one.
  query : ContactQuery
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
  This is the single place a contact predicate is built, which is what makes
  §6.6's "a count can never see a row the list cannot" a property of the code:
  :func:`list_contacts` hands the very same object to both of its statements.

  The empty case is real and reachable: an admin asking for ``status=all``
  with no ``kind`` and no search has no conjunct at all, so the fragment is
  empty and the statement carries no ``WHERE`` keyword — not a dangling one.

  Every conjunct is a module-level literal. Only values are bound, and the
  submitted *choices* (``status``, ``kind``, ``sort``, ``dir``) select a
  fragment rather than reaching SQL as text.
  """
  conjuncts: list[sql.Composable] = []
  params: dict[str, object] = {}

  if not scope.is_admin:
    conjuncts.append(_VISIBLE_OWNED)
    params["actor_id"] = str(scope.actor_id)

  archive = _ARCHIVE_FRAGMENTS[query.status]
  if archive is not None:
    conjuncts.append(archive)

  if query.kind is not None:
    conjuncts.append(_VISIBLE_KIND)
    params["kind"] = query.kind

  if query.term is not None:
    conjuncts.append(_VISIBLE_SEARCH)
    params["term"] = query.term

  if not conjuncts:
    return sql.Composed([]), params
  return sql.SQL("WHERE ") + sql.SQL("\n   AND ").join(conjuncts), params


async def list_contacts(conn: PoolConnection, scope: Scope, *, query: ContactQuery) -> ContactPage:
  """Read one page of contacts and its scoped total.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's short ``READ COMMITTED`` transaction
    (§6.8 row 6). A list page never runs at ``SERIALIZABLE``: taking
    predicate locks over a whole list would make every concurrent contact
    edit a ``40001`` candidate for no benefit.
  scope : Scope
    The caller's authorization scope, mandatory (``PIN 7``).
  query : ContactQuery
    The already-validated request.

  Returns
  -------
  ContactPage
    The rows, the total under the identical predicate, and the page and page
    size actually applied.

  Notes
  -----
  Two statements, not one. ``count(*) OVER ()`` would make it one round trip,
  but a window function is absent from §9.2's portable set and would make the
  total's correctness depend on the ``LIMIT``/``OFFSET`` shape. The honest
  consequence, stated rather than hidden: at ``READ COMMITTED`` the two
  statements are two snapshots, so a row committed between them can make
  ``total`` disagree with the page by one. It can **never** show a row the
  predicate excludes, because the predicate is the same object; only the
  dashboard's totals are pinned exact, and they get their own
  ``SERIALIZABLE, READ ONLY`` transaction in Slice D.

  ``LIMIT`` and ``OFFSET`` are bound parameters, clamped here as well as in
  the service. A page past the end is an ordinary empty result (``ACC-112``),
  never an error. Keyset pagination is §6.6's documented upgrade path and is
  deliberately not taken: at the profile's 1,000 contacts ``OFFSET`` stays
  inside a bounded scan, and keyset would change pagination markup that
  ``R24``/``R38`` have already frozen.
  """
  where, params = _visible_where(scope, query)
  page = max(query.page, 1)
  per_page = min(max(query.per_page, 1), MAX_PER_PAGE)
  offset = min((page - 1) * per_page, MAX_OFFSET)

  cursor = await conn.execute(
    _LIST_CONTACTS_SQL.format(where=where, order_by=_ORDER_BY[query.sort, query.direction]),
    {**params, "limit": per_page, "offset": offset},
  )
  rows = tuple(_row_to_contact(row) for row in await cursor.fetchall())

  cursor = await conn.execute(_COUNT_CONTACTS_SQL.format(where=where), params)
  total_row = await cursor.fetchone()
  total = 0 if total_row is None else int(str(total_row[0]))

  return ContactPage(rows=rows, total=total, page=page, per_page=per_page)


async def get_contact(conn: PoolConnection, scope: Scope, *, contact_id: UUID) -> ContactRow | None:
  """Read one contact under the **scope-only** predicate.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's transaction.
  scope : Scope
    The caller's authorization scope, mandatory.
  contact_id : UUID
    Which contact.

  Returns
  -------
  ContactRow | None
    ``None`` for a foreign contact **and** for a missing one: the two are one
    code path, which is what makes the 404 byte-identical for the same
    principal, modulo the correlation id (``PIN 8``, ``R27``).

  Notes
  -----
  There is deliberately **no archive clause**. An archived contact stays
  readable to its owner (``ACC-006``), and this read is also the re-read every
  mutation branches on, which has to *see* ``archived_at`` rather than be
  filtered by it (§4.3). It is what turns a zero-row ``UPDATE`` into the right
  answer: 404, 409 ``stale`` or 409 with the archived context.
  """
  cursor = await conn.execute(
    _GET_CONTACT_SQL.format(scope=_read_scope(scope)),
    {"contact_id": str(contact_id), "actor_id": str(scope.actor_id)},
  )
  row = await cursor.fetchone()
  return None if row is None else _row_to_contact(row)


async def insert_contact(
  conn: PoolConnection,
  scope: Scope,
  *,
  contact_id: UUID,
  fields: ContactFields,
  now: datetime,
) -> None:
  """Create one contact owned by the actor.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  scope : Scope
    The caller's authorization scope. **This is where ``owner_id`` comes
    from.**
  contact_id : UUID
    The application-generated id (``A3``).
  fields : ContactFields
    The five writable fields and their normalized companions.
  now : datetime
    The caller's instant, written to ``created_at`` and ``updated_at`` alike.

  Notes
  -----
  There is no ``owner_id`` parameter. ``ACC-007`` says the owner "is set by
  the service, never read from the request"; putting it behind the ``Scope``
  is stronger — there is no parameter through which a request value could
  arrive, so an agent supplying ``owner_id`` (``ACC-012``) is unreachable from
  this module by construction rather than by allowlist. An admin creates for
  themselves too and reassigns afterwards.

  ``archived_at`` is the literal ``NULL`` and ``version`` the literal ``1``:
  a new contact is active at version one and no caller could legitimately ask
  for anything else. The schema carries no DEFAULT clauses (§2.3 rule 1), so
  both are written here.

  Nothing is returned (**A3**): the id is the caller's, and the caller already
  knows every value it bound.
  """
  await conn.execute(
    _INSERT_CONTACT_SQL,
    {
      "id": str(contact_id),
      "owner_id": str(scope.actor_id),
      "full_name": fields.full_name,
      "full_name_lower": fields.full_name_lower,
      "company": fields.company,
      "company_lower": fields.company_lower,
      "email": fields.email,
      "email_lower": fields.email_lower,
      "phone": fields.phone,
      "kind": fields.kind,
      "now": now,
    },
  )


async def update_contact(
  conn: PoolConnection,
  scope: Scope,
  *,
  contact_id: UUID,
  expected_version: int,
  fields: ContactFields,
  now: datetime,
) -> ContactRow | None:
  """Edit the five writable fields of one active contact.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  scope : Scope
    The caller's authorization scope, inlined into the statement.
  contact_id : UUID
    Which contact.
  expected_version : int
    The version the submitted form carried.
  fields : ContactFields
    The new values and their normalized companions.
  now : datetime
    The caller's instant, written to ``updated_at``.

  Returns
  -------
  ContactRow | None
    The row as the database now holds it, or ``None`` when **no row matched**
    — foreign, missing, stale, or archived, four situations conflated on
    purpose. The caller re-reads with :func:`get_contact` and decides which
    404 or which 409 context that was; this function never chooses a status.

  Notes
  -----
  The ``SET`` list is fixed literal text and ``version = version + 1`` rides
  the same statement (§4.1). ``archived_at IS NULL`` is belt-and-braces for
  ``ACC-018``: editing an archived own contact matches zero rows, and the
  service's re-read is what turns that into the archived 409 context rather
  than the stale one.

  The row is read back with the ordinary primary-key ``SELECT`` inside the
  same transaction rather than with a ``RETURNING`` clause: §9.2 records
  ``RETURNING`` as portable and permitted while noting that no statement in
  this contract uses it, and keeping the tree uniform is what makes the R1DB
  portability claim one claim instead of two.
  """
  cursor = await conn.execute(
    _UPDATE_CONTACT_SQL.format(scope=_write_scope(scope)),
    {
      "contact_id": str(contact_id),
      "version": expected_version,
      "actor_id": str(scope.actor_id),
      "full_name": fields.full_name,
      "full_name_lower": fields.full_name_lower,
      "company": fields.company,
      "company_lower": fields.company_lower,
      "email": fields.email,
      "email_lower": fields.email_lower,
      "phone": fields.phone,
      "kind": fields.kind,
      "now": now,
    },
  )
  if cursor.rowcount != 1:
    return None
  return await get_contact(conn, scope, contact_id=contact_id)


async def archive_contact(
  conn: PoolConnection,
  scope: Scope,
  *,
  contact_id: UUID,
  expected_version: int,
  archived_at: datetime,
  now: datetime,
) -> ContactRow | None:
  """Archive one active contact. Nothing is deleted.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  scope : Scope
    The caller's authorization scope, inlined into the statement.
  contact_id : UUID
    Which contact.
  expected_version : int
    The version the submitted form carried.
  archived_at : datetime
    The business fact the UI renders.
  now : datetime
    The caller's instant, written to ``updated_at``.

  Returns
  -------
  ContactRow | None
    The archived row, or ``None`` when no row matched — including the case of
    a contact that is **already** archived (``ACC-023``), which the service's
    re-read separates from a stale version.

  Notes
  -----
  ``archived_at`` and ``now`` are two parameters although every caller passes
  the same instant: one is the business fact, the other is ``updated_at``. A
  single parameter would make a future "archive with a back-dated instant"
  silently rewrite ``updated_at``.

  This is an ``UPDATE`` and could not be a ``DELETE`` even by mistake: the
  runtime role holds no ``DELETE`` privilege on ``contacts`` at all (``S7``,
  migration ``0003`` step 05), so the absence of the grant is the control.
  """
  cursor = await conn.execute(
    _ARCHIVE_CONTACT_SQL.format(scope=_write_scope(scope)),
    {
      "contact_id": str(contact_id),
      "version": expected_version,
      "actor_id": str(scope.actor_id),
      "archived_at": archived_at,
      "now": now,
    },
  )
  if cursor.rowcount != 1:
    return None
  return await get_contact(conn, scope, contact_id=contact_id)


async def restore_contact(
  conn: PoolConnection,
  scope: Scope,
  *,
  contact_id: UUID,
  expected_version: int,
  now: datetime,
) -> ContactRow | None:
  """Restore one archived contact.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  scope : Scope
    The caller's authorization scope, inlined into the statement.
  contact_id : UUID
    Which contact.
  expected_version : int
    The version the submitted form carried.
  now : datetime
    The caller's instant, written to ``updated_at``.

  Returns
  -------
  ContactRow | None
    The restored row, or ``None`` when no row matched — including restoring a
    contact that is already active (``ACC-028``).

  Notes
  -----
  A separate function from :func:`archive_contact` rather than one with a
  nullable ``archived_at``: the two ``SET`` lists differ and the two guards
  are opposites (``IS NULL`` against ``IS NOT NULL``). Two literal statements
  chosen in Python is the shipped precedent (``revoke_sessions``,
  ``promote_session``).
  """
  cursor = await conn.execute(
    _RESTORE_CONTACT_SQL.format(scope=_write_scope(scope)),
    {
      "contact_id": str(contact_id),
      "version": expected_version,
      "actor_id": str(scope.actor_id),
      "now": now,
    },
  )
  if cursor.rowcount != 1:
    return None
  return await get_contact(conn, scope, contact_id=contact_id)


async def reassign_contact(
  conn: PoolConnection,
  scope: Scope,
  *,
  contact_id: UUID,
  expected_version: int,
  new_owner_id: UUID,
  now: datetime,
) -> ContactRow | None:
  """Move one active contact to another owner — **admin only**.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction, the same
    one that has already checked the target with ``is_active_user``.
  scope : Scope
    The caller's authorization scope. It must be an admin one.
  contact_id : UUID
    Which contact.
  expected_version : int
    The version the submitted form carried (``R25``).
  new_owner_id : UUID
    The target owner, already confirmed active **inside this transaction**.
  now : datetime
    The caller's instant, written to ``updated_at``.

  Returns
  -------
  ContactRow | None
    The reassigned row, or ``None`` when no row matched — missing, stale, or
    archived (``R25``: restore first).

  Raises
  ------
  ValueError
    If ``scope`` is not an admin scope.

  Notes
  -----
  The ``ValueError`` is **not** the authorization decision — ``ACC-033``'s 403
  is taken at pipeline step 3, before the transaction opens. It is a
  precondition on an admin-only statement whose scope fragment is *empty*: an
  agent ``Scope`` reaching here would be a programming error that the empty
  fragment could not catch, and a 500 is the right answer to that, never a
  request-shaped one.

  Exactly **one row** changes. Children follow by join, because neither
  ``deals`` nor ``activities`` carries an owner column (§3.10, §3.11), which
  is what ``SQL-023`` asserts and why no reader can ever observe children
  under one owner and their parent under another.

  The target's validity is **not** folded into this statement as an ``EXISTS``
  subquery: that would collapse ``ACC-032``'s 400 into an indistinguishable
  zero-row stale/404. It is a separate read composed by the service inside
  this same transaction, so a concurrent ``disable-user`` becomes a ``40001``
  and the retry refuses.
  """
  if not scope.is_admin:
    raise ValueError("reassign_contact requires an admin scope")
  cursor = await conn.execute(
    _REASSIGN_CONTACT_SQL,
    {
      "contact_id": str(contact_id),
      "version": expected_version,
      "new_owner_id": str(new_owner_id),
      "now": now,
    },
  )
  if cursor.rowcount != 1:
    return None
  return await get_contact(conn, scope, contact_id=contact_id)
