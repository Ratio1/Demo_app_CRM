"""Contacts: authorization, version, receipt and audit, inside one transaction.

Authority: ``contracts/slice-b.md`` §2(a) (this surface and its six outcome
types), §1(b)/§1(c) (the repository signatures and the statements behind
them), §1(d) (the seven steps of a Slice B mutation and the transaction
map), ``ACCESS_MATRIX.md`` §1.1 (the check order), §3.1/§3.2 (every cell),
§5.1-§5.5 (the field, sort and filter allowlists and the token map),
``UX_FLOWS.md`` §6.7 (every validation string).

This module holds **no SQL and no URL**. It calls the repositories of
``app/db/repositories/contacts.py``, decides which of six outcomes a
submission has, and returns a view model; ``app/routes/contacts.py`` turns
that into a status, a ``Location`` and a template. Four rules make the
authorization boundary a property of the code rather than of a review:

*The scope is the only filter.* Every read and every write goes through a
repository function that takes a mandatory :class:`~app.security.principal.Scope`
and inlines the ownership predicate in SQL (**PIN 2**, ``ARC-001``). There
is no Python post-filter anywhere below, because a post-filter still leaks
existence through a total.

*404 is raised, not returned.* :class:`app.security.failures.ContactNotFound`
unwinds the transaction and reaches one handler, so the six contact
surfaces cannot drift apart and a foreign object stays byte-identical to a
missing one (**PIN 8**).

*Validation runs before the transaction opens.* Field errors are
:class:`Invalid`; an unknown or repeated **body field** never reaches this
module at all — the route rejects it as a crafted request (§2(a) decision
3), because the two 400s are two different screens.

*Nothing here re-derives state from what was submitted.* Every mutation
re-reads the row it changed, inside the same transaction, so the 303
target, the ``?notice=`` code and the 409 recovery view all describe the
record as the database now holds it.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, cast

import psycopg

from app.db.repositories import contacts as contacts_repo
from app.db.repositories import users as users_repo
from app.db.retry import run_read_committed, run_serializable
from app.security.audit import (
  ACTION_CONTACT_ARCHIVED,
  ACTION_CONTACT_CREATED,
  ACTION_CONTACT_REASSIGNED,
  ACTION_CONTACT_RESTORED,
  ACTION_CONTACT_UPDATED,
  OBJECT_CONTACT,
  OUTCOME_SUCCESS,
  record,
)
from app.security.failures import ContactNotFound
from app.security.idempotency import (
  NOTICE_FOR_STATUS,
  commit_receipt,
  decide,
  mint_key,
  payload_sha256,
  replay_after_conflict,
)

if TYPE_CHECKING:
  from collections.abc import Mapping, Sequence
  from datetime import datetime
  from uuid import UUID

  from app.db.pool import Pool, PoolConnection
  from app.db.repositories.contacts import (
    ContactKind,
    ContactPage,
    ContactRow,
    SortDir,
    SortKey,
    StatusFilter,
  )
  from app.db.repositories.receipts import Operation, ReceiptRow
  from app.db.repositories.users import UserOptionRow
  from app.security.clock import Clock
  from app.security.principal import Scope

__all__ = [
  "CONTACT_FIELDS",
  "DEFAULT_PER_PAGE",
  "MAX_PER_PAGE",
  "Applied",
  "AssignableUser",
  "Blocked",
  "ContactListView",
  "ContactRowView",
  "ContactView",
  "Duplicate",
  "Invalid",
  "RestoreForm",
  "Stale",
  "archive_contact",
  "build_contact_query",
  "create_contact",
  "get_for_detail",
  "list_assignable_users",
  "list_contacts",
  "reassign_contact",
  "restore_contact",
  "update_contact",
]

#: Re-exported from the repository so ``app/routes/**`` can read the two
#: page-size constants without importing ``app.db.repositories`` itself,
#: which ``ARC-008`` forbids. One definition, in the Data lane's module.
DEFAULT_PER_PAGE: Final[int] = contacts_repo.DEFAULT_PER_PAGE
MAX_PER_PAGE: Final[int] = contacts_repo.MAX_PER_PAGE

#: The five writable fields of ``ACCESS_MATRIX.md`` §5.1, in the order the
#: digest and the form both use. **The tuple is the allowlist**: unknown or
#: non-writable is a 400, never a silent ignore.
CONTACT_FIELDS: Final[tuple[str, ...]] = ("name", "company", "email", "phone", "kind")

#: ``UX_FLOWS.md`` §6.7 and §6.2 — the resolved strings, named for their
#: copy ids. Resolved here rather than passed as ids, which is the shipped
#: Slice A shape (``app/routes/auth.py``'s ``CP_01_LOGIN_FAILED``).
CP_60_NAME_REQUIRED: Final = "Enter a name."
CP_61_TOO_LONG_160: Final = "Use 160 characters or fewer."
CP_62_EMAIL_REQUIRED: Final = "Enter a work email address."
CP_63_EMAIL_MALFORMED: Final = "Enter an email address such as name@example.test."
CP_64_EMAIL_TOO_LONG: Final = "Use 254 characters or fewer."
CP_65_PHONE_TOO_LONG: Final = "Use 32 characters or fewer."
CP_66_KIND_REQUIRED: Final = "Choose lead or customer."
CP_25_BAD_TARGET: Final = "That person cannot own contacts. Choose someone else."

#: ``ck_contacts_*``'s bounds, mirrored in Python so the database CHECK is
#: the second line of defence and never the first (``ACC-210``'s rule,
#: applied to this object).
NAME_MAX: Final = 160
COMPANY_MAX: Final = 160
EMAIL_MIN: Final = 3
EMAIL_MAX: Final = 254
PHONE_MAX: Final = 32

#: ``ck_contacts_kind``'s two values, and the labels the row view renders.
KIND_LABELS: Final[dict[str, str]] = {"lead": "Lead", "customer": "Customer"}

OP_CREATE: Final[Operation] = "contact_create"
OP_UPDATE: Final[Operation] = "contact_update"
OP_ARCHIVE: Final[Operation] = "contact_archive"
OP_RESTORE: Final[Operation] = "contact_restore"
OP_REASSIGN: Final[Operation] = "contact_reassign"

#: ``unique_violation``. Classified by SQLSTATE string and never by a
#: psycopg exception class name (``DECISIONS.md`` §3): inside a Slice B
#: business transaction the only reachable UNIQUE constraints are two
#: primary keys on application-generated UUIDs and
#: ``uq_mutation_receipts_key``, so a ``23505`` here *is* the receipt key
#: and needs no constraint-name inspection (§1(d)).
_UNIQUE_VIOLATION: Final = "23505"

_KIND_VALUES: Final[frozenset[str]] = frozenset(KIND_LABELS)


class _ConcurrentStale(Exception):
  """The guarded ``UPDATE`` matched no row although the re-read admitted it.

  Raised from inside the transaction body so the transaction **rolls
  back**: the receipt was already written at §1(d) step 3, and committing
  it beside a business write that did not happen would make a later replay
  report a success that never occurred. The caller re-reads in a fresh
  transaction and answers 409 ``stale`` — §1(d) step 4's belt and braces,
  with nothing left behind.
  """


@dataclass(frozen=True, slots=True)
class ContactView:
  """One contact as a screen renders it (``CONTRACTS.md`` §8.2's ``contact``).

  Attributes
  ----------
  id : UUID
    The record's id.
  owner_id : UUID
    The current owner. **Never rendered as part of ``contact``** — the
    route puts it only in ``reassign.current_owner_id``, which §8.2 freezes
    — and present here because that one key has no other source.
  full_name, company, email, phone : str
    The stored display values.
  kind : str
    ``lead`` or ``customer``.
  kind_label : str
    The rendered label for ``kind``.
  owner_name : str
    ``users.display_name`` of the owner (§8 rule 4; amendment **A-8**).
  is_own : bool
    Whether the viewer owns it, for ``CP-32``'s owner line.
  is_archived : bool
    Whether ``archived_at`` is set.
  archived_at : datetime | None
    When it was archived.
  version : int
    The concurrency token every mutation form carries.
  created_at, updated_at : datetime
    Record timestamps.
  """

  id: UUID
  owner_id: UUID
  full_name: str
  company: str
  email: str
  phone: str
  kind: str
  kind_label: str
  owner_name: str
  is_own: bool
  is_archived: bool
  archived_at: datetime | None
  version: int
  created_at: datetime
  updated_at: datetime


@dataclass(frozen=True, slots=True)
class ContactRowView:
  """One row of a contact list (``CONTRACTS.md`` §8.3's ``contact_row``).

  The ``url`` key of that shape is added by the route: this module holds no
  URL.
  """

  id: UUID
  full_name: str
  company: str
  email: str
  phone: str
  kind: str
  kind_label: str
  owner_name: str
  is_own: bool
  is_archived: bool
  updated_at: datetime


@dataclass(frozen=True, slots=True)
class ContactListView:
  """The non-URL half of ``CONTRACTS.md`` §8.3's ``results``.

  Attributes
  ----------
  items : tuple[ContactRowView, ...]
    The page's rows, already scoped.
  total : int
    The scoped total — the **identical** ``WHERE`` as ``items`` (§1(c)), so
    a foreign row can never change a total or a page count (``ACC-102``).
  page, per_page, pages : int
    The pagination position. ``pages`` is at least one, so an empty result
    still reads "Page 1 of 1".
  range_start, range_end : int
    1-based inclusive bounds of this page, both ``0`` when it is empty.
  has_prev, has_next : bool
    Whether the two paging controls are live; the route turns ``False``
    into a ``None`` URL, which is **R24**'s instruction to render the inert
    ``<span>``.
  result_state : {"ok", "empty", "no_results"}
    ``UX_FLOWS.md`` §3.22, computed server-side so the two never collapse.
  """

  items: tuple[ContactRowView, ...]
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
class AssignableUser:
  """One option of the admin reassign ``<select>`` (``ACC-032``)."""

  id: UUID
  display_name: str


@dataclass(frozen=True, slots=True)
class RestoreForm:
  """The frozen ``{idempotency_key, version}`` of a restore form."""

  idempotency_key: UUID
  version: int


@dataclass(frozen=True, slots=True)
class Applied:
  """The mutation happened (or had already happened): ``303`` + ``?notice=``.

  Attributes
  ----------
  contact_id : UUID
    The record the ``Location`` names.
  notice : str
    The ``?notice=`` code, from :data:`app.security.idempotency.NOTICE_FOR_STATUS`.
  replayed : bool
    ``True`` when this answer came from a stored receipt rather than from a
    write. The user sees the same page either way — nothing went wrong —
    and the flag exists so a test can tell the two apart (``SQL-011``).
  """

  contact_id: UUID
  notice: str
  replayed: bool


@dataclass(frozen=True, slots=True)
class Invalid:
  """Field-level validation failed: ``400``, re-render the originating form."""

  errors: dict[str, list[str]]


@dataclass(frozen=True, slots=True)
class Stale:
  """``409`` ``context="stale"`` — the record moved under the editor (**PIN 3**).

  Attributes
  ----------
  contact_id : UUID
    The record.
  current : ContactView
    The row as it now stands, re-read under the scope predicate.
  submitted : Mapping[str, str]
    The **normalized** submitted values, so trailing whitespace is never
    reported as a change. Empty for archive and restore, whose form has no
    data field (§5.1).
  version : int
    The **current** version, re-issued in ``keep_form``.
  idempotency_key : UUID
    A **fresh** key. The submitted one is never re-offered: re-posting it
    would meet the receipt and answer 409 ``duplicate``.
  """

  contact_id: UUID
  current: ContactView
  submitted: Mapping[str, str]
  version: int
  idempotency_key: UUID


@dataclass(frozen=True, slots=True)
class Blocked:
  """``409`` ``context="archived_parent"`` — the archive state refuses the write.

  Attributes
  ----------
  contact_id : UUID
    The record.
  contact_name : str
    Its ``full_name``, for the heading.
  body : {"cp_13", "cp_23"}
    ``cp_13`` — "restore it first" (``ACC-018``, and a reassign under
    **R25**). ``cp_23`` — "that has already been done" (``ACC-023``,
    ``ACC-028``).
  state : {"archived", "active"}
    ``CP-23``'s substitution.
  restore_form : RestoreForm | None
    The real restore ``POST``'s hidden fields, or ``None`` when the contact
    is already active and there is nothing to restore.
  """

  contact_id: UUID
  contact_name: str
  body: Literal["cp_13", "cp_23"]
  state: Literal["archived", "active"]
  restore_form: RestoreForm | None


@dataclass(frozen=True, slots=True)
class Duplicate:
  """``409`` ``context="duplicate"`` — same key, different payload (``SQL-028``)."""

  contact_id: UUID


@dataclass(frozen=True, slots=True)
class _Normalized:
  """A submission that passed validation: what to write, and what was typed."""

  fields: contacts_repo.ContactFields
  values: dict[str, str]


def _email_shaped(value: str) -> bool:
  """Return whether ``value`` satisfies ``ck_contacts_email``'s ``LIKE '%_@_%'``.

  Parameters
  ----------
  value : str
    The submitted address, already stripped.

  Returns
  -------
  bool
    ``True`` when an ``@`` occurs with at least one character on each side
    — which is exactly what the CHECK's mask means, character for
    character. Deliberately not a syntax validator: the schema's rule is
    the one the row must satisfy, and a stricter Python rule would refuse
    addresses the database would accept.
  """
  return "@" in value[1:-1]


def _validate(submitted: Mapping[str, str]) -> Invalid | _Normalized:
  """Normalize and check the five writable fields (``UX_FLOWS.md`` §6.7).

  Parameters
  ----------
  submitted : Mapping[str, str]
    The five wire names of :data:`CONTACT_FIELDS`, each present — the route
    supplies ``""`` for a field the body omitted, because a radio group
    with nothing selected sends no field at all and that is ``CP-66``.

  Returns
  -------
  Invalid | _Normalized
    ``Invalid`` carries one list of strings per failing field, keyed by the
    wire name so the error summary can link to the control (**R28**).

  Notes
  -----
  Both halves of every ``_lower`` pair are computed here and both are
  length-checked. Lowercasing can lengthen a string — ``'İ'.lower()`` is
  two characters — so a name that passes at 160 characters can produce a
  ``full_name_lower`` that violates ``ck_contacts_name_lower``. Checking
  the derived value is what keeps that a field error instead of a 500.
  """
  errors: dict[str, list[str]] = {}
  name = submitted.get("name", "").strip()
  company = submitted.get("company", "").strip()
  email = submitted.get("email", "").strip()
  phone = submitted.get("phone", "").strip()
  kind = submitted.get("kind", "").strip()

  name_lower = name.lower()
  company_lower = company.lower()
  email_lower = email.lower()

  if not name:
    errors["name"] = [CP_60_NAME_REQUIRED]
  elif len(name) > NAME_MAX or len(name_lower) > NAME_MAX:
    errors["name"] = [CP_61_TOO_LONG_160]
  if len(company) > COMPANY_MAX or len(company_lower) > COMPANY_MAX:
    errors["company"] = [CP_61_TOO_LONG_160]
  if not email:
    errors["email"] = [CP_62_EMAIL_REQUIRED]
  elif len(email) > EMAIL_MAX or len(email_lower) > EMAIL_MAX:
    errors["email"] = [CP_64_EMAIL_TOO_LONG]
  elif len(email) < EMAIL_MIN or not _email_shaped(email):
    errors["email"] = [CP_63_EMAIL_MALFORMED]
  if len(phone) > PHONE_MAX:
    errors["phone"] = [CP_65_PHONE_TOO_LONG]
  if kind not in _KIND_VALUES:
    errors["kind"] = [CP_66_KIND_REQUIRED]

  if errors:
    return Invalid(errors=errors)
  return _Normalized(
    fields=contacts_repo.ContactFields(
      full_name=name,
      full_name_lower=name_lower,
      company=company,
      company_lower=company_lower,
      email=email,
      email_lower=email_lower,
      phone=phone,
      kind=cast("ContactKind", kind),
    ),
    values={"name": name, "company": company, "email": email, "phone": phone, "kind": kind},
  )


def _digest_fields(values: Mapping[str, str]) -> Sequence[tuple[str, str]]:
  """Return the declared fields as digest pairs, in :data:`CONTACT_FIELDS` order."""
  return [(name, values[name]) for name in CONTACT_FIELDS]


def _view(row: ContactRow, scope: Scope) -> ContactView:
  """Build the screen's contact from a repository row and the viewer's scope."""
  return ContactView(
    id=row.id,
    owner_id=row.owner_id,
    full_name=row.full_name,
    company=row.company,
    email=row.email,
    phone=row.phone,
    kind=row.kind,
    kind_label=KIND_LABELS.get(row.kind, row.kind),
    owner_name=row.owner_name,
    is_own=row.owner_id == scope.actor_id,
    is_archived=row.archived_at is not None,
    archived_at=row.archived_at,
    version=row.version,
    created_at=row.created_at,
    updated_at=row.updated_at,
  )


def _row_view(row: ContactRow, scope: Scope) -> ContactRowView:
  """Build one list row from a repository row and the viewer's scope."""
  return ContactRowView(
    id=row.id,
    full_name=row.full_name,
    company=row.company,
    email=row.email,
    phone=row.phone,
    kind=row.kind,
    kind_label=KIND_LABELS.get(row.kind, row.kind),
    owner_name=row.owner_name,
    is_own=row.owner_id == scope.actor_id,
    is_archived=row.archived_at is not None,
    updated_at=row.updated_at,
  )


def _applied(receipt: ReceiptRow, *, replayed: bool) -> Applied:
  """Rebuild the original answer from a stored receipt.

  Parameters
  ----------
  receipt : ReceiptRow
    The stored outcome: a status, an object type and an object id.
  replayed : bool
    Whether this is a replay.

  Returns
  -------
  Applied
    The ``Location`` is rebuilt by the route from ``result_object_id`` and
    the ``?notice=`` code this maps ``result_status`` to — no URL was ever
    stored.
  """
  return Applied(
    contact_id=receipt.result_object_id,
    notice=NOTICE_FOR_STATUS[receipt.result_status],
    replayed=replayed,
  )


async def _resolve_conflict(
  pool: Pool,
  error: psycopg.Error,
  *,
  user_id: UUID,
  operation: Operation,
  key: UUID,
  digest: str,
) -> Applied | Duplicate:
  """Answer a ``23505`` on the receipt insert by reading the winner's receipt.

  Parameters
  ----------
  pool : Pool
    The process pool; the conflicting transaction has already unwound and
    released its connection.
  error : psycopg.Error
    The original failure, re-raised if the receipt cannot be found.
  user_id, operation, key, digest
    The same four values the failed insert carried.

  Returns
  -------
  Applied | Duplicate

  Raises
  ------
  psycopg.Error
    When the re-read finds no receipt at all. A receipt that provoked a
    ``23505`` a moment ago cannot legitimately be absent, and running the
    mutation a second time is the one thing this whole module exists to
    prevent — so the honest answer is the sanitized 500 the original error
    produces, with its correlation id.
  """
  decision = await replay_after_conflict(
    pool, user_id=user_id, operation=operation, key=key, digest=digest
  )
  if decision.receipt is None:
    raise error
  if decision.kind == "duplicate":
    return Duplicate(contact_id=decision.receipt.result_object_id)
  return _applied(decision.receipt, replayed=True)


async def _stale_after_race(
  pool: Pool,
  scope: Scope,
  *,
  contact_id: UUID,
  submitted: Mapping[str, str],
) -> Stale:
  """Re-read a contact in a fresh transaction to build §1(d) step 4's 409.

  Raises
  ------
  ContactNotFound
    If the row is gone. Nothing in this application deletes a contact, so
    this is unreachable; answering 404 rather than inventing a recovery
    view for a record that does not exist is the honest degradation.
  """

  async def _read(conn: PoolConnection) -> ContactRow | None:
    return await contacts_repo.get_contact(conn, scope, contact_id=contact_id)

  row = await run_read_committed(pool, _read, op="contact-stale-reread")
  if row is None:
    raise ContactNotFound(contact_id)
  current = _view(row, scope)
  return Stale(
    contact_id=contact_id,
    current=current,
    submitted=submitted,
    version=current.version,
    idempotency_key=mint_key(),
  )


def _blocked(row: ContactRow, *, body: Literal["cp_13", "cp_23"]) -> Blocked:
  """Build the 409 ``archived_parent`` payload for a row in the wrong state."""
  archived = row.archived_at is not None
  return Blocked(
    contact_id=row.id,
    contact_name=row.full_name,
    body=body,
    state="archived" if archived else "active",
    restore_form=RestoreForm(idempotency_key=mint_key(), version=row.version) if archived else None,
  )


def build_contact_query(
  *,
  term: str | None,
  kind: str | None,
  status: str,
  sort: str,
  direction: str,
  page: int,
  per_page: int,
) -> contacts_repo.ContactQuery:
  """Turn already-validated request values into one repository query.

  Parameters
  ----------
  term : str | None
    The raw ``?q=`` value, or ``None``. Normalized and escaped here, which
    is the one place it happens (§1(c), ``ACCESS_MATRIX.md`` §5.5).
  kind : str | None
    ``lead``, ``customer`` or ``None``; the route has already rejected
    anything else with a 400.
  status : str
    ``active``, ``archived`` or ``all``. ``active`` is the default, so
    **PIN 4**'s "archived contacts hidden by default" is the absence of an
    input rather than a branch a caller can forget.
  sort : str
    One of ``ACCESS_MATRIX.md`` §5.2's five keys.
  direction : str
    ``asc`` or ``desc``.
  page : int
    A positive integer.
  per_page : int
    A positive integer; clamped to :data:`MAX_PER_PAGE` here (``ACC-112``).

  Returns
  -------
  ContactQuery
    Nothing in it is a raw request string: the term is escaped and
    prefix-bounded, and the four enumerated values only *look up* a
    code-authored SQL fragment inside the repository.

  Notes
  -----
  The escape order is binding and is ``!``, then ``%``, then ``_``: escaping
  ``%`` before ``!`` would double-escape the escape character. A **single
  trailing** ``%`` and **no leading one** — prefix-only, which ``ACC-103``
  asserts explicitly with a fixture whose term occurs only mid-string.
  The term is lowered in Python, never by a SQL function, because the
  columns it is compared against are the stored ``_lower`` ones.
  """
  normalized: str | None = None
  if term is not None:
    cleaned = term.strip().lower()
    if cleaned:
      escaped = cleaned.replace("!", "!!").replace("%", "!%").replace("_", "!_")
      normalized = f"{escaped}%"
  return contacts_repo.ContactQuery(
    term=normalized,
    kind=None if kind is None else cast("ContactKind", kind),
    status=cast("StatusFilter", status),
    sort=cast("SortKey", sort),
    direction=cast("SortDir", direction),
    page=page,
    per_page=min(per_page, MAX_PER_PAGE),
  )


async def list_contacts(
  pool: Pool, scope: Scope, *, query: contacts_repo.ContactQuery
) -> ContactListView:
  """Read one page of contacts and its scoped total.

  Parameters
  ----------
  pool : Pool
    The process pool.
  scope : Scope
    The viewer's scope; the repository inlines it in **both** statements.
  query : ContactQuery
    Built by :func:`build_contact_query`.

  Returns
  -------
  ContactListView

  Notes
  -----
  One short ``READ COMMITTED`` transaction (§1(d) row 6), never a
  ``SERIALIZABLE`` one: a list page taking predicate locks would make every
  concurrent contact edit a ``40001`` candidate for no benefit.

  ``result_state`` is decided without a third statement, which the
  transaction map does not admit: with no filter active a scoped total of
  zero **is** "no rows in scope", so ``empty`` is exact for the default
  view; with any filter active the honest answer is ``no_results``. The one
  edge this leaves is a scope whose only rows are archived, which reads
  ``empty`` under the default ``status=active`` filter — recorded rather
  than papered over.
  """

  async def _read(conn: PoolConnection) -> ContactPage:
    return await contacts_repo.list_contacts(conn, scope, query=query)

  page = await run_read_committed(pool, _read, op="contact-list")
  rows = tuple(_row_view(row, scope) for row in page.rows)
  total = page.total
  # The page and the page size the repository actually applied, after its
  # own clamps — never the requested ones, so the rendered range can never
  # describe a window the statement did not read.
  per_page = page.per_page
  pages = max(1, math.ceil(total / per_page))
  offset = (page.page - 1) * per_page
  filtered = query.term is not None or query.kind is not None or query.status != "active"
  if rows:
    state: Literal["ok", "empty", "no_results"] = "ok"
  elif total > 0 or filtered:
    state = "no_results"
  else:
    state = "empty"
  return ContactListView(
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


async def get_for_detail(pool: Pool, scope: Scope, *, contact_id: UUID) -> ContactView:
  """Read one contact for its workspace or its edit form.

  Raises
  ------
  ContactNotFound
    For a foreign contact and for a missing one alike — one statement, one
    code path, one body (**PIN 8**, ``ACC-002``/``ACC-015``).

  Notes
  -----
  There is **no archive clause**: an archived contact stays readable to its
  owner (``ACC-006``), and the screen renders the archived banner and the
  restore action from ``is_archived``.
  """

  async def _read(conn: PoolConnection) -> ContactRow | None:
    return await contacts_repo.get_contact(conn, scope, contact_id=contact_id)

  row = await run_read_committed(pool, _read, op="contact-detail")
  if row is None:
    raise ContactNotFound(contact_id)
  return _view(row, scope)


async def list_assignable_users(pool: Pool) -> tuple[AssignableUser, ...]:
  """Return the active users an admin may reassign a contact to (``ACC-032``).

  Parameters
  ----------
  pool : Pool
    The process pool.

  Returns
  -------
  tuple[AssignableUser, ...]
    ``(id, display_name)`` ordered by display name — the only source
    ``CONTRACTS.md`` §8.2's frozen ``reassign.assignable_users`` has.

  Notes
  -----
  Takes no ``Scope``: ``users`` is an identity repository, and the option
  list is the same for every admin (§1(b) B2, amendment **A-10**). It is
  never an authorization input — the reassign target is re-validated
  **inside** the mutation's own transaction by
  :func:`app.db.repositories.users.is_active_user`, so a list that went
  stale while the page was open cannot widen anything.
  """

  async def _read(conn: PoolConnection) -> tuple[UserOptionRow, ...]:
    return await users_repo.list_active_users(conn)

  rows = await run_read_committed(pool, _read, op="assignable-users")
  return tuple(AssignableUser(id=row.id, display_name=row.display_name) for row in rows)


async def create_contact(
  pool: Pool,
  clock: Clock,
  scope: Scope,
  *,
  submitted: Mapping[str, str],
  key: UUID,
  correlation_id: str,
) -> Applied | Invalid | Duplicate:
  """Create one contact owned by the actor (``ACC-007``).

  Parameters
  ----------
  pool : Pool
    The process pool.
  clock : Clock
    The injected time source; every instant below comes from it.
  scope : Scope
    The actor's scope. **The owner is the scope**: ``insert_contact`` has no
    ``owner_id`` parameter, so ``ACC-012`` — an agent supplying one — is
    unreachable by construction rather than by allowlist.
  submitted : Mapping[str, str]
    The five writable fields.
  key : UUID
    The form's idempotency key, already parsed as canonical.
  correlation_id : str
    This request's id, written into the audit row.

  Returns
  -------
  Applied | Invalid | Duplicate

  Notes
  -----
  The new id and the instant are generated **before** the transaction, so
  every retry of the body writes the same id and the same timestamps —
  which is what makes the receipt's ``result_object_id`` stable across a
  ``40001`` retry.
  """
  validated = _validate(submitted)
  if isinstance(validated, Invalid):
    return validated
  fields = validated.fields
  digest = payload_sha256(
    operation=OP_CREATE, target_id=None, fields=_digest_fields(validated.values)
  )
  now = clock.now()
  contact_id = uuid.uuid4()

  async def _work(conn: PoolConnection) -> Applied | Duplicate:
    decision = await decide(
      conn, user_id=scope.actor_id, operation=OP_CREATE, key=key, digest=digest
    )
    if decision.receipt is not None:
      if decision.kind == "duplicate":
        return Duplicate(contact_id=decision.receipt.result_object_id)
      return _applied(decision.receipt, replayed=True)
    await commit_receipt(
      conn,
      user_id=scope.actor_id,
      operation=OP_CREATE,
      key=key,
      digest=digest,
      status="created",
      object_type="contact",
      object_id=contact_id,
      now=now,
    )
    await contacts_repo.insert_contact(conn, scope, contact_id=contact_id, fields=fields, now=now)
    await record(
      conn,
      actor_id=scope.actor_id,
      object_type=OBJECT_CONTACT,
      object_id=contact_id,
      action=ACTION_CONTACT_CREATED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return Applied(contact_id=contact_id, notice=NOTICE_FOR_STATUS["created"], replayed=False)

  try:
    return await run_serializable(pool, _work, op=OP_CREATE)
  except psycopg.Error as error:
    if error.sqlstate != _UNIQUE_VIOLATION:
      raise
    return await _resolve_conflict(
      pool, error, user_id=scope.actor_id, operation=OP_CREATE, key=key, digest=digest
    )


async def update_contact(
  pool: Pool,
  clock: Clock,
  scope: Scope,
  *,
  contact_id: UUID,
  expected_version: int,
  submitted: Mapping[str, str],
  key: UUID,
  correlation_id: str,
) -> Applied | Invalid | Stale | Blocked | Duplicate:
  """Edit one contact's five writable fields (``ACC-014``-``ACC-020``).

  Returns
  -------
  Applied | Invalid | Stale | Blocked | Duplicate

  Raises
  ------
  ContactNotFound
    Foreign or missing, decided by the scope predicate before the archive
    state is ever consulted — which is the ordering that keeps the 409 from
    becoming an existence oracle (``ACC-020``).
  """
  validated = _validate(submitted)
  if isinstance(validated, Invalid):
    return validated
  fields = validated.fields
  values = validated.values
  digest = payload_sha256(
    operation=OP_UPDATE,
    target_id=contact_id,
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
        return Duplicate(contact_id=decision.receipt.result_object_id)
      return _applied(decision.receipt, replayed=True)
    row = await contacts_repo.get_contact(conn, scope, contact_id=contact_id)
    if row is None:
      raise ContactNotFound(contact_id)
    if row.archived_at is not None:
      return _blocked(row, body="cp_13")
    if row.version != expected_version:
      return Stale(
        contact_id=contact_id,
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
      object_type="contact",
      object_id=contact_id,
      now=now,
    )
    updated = await contacts_repo.update_contact(
      conn,
      scope,
      contact_id=contact_id,
      expected_version=expected_version,
      fields=fields,
      now=now,
    )
    if updated is None:
      raise _ConcurrentStale
    await record(
      conn,
      actor_id=scope.actor_id,
      object_type=OBJECT_CONTACT,
      object_id=contact_id,
      action=ACTION_CONTACT_UPDATED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return Applied(contact_id=contact_id, notice=NOTICE_FOR_STATUS["updated"], replayed=False)

  try:
    return await run_serializable(pool, _work, op=OP_UPDATE)
  except _ConcurrentStale:
    return await _stale_after_race(pool, scope, contact_id=contact_id, submitted=values)
  except psycopg.Error as error:
    if error.sqlstate != _UNIQUE_VIOLATION:
      raise
    return await _resolve_conflict(
      pool, error, user_id=scope.actor_id, operation=OP_UPDATE, key=key, digest=digest
    )


async def archive_contact(
  pool: Pool,
  clock: Clock,
  scope: Scope,
  *,
  contact_id: UUID,
  expected_version: int,
  key: UUID,
  correlation_id: str,
) -> Applied | Stale | Blocked | Duplicate:
  """Archive one active contact (``ACC-021``-``ACC-024``).

  Notes
  -----
  Archive is not erasure: nothing is deleted, which is why the runtime role
  holds no ``DELETE`` on ``contacts`` at all (``S7``, §1(a) step 05).
  Archiving an already-archived contact is ``ACC-023``'s 409 with
  ``CP-23``, reachable only by a replayed form.
  """
  digest = payload_sha256(operation=OP_ARCHIVE, target_id=contact_id, version=expected_version)
  now = clock.now()

  async def _work(conn: PoolConnection) -> Applied | Stale | Blocked | Duplicate:
    decision = await decide(
      conn, user_id=scope.actor_id, operation=OP_ARCHIVE, key=key, digest=digest
    )
    if decision.receipt is not None:
      if decision.kind == "duplicate":
        return Duplicate(contact_id=decision.receipt.result_object_id)
      return _applied(decision.receipt, replayed=True)
    row = await contacts_repo.get_contact(conn, scope, contact_id=contact_id)
    if row is None:
      raise ContactNotFound(contact_id)
    if row.archived_at is not None:
      return _blocked(row, body="cp_23")
    if row.version != expected_version:
      return Stale(
        contact_id=contact_id,
        current=_view(row, scope),
        submitted={},
        version=row.version,
        idempotency_key=mint_key(),
      )
    await commit_receipt(
      conn,
      user_id=scope.actor_id,
      operation=OP_ARCHIVE,
      key=key,
      digest=digest,
      status="archived",
      object_type="contact",
      object_id=contact_id,
      now=now,
    )
    archived = await contacts_repo.archive_contact(
      conn,
      scope,
      contact_id=contact_id,
      expected_version=expected_version,
      archived_at=now,
      now=now,
    )
    if archived is None:
      raise _ConcurrentStale
    await record(
      conn,
      actor_id=scope.actor_id,
      object_type=OBJECT_CONTACT,
      object_id=contact_id,
      action=ACTION_CONTACT_ARCHIVED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return Applied(contact_id=contact_id, notice=NOTICE_FOR_STATUS["archived"], replayed=False)

  try:
    return await run_serializable(pool, _work, op=OP_ARCHIVE)
  except _ConcurrentStale:
    return await _stale_after_race(pool, scope, contact_id=contact_id, submitted={})
  except psycopg.Error as error:
    if error.sqlstate != _UNIQUE_VIOLATION:
      raise
    return await _resolve_conflict(
      pool, error, user_id=scope.actor_id, operation=OP_ARCHIVE, key=key, digest=digest
    )


async def restore_contact(
  pool: Pool,
  clock: Clock,
  scope: Scope,
  *,
  contact_id: UUID,
  expected_version: int,
  key: UUID,
  correlation_id: str,
) -> Applied | Stale | Blocked | Duplicate:
  """Restore one archived contact (``ACC-026``-``ACC-029``).

  Notes
  -----
  Restoring an already-active contact is ``ACC-028``'s 409 with ``CP-23``
  and **no** restore form: there is nothing left to restore, so offering
  the button would be a control that does nothing.
  """
  digest = payload_sha256(operation=OP_RESTORE, target_id=contact_id, version=expected_version)
  now = clock.now()

  async def _work(conn: PoolConnection) -> Applied | Stale | Blocked | Duplicate:
    decision = await decide(
      conn, user_id=scope.actor_id, operation=OP_RESTORE, key=key, digest=digest
    )
    if decision.receipt is not None:
      if decision.kind == "duplicate":
        return Duplicate(contact_id=decision.receipt.result_object_id)
      return _applied(decision.receipt, replayed=True)
    row = await contacts_repo.get_contact(conn, scope, contact_id=contact_id)
    if row is None:
      raise ContactNotFound(contact_id)
    if row.archived_at is None:
      return _blocked(row, body="cp_23")
    if row.version != expected_version:
      return Stale(
        contact_id=contact_id,
        current=_view(row, scope),
        submitted={},
        version=row.version,
        idempotency_key=mint_key(),
      )
    await commit_receipt(
      conn,
      user_id=scope.actor_id,
      operation=OP_RESTORE,
      key=key,
      digest=digest,
      status="restored",
      object_type="contact",
      object_id=contact_id,
      now=now,
    )
    restored = await contacts_repo.restore_contact(
      conn, scope, contact_id=contact_id, expected_version=expected_version, now=now
    )
    if restored is None:
      raise _ConcurrentStale
    await record(
      conn,
      actor_id=scope.actor_id,
      object_type=OBJECT_CONTACT,
      object_id=contact_id,
      action=ACTION_CONTACT_RESTORED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return Applied(contact_id=contact_id, notice=NOTICE_FOR_STATUS["restored"], replayed=False)

  try:
    return await run_serializable(pool, _work, op=OP_RESTORE)
  except _ConcurrentStale:
    return await _stale_after_race(pool, scope, contact_id=contact_id, submitted={})
  except psycopg.Error as error:
    if error.sqlstate != _UNIQUE_VIOLATION:
      raise
    return await _resolve_conflict(
      pool, error, user_id=scope.actor_id, operation=OP_RESTORE, key=key, digest=digest
    )


async def reassign_contact(
  pool: Pool,
  clock: Clock,
  scope: Scope,
  *,
  contact_id: UUID,
  expected_version: int,
  new_owner_id: UUID,
  key: UUID,
  correlation_id: str,
) -> Applied | Invalid | Stale | Blocked | Duplicate:
  """Move one contact to another active owner — admin only (``ACC-031``).

  Parameters
  ----------
  new_owner_id : UUID
    The target, already parsed as canonical by the route.

  Returns
  -------
  Applied | Invalid | Stale | Blocked | Duplicate
    ``Invalid`` — one answer for a missing target and for a disabled one
    (``ACC-032``), so no admin learns which it was.

  Notes
  -----
  The role check is the route's, at order step 3, **before** this is
  reached: ``ACC-033``'s 403 is constant over objects and must not depend
  on resolving one.

  The target is validated **inside** this transaction, not before it: a
  concurrent ``disable-user`` writes the row this transaction read,
  PostgreSQL's SSI sees the read-write conflict and aborts one with
  ``40001``, and the retry re-reads and refuses. A check in an earlier
  transaction would be a TOCTOU window instead.

  Reassigning to the **current** owner is an ordinary success: it is
  idempotent by nature, and refusing it would need a comparison that tells
  the admin nothing. Exactly one row changes; children follow by join,
  because neither ``deals`` nor ``activities`` carries an owner column.
  """
  digest = payload_sha256(
    operation=OP_REASSIGN,
    target_id=contact_id,
    version=expected_version,
    fields=[("owner_id", str(new_owner_id))],
  )
  now = clock.now()

  async def _work(conn: PoolConnection) -> Applied | Invalid | Stale | Blocked | Duplicate:
    decision = await decide(
      conn, user_id=scope.actor_id, operation=OP_REASSIGN, key=key, digest=digest
    )
    if decision.receipt is not None:
      if decision.kind == "duplicate":
        return Duplicate(contact_id=decision.receipt.result_object_id)
      return _applied(decision.receipt, replayed=True)
    row = await contacts_repo.get_contact(conn, scope, contact_id=contact_id)
    if row is None:
      raise ContactNotFound(contact_id)
    if row.archived_at is not None:
      return _blocked(row, body="cp_13")
    if row.version != expected_version:
      return Stale(
        contact_id=contact_id,
        current=_view(row, scope),
        submitted={"owner_id": str(new_owner_id)},
        version=row.version,
        idempotency_key=mint_key(),
      )
    if not await users_repo.is_active_user(conn, user_id=new_owner_id):
      return Invalid(errors={"owner_id": [CP_25_BAD_TARGET]})
    await commit_receipt(
      conn,
      user_id=scope.actor_id,
      operation=OP_REASSIGN,
      key=key,
      digest=digest,
      status="reassigned",
      object_type="contact",
      object_id=contact_id,
      now=now,
    )
    reassigned = await contacts_repo.reassign_contact(
      conn,
      scope,
      contact_id=contact_id,
      expected_version=expected_version,
      new_owner_id=new_owner_id,
      now=now,
    )
    if reassigned is None:
      raise _ConcurrentStale
    await record(
      conn,
      actor_id=scope.actor_id,
      object_type=OBJECT_CONTACT,
      object_id=contact_id,
      action=ACTION_CONTACT_REASSIGNED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return Applied(contact_id=contact_id, notice=NOTICE_FOR_STATUS["reassigned"], replayed=False)

  try:
    return await run_serializable(pool, _work, op=OP_REASSIGN)
  except _ConcurrentStale:
    return await _stale_after_race(
      pool, scope, contact_id=contact_id, submitted={"owner_id": str(new_owner_id)}
    )
  except psycopg.Error as error:
    if error.sqlstate != _UNIQUE_VIOLATION:
      raise
    return await _resolve_conflict(
      pool, error, user_id=scope.actor_id, operation=OP_REASSIGN, key=key, digest=digest
    )
