"""The Slice B route table: contacts, their forms, and the four mutations.

Authority: ``contracts/slice-b.md`` §2(c) (the table itself — method, path,
name, CSRF, idempotency, template, context, success and error statuses),
§2(d) (the ``409`` renders), §2(e) (the fragment predicate and the focus
rule), §2(f) (every form's exact accepted field set), §1(d) (which
transaction each call opens), ``ACCESS_MATRIX.md`` §1.1 (the check order),
§1.2 (the status policy and the H-08 unknown-parameter rule), §4.5 (the
deny-audit triples), §5.1-§5.3 (the field allowlists), ``CONTRACTS.md`` §8
(every context key, frozen).

Each handler follows the one shape, in the one order: resolve the session,
read and check CSRF on an unsafe method, charge the budget, apply the
forced-reset gate, check the role where there is one, then do the work. A
refusal is **raised**, never rendered here — :mod:`app.routes.errors` owns
every status page — with one deliberate exception: the ``400`` of a
crafted request is returned from :func:`_reject_input`, because it also
writes ``ACCESS_MATRIX.md`` §4.5 row 6 and that row belongs beside the
decision that produced it.

Three rules are worth reading before changing anything here.

*Nothing on this page is authorization.* ``can_create``, ``can.edit``,
``can.reassign`` and the absence of a panel are **UI hiding**; every one
of them is re-decided server-side by the route's own guards and by the
scope predicate inside the statement. Hiding a control is never a
substitute (``ACCESS_MATRIX.md`` §1.4).

*An empty query value means the parameter was not supplied.* A
``<select>`` always submits something, so ``?kind=`` is the filter bar's
"any" option and not a value outside the enum; a **non-empty** value
outside an allowlist is the ``400`` of ``ACC-109``/``ACC-110``/``ACC-111``.
One rule for ``q``, ``kind``, ``status``, ``sort``, ``dir``, ``page`` and
``per_page`` alike.

*A fragment is decided by two headers, not one.* htmx 2.0.10 sends
``HX-Request: true`` on a Back-button history restore as well, and swaps
that response into the history element with ``innerHTML`` — so a bare
``HX-Request`` check would swap a fragment in as the whole document
(§2(e), measured in §2(j) probe 1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlencode

from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import Response

from app.logging import current_correlation_id
from app.routes.errors import CONTACTS_URL, bad_request, conflict, redirect
from app.routes.rendering import View, base_context, csrf_token_for_request, notice_for, render
from app.security.audit import (
  ACTION_INPUT_REJECTED,
  ACTION_ROLE_DENIED,
  OBJECT_CONTACT,
  record_denial,
)
from app.security.authz import (
  charge_account_budget,
  form_content_type_ok,
  read_form,
  require_admin,
  require_csrf,
  require_session,
)
from app.security.context import context_of
from app.security.failures import ContactNotFound, ForcedResetRequired, RoleRequired
from app.security.idempotency import mint_key, parse_canonical
from app.security.principal import scope_of
from app.services.contacts import (
  CP_25_BAD_TARGET,
  DEFAULT_PER_PAGE,
  KIND_LABELS,
  MAX_PER_PAGE,
  Applied,
  Blocked,
  ContactListView,
  ContactView,
  Duplicate,
  Invalid,
  Stale,
  archive_contact,
  build_contact_query,
  create_contact,
  get_for_detail,
  list_assignable_users,
  list_contacts,
  reassign_contact,
  restore_contact,
  update_contact,
)

if TYPE_CHECKING:
  from uuid import UUID

  from starlette.datastructures import FormData

  from app.security.principal import Principal

__all__ = ["router"]

router = APIRouter()

#: ``ACCESS_MATRIX.md`` §5.2. Every other parameter **name** is ignored,
#: dropped before any other check (H-08); a repeated one of these is a
#: ``400`` (``SEC-076``).
_LIST_KEYS: Final[tuple[str, ...]] = ("q", "status", "kind", "sort", "dir", "page", "per_page")

_SORT_KEYS: Final[frozenset[str]] = frozenset(
  {"name", "company", "email", "created_at", "updated_at"}
)
_DIRECTIONS: Final[frozenset[str]] = frozenset({"asc", "desc"})
_STATUSES: Final[frozenset[str]] = frozenset({"active", "archived", "all"})

_DEFAULT_SORT: Final = "updated_at"
_DEFAULT_DIRECTION: Final = "desc"
_DEFAULT_STATUS: Final = "active"

#: §2(c). 254 is ``ck_contacts_email``'s upper bound and therefore the
#: longest **searched** column of the three, so a longer prefix can match
#: nothing that could ever be stored. 160 — the ``full_name``/``company``
#: bound — would wrongly refuse a legitimate long-email prefix.
_MAX_TERM_LENGTH: Final = 254

_DIGITS: Final = re.compile(r"\A[0-9]+\Z")

#: §2(f). ``csrf_token`` and ``idempotency_key`` are on **every** form, are
#: never writable business fields, and are never accepted from a query
#: string. Anything outside a row's set — and any of ``id``, ``owner_id``,
#: ``archived_at``, ``created_at``, ``updated_at``, ``role`` — is a
#: crafted-request ``400``, rejected and never ignored (``ACC-011``,
#: ``ACC-012``, ``ACC-019``).
_CREATE_FIELDS: Final[frozenset[str]] = frozenset(
  {"csrf_token", "idempotency_key", "name", "company", "email", "phone", "kind"}
)
_EDIT_FIELDS: Final[frozenset[str]] = _CREATE_FIELDS | {"version"}
_VERSION_ONLY_FIELDS: Final[frozenset[str]] = frozenset(
  {"csrf_token", "idempotency_key", "version"}
)
_REASSIGN_FIELDS: Final[frozenset[str]] = _VERSION_ONLY_FIELDS | {"owner_id"}

#: ``UX_FLOWS.md`` §6.7 ``CP-127`` — the form labels the 409-stale
#: comparison panels use, in :data:`app.services.contacts.CONTACT_FIELDS`
#: order.
_FIELD_LABELS: Final[tuple[tuple[str, str], ...]] = (
  ("name", "Full name"),
  ("company", "Company"),
  ("email", "Work email"),
  ("phone", "Phone"),
  ("kind", "Type"),
)
_OWNER_LABEL: Final = "Owner"

#: ``UX_FLOWS.md`` §6.3 ``CP-30``/``CP-31`` and §6.5 ``CP-41``/``CP-42``/
#: ``CP-43``.
_CP_30_AGENT_SCOPE: Final = "Your records"
_CP_31_ADMIN_SCOPE: Final = "All records"
_CP_42_NO_RESULTS: Final = "No contacts match this search."
_CP_43_EMPTY: Final = (
  "No contacts yet. Add your first contact to start tracking deals and activity."
)

#: ``UX_FLOWS.md`` §6.3 ``CP-38`` — the label for an owner id that names no
#: active user, which a 409-stale reassign panel can legitimately hold.
_CP_38_UNKNOWN_USER: Final = "removed user"

#: The field limits ``contacts/form.html`` renders as ``maxlength``
#: (``CONTRACTS.md`` §8.2). A progressive convenience only: the
#: server-rendered error summary stays authoritative (**R28**, **R31**).
_FORM_LIMITS: Final[dict[str, int]] = {
  "full_name": 160,
  "company": 160,
  "email": 254,
  "phone": 32,
}

#: The two paging control ids §2(e) pins. ``HX-Trigger`` is
#: client-supplied, so it is matched against exactly these, never echoed,
#: and decides focus only — never authorization.
_PAGER_PREV: Final = "page-prev"
_PAGER_NEXT: Final = "page-next"


@dataclass(frozen=True, slots=True)
class _ListQuery:
  """One validated ``GET /contacts`` query string."""

  q: str | None
  kind: str | None
  status: str
  sort: str
  direction: str
  page: int
  per_page: int


def _field(form: FormData, name: str) -> str | None:
  """Return one form field as text, or ``None`` when it is absent."""
  value = form.get(name)
  return value if isinstance(value, str) else None


def _is_fragment(request: Request) -> bool:
  """Return whether this ``GET`` must answer with the partial (§2(e), **PIN 5**).

  Parameters
  ----------
  request : Request
    The inbound request.

  Returns
  -------
  bool
    ``True`` only for a genuine htmx fragment request. A Back-button
    history restore carries ``HX-Request: true`` **and**
    ``HX-History-Restore-Request: true`` — htmx 2.0.10 defaults
    ``historyRestoreAsHxRequest`` to ``true``, and with the pinned
    ``historyCacheSize: 0`` every restore is a cache miss, so this is the
    normal path rather than an edge case. htmx swaps that response into
    the history element with ``innerHTML``, so answering it with a
    fragment would put a fragment on screen as the whole document.
  """
  if request.headers.get("hx-request", "").casefold() != "true":
    return False
  return request.headers.get("hx-history-restore-request", "").casefold() != "true"


def _query_value(request: Request, key: str) -> tuple[bool, str | None]:
  """Return ``(ok, value)`` for one allowlisted query key.

  Parameters
  ----------
  request : Request
    The inbound request.
  key : str
    An allowlisted key.

  Returns
  -------
  tuple[bool, str | None]
    ``ok`` is ``False`` when the key was supplied more than once
    (``SEC-076``), which is a ``400``; the rule applies to allowlisted keys
    only, because an unknown key is already gone by the time duplicates are
    counted (H-08). ``value`` is ``None`` when the key was absent **or
    empty**: a ``<select>`` always submits something, so an empty value is
    the absence of a choice.
  """
  values = request.query_params.getlist(key)
  if len(values) > 1:
    return False, None
  if not values or not values[0]:
    return True, None
  return True, values[0]


def _parse_list_query(request: Request) -> _ListQuery | None:
  """Validate the contact list's query string (**PIN 6**, ``ACC-109``-``ACC-112``).

  Returns
  -------
  _ListQuery | None
    ``None`` means ``400``: a repeated allowlisted key, a non-empty value
    outside an allowlist, a ``page`` or ``per_page`` that is not a positive
    integer, or a ``q`` longer than :data:`_MAX_TERM_LENGTH`. A ``page``
    **beyond the last** is not an error — it is an ordinary empty result
    (``ACC-112``) — and a ``per_page`` above 100 is **clamped**, not
    refused.
  """
  raw: dict[str, str | None] = {}
  for key in _LIST_KEYS:
    ok, value = _query_value(request, key)
    if not ok:
      return None
    raw[key] = value

  term = raw["q"]
  if term is not None and len(term) > _MAX_TERM_LENGTH:
    return None

  status = raw["status"] or _DEFAULT_STATUS
  if status not in _STATUSES:
    return None
  kind = raw["kind"]
  if kind is not None and kind not in KIND_LABELS:
    return None
  sort = raw["sort"] or _DEFAULT_SORT
  if sort not in _SORT_KEYS:
    return None
  direction = raw["dir"] or _DEFAULT_DIRECTION
  if direction not in _DIRECTIONS:
    return None

  page = _positive_int(raw["page"], default=1)
  if page is None:
    return None
  per_page = _positive_int(raw["per_page"], default=DEFAULT_PER_PAGE)
  if per_page is None:
    return None

  return _ListQuery(
    q=term,
    kind=kind,
    status=status,
    sort=sort,
    direction=direction,
    page=page,
    per_page=min(per_page, MAX_PER_PAGE),
  )


def _positive_int(value: str | None, *, default: int) -> int | None:
  """Return ``value`` as a positive integer, ``default`` when absent, else ``None``.

  Notes
  -----
  Matched against ``[0-9]+`` rather than parsed with :meth:`str.isdigit`,
  which is ``True`` for non-ASCII digits :func:`int` also accepts — one
  more spelling of the same number is one more thing a test cannot
  enumerate.
  """
  if value is None:
    return default
  if _DIGITS.match(value) is None:
    return None
  parsed = int(value)
  return parsed if parsed >= 1 else None


def _read_body(form: FormData, allowed: frozenset[str]) -> dict[str, str] | None:
  """Return the submitted body when it is exactly within ``allowed``.

  Parameters
  ----------
  form : FormData
    The parsed body.
  allowed : frozenset[str]
    That form's exact accepted set (§2(f)).

  Returns
  -------
  dict[str, str] | None
    Every allowed name, with ``""`` for one the body omitted — which is
    how an unselected radio group reaches ``CP-66`` rather than a crafted
    400. ``None`` means the body carried a name outside the set, a
    **repeated** name, or a non-textual part: all three are crafted
    requests, rejected and never ignored, because silence makes mass
    assignment untestable (``ACCESS_MATRIX.md`` §5.1).
  """
  counts: dict[str, int] = {}
  for key, value in form.multi_items():
    if key not in allowed or not isinstance(value, str):
      return None
    counts[key] = counts.get(key, 0) + 1
  if any(count != 1 for count in counts.values()):
    return None
  body: dict[str, str] = {}
  for key in allowed:
    submitted = form.get(key)
    body[key] = submitted if isinstance(submitted, str) else ""
  return body


async def _reject_input(request: Request, principal: Principal) -> Response:
  """Answer a crafted query or body with ``400`` and §4.5 **row 6**.

  Notes
  -----
  ``object_id`` is ``NULL``: the row records *that* an allowlist refused
  this actor's request, never which value it refused, so no submitted free
  text reaches a 90-day table the runtime role can read (§4.5 rule 1).
  The generic ``errors/400.html`` names no field and echoes no value
  (``CP-80``/``CP-15``), which is what keeps it a different screen from the
  inline field errors of ``UX_FLOWS.md`` §3.13.
  """
  context = context_of(request)
  await record_denial(
    context.pool,
    actor_id=principal.id,
    object_type=OBJECT_CONTACT,
    object_id=None,
    action=ACTION_INPUT_REJECTED,
    correlation_id=current_correlation_id(),
    at=context.clock.now(),
  )
  return await bad_request(request)


async def _require_admin(request: Request, principal: Principal, raw_id: str) -> None:
  """Step 3: the role check, with §4.5 **row 4** written on refusal.

  Notes
  -----
  Runs **before** the path id is parsed, so an agent posting to
  ``/contacts/<garbage>/reassign`` meets ``403`` and not ``404``: the role
  check is constant over objects and leaks nothing about the target
  (``ACC-033``). ``object_id`` is the path id **iff** it is canonical,
  ``NULL`` otherwise.
  """
  try:
    require_admin(principal)
  except RoleRequired:
    context = context_of(request)
    await record_denial(
      context.pool,
      actor_id=principal.id,
      object_type=OBJECT_CONTACT,
      object_id=parse_canonical(raw_id),
      action=ACTION_ROLE_DENIED,
      correlation_id=current_correlation_id(),
      at=context.clock.now(),
    )
    raise


def _contact_id(raw: str) -> UUID:
  """Return the path segment as a canonical id, or raise the one ``404``.

  Notes
  -----
  No database read happens for a non-canonical segment, and the answer is
  the **same** body as a foreign or missing contact with ``object_id``
  ``NULL`` in the deny row (§2(c)). A non-canonical id must not be a
  cheaper 404 than a canonical one.
  """
  parsed = parse_canonical(raw)
  if parsed is None:
    raise ContactNotFound(None)
  return parsed


def _detail_url(request: Request, contact_id: UUID) -> str:
  """Return the relative ``/contacts/{id}`` path for one contact."""
  return str(request.app.url_path_for("contact_detail", contact_id=str(contact_id)))


def _edit_url(request: Request, contact_id: UUID) -> str:
  """Return the relative ``/contacts/{id}/edit`` path for one contact."""
  return str(request.app.url_path_for("contact_edit", contact_id=str(contact_id)))


def _archive_url(request: Request, contact_id: UUID) -> str:
  """Return the relative ``/contacts/{id}/archive`` path."""
  return str(request.app.url_path_for("contact_archive", contact_id=str(contact_id)))


def _restore_url(request: Request, contact_id: UUID) -> str:
  """Return the relative ``/contacts/{id}/restore`` path."""
  return str(request.app.url_path_for("contact_restore", contact_id=str(contact_id)))


def _reassign_url(request: Request, contact_id: UUID) -> str:
  """Return the relative ``/contacts/{id}/reassign`` path."""
  return str(request.app.url_path_for("contact_reassign", contact_id=str(contact_id)))


def _applied_redirect(request: Request, result: Applied) -> Response:
  """Turn an :class:`~app.services.contacts.Applied` into its ``303``.

  Notes
  -----
  The ``Location`` is rebuilt here from the outcome's object id and its
  allowlisted ``?notice=`` code — the same route-name function on the first
  submission and on a replay, because no URL is ever stored (§1(b)).
  """
  return redirect(f"{_detail_url(request, result.contact_id)}?notice={result.notice}", request)


def _list_url(query: _ListQuery, *, page: int) -> str:
  """Return the canonical ``/contacts`` URL for one page of this query.

  Notes
  -----
  Built from the **validated** values, never from the raw query string, so
  an unknown parameter a client supplied is dropped rather than carried
  forward, and every default is omitted — one query has one URL.
  """
  parameters: list[tuple[str, str]] = []
  if query.q:
    parameters.append(("q", query.q))
  if query.kind:
    parameters.append(("kind", query.kind))
  if query.status != _DEFAULT_STATUS:
    parameters.append(("status", query.status))
  if query.sort != _DEFAULT_SORT:
    parameters.append(("sort", query.sort))
  if query.direction != _DEFAULT_DIRECTION:
    parameters.append(("dir", query.direction))
  if query.per_page != DEFAULT_PER_PAGE:
    parameters.append(("per_page", str(query.per_page)))
  if page != 1:
    parameters.append(("page", str(page)))
  return f"{CONTACTS_URL}?{urlencode(parameters)}" if parameters else CONTACTS_URL


def _announce(view: ContactListView) -> str:
  """Return the live-region text for a swapped list (``CP-41``/``CP-42``/``CP-43``)."""
  if view.result_state == "ok":
    return f"{view.total} results. Page {view.page} of {view.pages}."
  if view.result_state == "no_results":
    return _CP_42_NO_RESULTS
  return _CP_43_EMPTY


def _results(request: Request, view: ContactListView, query: _ListQuery) -> View:
  """Build ``CONTRACTS.md`` §8.3's ``results`` from the service's view model.

  Notes
  -----
  ``prev_url``/``next_url`` are ``None`` **exactly** when the matching
  ``has_*`` is false, which is the template's instruction to render
  **R24**'s inert ``<span aria-disabled="true">`` carrying the same visible
  label — not to omit the control, which would shift the layout at the
  first and last page.
  """
  return View(
    items=[
      {
        "id": str(row.id),
        "url": _detail_url(request, row.id),
        "full_name": row.full_name,
        "company": row.company,
        "email": row.email,
        "phone": row.phone,
        "kind": row.kind,
        "kind_label": row.kind_label,
        "owner_name": row.owner_name,
        "is_own": row.is_own,
        "is_archived": row.is_archived,
        "updated_at": row.updated_at,
      }
      for row in view.items
    ],
    total=view.total,
    page=view.page,
    pages=view.pages,
    per_page=view.per_page,
    range_start=view.range_start,
    range_end=view.range_end,
    has_prev=view.has_prev,
    has_next=view.has_next,
    prev_url=_list_url(query, page=view.page - 1) if view.has_prev else None,
    next_url=_list_url(query, page=view.page + 1) if view.has_next else None,
    result_state=view.result_state,
    sort=query.sort,
    dir=query.direction,
    clear_url=CONTACTS_URL,
  )


def _scope_label(principal: Principal) -> str:
  """Return ``CP-30`` or ``CP-31`` for this principal's list heading."""
  return _CP_31_ADMIN_SCOPE if principal.is_admin else _CP_30_AGENT_SCOPE


def _contact_context(view: ContactView) -> dict[str, Any]:
  """Build ``CONTRACTS.md`` §8.2's ``contact`` — and nothing beyond it.

  Notes
  -----
  ``owner_id`` is deliberately absent: §8's rule 1 keeps a foreign row's
  owner id out of every template, and the one screen that needs it gets it
  as ``reassign.current_owner_id`` instead.
  """
  return {
    "id": str(view.id),
    "full_name": view.full_name,
    "company": view.company,
    "email": view.email,
    "phone": view.phone,
    "kind": view.kind,
    "kind_label": view.kind_label,
    "owner_name": view.owner_name,
    "is_own": view.is_own,
    "is_archived": view.is_archived,
    "archived_at": view.archived_at,
    "version": view.version,
    "created_at": view.created_at,
    "updated_at": view.updated_at,
  }


def _empty_timeline() -> View:
  """Return the placeholder ``timeline`` Slice C fills in.

  Notes
  -----
  ``contacts/detail.html`` is frozen under ``StrictUndefined`` (**D11**), so
  a missing key is a sanitized 500 — and this whole page is re-rendered by
  the reassign bad-target 400. An entry point that 404s would be worse than
  one that is absent, so ``can.add_deal``/``can.add_activity`` are
  ``False`` and these structures are empty (§2(i)).
  """
  return View(
    items=[],
    total=0,
    page=1,
    pages=1,
    has_prev=False,
    has_next=False,
    prev_url=None,
    next_url=None,
    range_start=0,
    range_end=0,
  )


async def _detail_context(
  request: Request,
  principal: Principal,
  view: ContactView,
  *,
  reassign_errors: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
  """Build the whole frozen context of ``contacts/detail.html`` (§8.2).

  Parameters
  ----------
  reassign_errors : dict[str, list[str]] | None, optional
    ``{"owner_id": [CP-25]}`` when re-rendering after a bad reassign
    target, which is a ``400`` on this page and never a 409 (``ACC-032``).

  Notes
  -----
  Four idempotency keys are minted per render — archive, restore, reassign
  and the Slice C activity form — because a page with N mutation forms
  carries N keys (``CONTRACTS.md`` §8 rule 2).

  The reassign panel is built only for an admin on an **active** contact
  (**R25**): while the contact is archived it does not render at all, and a
  crafted POST then answers 409 ``archived_parent``.
  """
  context = context_of(request)
  can_reassign = principal.is_admin and not view.is_archived
  reassign: dict[str, Any] | None = None
  if can_reassign:
    users = await list_assignable_users(context.pool)
    reassign = {
      "assignable_users": [
        {"id": str(user.id), "display_name": user.display_name} for user in users
      ],
      "current_owner_id": str(view.owner_id),
      "idempotency_key": str(mint_key()),
      "version": view.version,
      "errors": reassign_errors or {},
    }
  page = base_context(
    page_title=view.full_name,
    principal=principal,
    csrf_token=csrf_token_for_request(request),
    private=True,
    nav_active="contacts",
    scope_label=_scope_label(principal),
    notice=notice_for(request, substitutions={"name": view.owner_name}),
  )
  page.update(
    contact=_contact_context(view),
    can={
      "edit": not view.is_archived,
      "archive": not view.is_archived,
      "restore": view.is_archived,
      "reassign": can_reassign,
      "add_deal": False,
      "add_activity": False,
    },
    deals=[],
    deal_forms={},
    timeline=_empty_timeline(),
    activity_form=View(
      values={
        "kind": "note",
        "occurred_on": context.clock.now().date().isoformat(),
        "summary": "",
      },
      errors={},
      idempotency_key=str(mint_key()),
      limit=1000,
    ),
    archive_form={"idempotency_key": str(mint_key()), "version": view.version},
    restore_form={"idempotency_key": str(mint_key()), "version": view.version},
    reassign=reassign,
  )
  return page


def _form_context(
  request: Request,
  principal: Principal,
  *,
  mode: str,
  action_url: str,
  cancel_url: str,
  contact: dict[str, Any],
  owner_label: str,
  errors: dict[str, list[str]],
  idempotency_key: UUID,
) -> dict[str, Any]:
  """Build the whole frozen context of ``contacts/form.html`` (§8.2).

  Notes
  -----
  A fresh key is minted for every render, the re-render after a failed
  ``POST`` included: nothing was consumed by a submission that did not
  reach the receipt table, and offering the submitted key back would turn
  the user's next attempt into a 409 ``duplicate``.
  """
  page = base_context(
    page_title="New contact" if mode == "new" else "Edit contact",
    principal=principal,
    csrf_token=csrf_token_for_request(request),
    private=True,
    nav_active="contacts",
    scope_label=_scope_label(principal),
    notice=notice_for(request),
  )
  page.update(
    mode=mode,
    action_url=action_url,
    cancel_url=cancel_url,
    contact=contact,
    owner_label=owner_label,
    errors=errors,
    idempotency_key=str(idempotency_key),
    limits=dict(_FORM_LIMITS),
  )
  return page


def _submitted_contact(
  body: dict[str, str], *, contact_id: str | None, version: int | None
) -> dict[str, Any]:
  """Echo a rejected submission back into ``contacts/form.html``'s ``contact``."""
  return {
    "id": contact_id,
    "full_name": body.get("name", ""),
    "company": body.get("company", ""),
    "email": body.get("email", ""),
    "phone": body.get("phone", ""),
    "kind": body.get("kind", ""),
    "version": version,
  }


def _stale_fields(result: Stale, owner_names: dict[str, str] | None) -> list[dict[str, Any]]:
  """Build ``stale.fields`` — submitted beside current, for every field.

  Parameters
  ----------
  result : Stale
    The service's outcome; ``submitted`` holds the **normalized** values.
  owner_names : dict[str, str] | None
    Display names by user id, for a reassign. Both sides of the ``Owner``
    row are display names — never raw ids (§2(d)) — and an id that names no
    active user renders ``CP-38``'s "removed user", which is the honest
    label for a target that has since been disabled.

  Returns
  -------
  list[dict[str, Any]]
    ``differs`` is computed on the values themselves, so trailing
    whitespace is never reported as a change, and on the owner **id** for a
    reassign, so two users sharing a display name are still two values.
    Archive and restore produce an **empty** list: their form has no data
    field, only a version (§5.1), and ``UX_FLOWS.md`` §3.9 never requires
    at least one.
  """
  if not result.submitted:
    return []
  if "owner_id" in result.submitted:
    submitted_owner = result.submitted["owner_id"]
    names = owner_names or {}
    return [
      {
        "label": _OWNER_LABEL,
        "submitted": names.get(submitted_owner, _CP_38_UNKNOWN_USER),
        "current": result.current.owner_name,
        "differs": submitted_owner != str(result.current.owner_id),
      }
    ]
  current = {
    "name": result.current.full_name,
    "company": result.current.company,
    "email": result.current.email,
    "phone": result.current.phone,
    "kind": result.current.kind_label,
  }
  fields: list[dict[str, Any]] = []
  for name, label in _FIELD_LABELS:
    submitted = result.submitted.get(name, "")
    if name == "kind":
      submitted = KIND_LABELS.get(submitted, submitted)
    fields.append(
      {
        "label": label,
        "submitted": submitted,
        "current": current[name],
        "differs": submitted != current[name],
      }
    )
  return fields


async def _stale_response(
  request: Request,
  result: Stale,
  *,
  action_url: str,
  owner_names: dict[str, str] | None = None,
) -> Response:
  """Render ``errors/409.html`` ``context="stale"`` (**PIN 3**, ``ACC-017``).

  Notes
  -----
  ``keep_form.values`` carries the **raw** submitted values — the owner
  *id* for a reassign, not the display name — because "Keep my changes"
  re-posts them verbatim. Only the comparison panel renders names.
  """
  return await conflict(
    request,
    context="stale",
    extra={
      "stale": {
        "object_label": result.current.full_name,
        "updated_at": result.current.updated_at,
        "fields": _stale_fields(result, owner_names),
        "keep_form": View(
          action_url=action_url,
          values=dict(result.submitted),
          version=result.version,
          idempotency_key=str(result.idempotency_key),
        ),
        "reload_url": _edit_url(request, result.contact_id),
      }
    },
  )


async def _blocked_response(request: Request, result: Blocked) -> Response:
  """Render ``errors/409.html`` ``context="archived_parent"`` (``ACC-018``/``023``/``028``).

  Notes
  -----
  ``body`` and ``state`` select ``CP-13`` ("restore it first") from
  ``CP-23`` ("that has already been done; the contact is {state} now").
  The two keys are additions to ``CONTRACTS.md`` §8.4's frozen
  ``archived_parent`` row, without which ``CP-23`` is unreachable —
  recorded for the contract step rather than assumed.
  """
  restore_form = (
    None
    if result.restore_form is None
    else {
      "idempotency_key": str(result.restore_form.idempotency_key),
      "version": result.restore_form.version,
    }
  )
  return await conflict(
    request,
    context="archived_parent",
    extra={
      "archived_parent": {
        "contact_id": str(result.contact_id),
        "contact_name": result.contact_name,
        "restore_form": restore_form,
        "body": result.body,
        "state": result.state,
      }
    },
  )


async def _duplicate_response(request: Request, result: Duplicate) -> Response:
  """Render ``errors/409.html`` ``context="duplicate"`` (``SQL-028``, ``ACC-226``)."""
  return await conflict(
    request,
    context="duplicate",
    extra={"duplicate": {"record_url": _detail_url(request, result.contact_id)}},
  )


async def _start_mutation(
  request: Request, form_fields: frozenset[str]
) -> tuple[Principal, dict[str, str]] | Response:
  """Run the unsafe-method pipeline up to the body allowlist (§2(c)).

  Returns
  -------
  tuple[Principal, dict[str, str]] | Response
    The principal and the validated body, or the response that refuses the
    request. The order is fixed and shared so nine routes cannot drift:
    session, body, CSRF, content type, budget, forced-reset gate, body
    allowlist. CSRF is checked **before** the content type, so a cross-site
    post carrying no token at all meets the same ``403`` as one carrying a
    stale token; the budget is charged **after** CSRF, so an unauthenticated
    cross-site request cannot burn an authenticated user's budget.
  """
  principal = await require_session(request)
  form = await read_form(request)
  await require_csrf(request, _field(form, "csrf_token"))
  if not form_content_type_ok(request):
    return await bad_request(request)
  await charge_account_budget(request, principal, safe=False)
  if principal.must_change_password:
    raise ForcedResetRequired
  body = _read_body(form, form_fields)
  if body is None:
    return await _reject_input(request, principal)
  return principal, body


async def _start_read(request: Request) -> Principal:
  """Run the safe-method pipeline: session, budget, forced-reset gate."""
  principal = await require_session(request)
  await charge_account_budget(request, principal, safe=True)
  if principal.must_change_password:
    raise ForcedResetRequired
  return principal


@router.get("/contacts", name="contacts")
async def contacts_page(request: Request) -> Response:
  """List, filter and search contacts — one route, two renderings (**PIN 5**).

  Returns
  -------
  Response
    ``200`` with ``partials/contact_results.html`` for an htmx fragment and
    ``contacts/list.html`` otherwise, from the **same** query handling: one
    route, two renderings, no second route table (``CONTRACTS.md`` §8 rule
    3).
  """
  principal = await _start_read(request)
  parsed = _parse_list_query(request)
  if parsed is None:
    return await _reject_input(request, principal)

  context = context_of(request)
  view = await list_contacts(
    context.pool,
    scope_of(principal),
    query=build_contact_query(
      term=parsed.q,
      kind=parsed.kind,
      status=parsed.status,
      sort=parsed.sort,
      direction=parsed.direction,
      page=parsed.page,
      per_page=parsed.per_page,
    ),
  )
  results = _results(request, view, parsed)
  fragment = _is_fragment(request)
  # R24's focus rule: the container takes focus only when the control that
  # triggered the request has disappeared. `HX-Trigger` is client-supplied,
  # so it is matched against exactly the two pager ids, never echoed, and
  # decides focus only. A full page load is not a swap, so it is never set.
  trigger = request.headers.get("hx-trigger", "")
  focus_region = fragment and (
    (trigger == _PAGER_PREV and not view.has_prev) or (trigger == _PAGER_NEXT and not view.has_next)
  )
  page = base_context(
    page_title="Contacts",
    principal=principal,
    csrf_token=csrf_token_for_request(request),
    private=True,
    nav_active="contacts",
    announce=_announce(view) if fragment else None,
    scope_label=_scope_label(principal),
    notice=None if fragment else notice_for(request),
  )
  page.update(
    query={
      "q": parsed.q or "",
      "kind": parsed.kind or "",
      "status": parsed.status,
      "sort": parsed.sort,
      "dir": parsed.direction,
      "page": parsed.page,
    },
    results=results,
    can_create=True,
    focus_region=focus_region,
  )
  # One route, two renderings, from the same query handling and the same
  # context: `contacts/list.html` includes the partial, so every key the
  # partial reads must be present on the full page too.
  template = "partials/contact_results.html" if fragment else "contacts/list.html"
  return render(request, template, page)


@router.get("/contacts/new", name="contact_new")
async def contact_new(request: Request) -> Response:
  """Render the empty create form.

  Notes
  -----
  Registered **before** ``/contacts/{contact_id}``: Starlette matches in
  registration order, and the other way round ``new`` would be read as a
  non-canonical id and answered ``404``.
  """
  principal = await _start_read(request)
  return render(
    request,
    "contacts/form.html",
    _form_context(
      request,
      principal,
      mode="new",
      action_url=CONTACTS_URL,
      cancel_url=CONTACTS_URL,
      contact=_submitted_contact({}, contact_id=None, version=None),
      owner_label=principal.display_name,
      errors={},
      idempotency_key=mint_key(),
    ),
  )


@router.post("/contacts", name="contact_create")
async def contact_create(request: Request) -> Response:
  """Create one contact owned by the actor (``ACC-007``)."""
  started = await _start_mutation(request, _CREATE_FIELDS)
  if isinstance(started, Response):
    return started
  principal, body = started
  key = parse_canonical(body["idempotency_key"])
  if key is None:
    return await _reject_input(request, principal)

  context = context_of(request)
  result = await create_contact(
    context.pool,
    context.clock,
    scope_of(principal),
    submitted=body,
    key=key,
    correlation_id=current_correlation_id(),
  )
  if isinstance(result, Invalid):
    return render(
      request,
      "contacts/form.html",
      _form_context(
        request,
        principal,
        mode="new",
        action_url=CONTACTS_URL,
        cancel_url=CONTACTS_URL,
        contact=_submitted_contact(body, contact_id=None, version=None),
        owner_label=principal.display_name,
        errors=result.errors,
        idempotency_key=mint_key(),
      ),
      status_code=400,
    )
  if isinstance(result, Duplicate):
    return await _duplicate_response(request, result)
  return _applied_redirect(request, result)


@router.get("/contacts/{contact_id}", name="contact_detail")
async def contact_detail(request: Request, contact_id: str) -> Response:
  """Render one contact's workspace (``ACC-001``-``ACC-006``)."""
  principal = await _start_read(request)
  identifier = _contact_id(contact_id)
  context = context_of(request)
  view = await get_for_detail(context.pool, scope_of(principal), contact_id=identifier)
  page = await _detail_context(request, principal, view)
  return render(request, "contacts/detail.html", page)


@router.get("/contacts/{contact_id}/edit", name="contact_edit")
async def contact_edit(request: Request, contact_id: str) -> Response:
  """Render the edit form for one contact."""
  principal = await _start_read(request)
  identifier = _contact_id(contact_id)
  context = context_of(request)
  view = await get_for_detail(context.pool, scope_of(principal), contact_id=identifier)
  detail_url = _detail_url(request, identifier)
  return render(
    request,
    "contacts/form.html",
    _form_context(
      request,
      principal,
      mode="edit",
      action_url=detail_url,
      cancel_url=detail_url,
      contact={
        "id": str(view.id),
        "full_name": view.full_name,
        "company": view.company,
        "email": view.email,
        "phone": view.phone,
        "kind": view.kind,
        "version": view.version,
      },
      owner_label=view.owner_name,
      errors={},
      idempotency_key=mint_key(),
    ),
  )


@router.post("/contacts/{contact_id}", name="contact_update")
async def contact_update(request: Request, contact_id: str) -> Response:
  """Edit one contact's five writable fields (``ACC-014``-``ACC-020``)."""
  started = await _start_mutation(request, _EDIT_FIELDS)
  if isinstance(started, Response):
    return started
  principal, body = started
  identifier = _contact_id(contact_id)
  version = _positive_int(body["version"] or None, default=0)
  key = parse_canonical(body["idempotency_key"])
  if version is None or version < 1 or key is None:
    return await _reject_input(request, principal)

  context = context_of(request)
  result = await update_contact(
    context.pool,
    context.clock,
    scope_of(principal),
    contact_id=identifier,
    expected_version=version,
    submitted=body,
    key=key,
    correlation_id=current_correlation_id(),
  )
  detail_url = _detail_url(request, identifier)
  if isinstance(result, Invalid):
    return render(
      request,
      "contacts/form.html",
      _form_context(
        request,
        principal,
        mode="edit",
        action_url=detail_url,
        cancel_url=detail_url,
        contact=_submitted_contact(body, contact_id=str(identifier), version=version),
        owner_label=principal.display_name,
        errors=result.errors,
        idempotency_key=mint_key(),
      ),
      status_code=400,
    )
  if isinstance(result, Stale):
    return await _stale_response(request, result, action_url=detail_url)
  if isinstance(result, Blocked):
    return await _blocked_response(request, result)
  if isinstance(result, Duplicate):
    return await _duplicate_response(request, result)
  return _applied_redirect(request, result)


@router.post("/contacts/{contact_id}/archive", name="contact_archive")
async def contact_archive(request: Request, contact_id: str) -> Response:
  """Archive one active contact (``ACC-021``-``ACC-025``)."""
  started = await _start_mutation(request, _VERSION_ONLY_FIELDS)
  if isinstance(started, Response):
    return started
  principal, body = started
  identifier = _contact_id(contact_id)
  version = _positive_int(body["version"] or None, default=0)
  key = parse_canonical(body["idempotency_key"])
  if version is None or version < 1 or key is None:
    return await _reject_input(request, principal)

  context = context_of(request)
  result = await archive_contact(
    context.pool,
    context.clock,
    scope_of(principal),
    contact_id=identifier,
    expected_version=version,
    key=key,
    correlation_id=current_correlation_id(),
  )
  return await _mutation_response(request, result, action_url=_archive_url(request, identifier))


@router.post("/contacts/{contact_id}/restore", name="contact_restore")
async def contact_restore(request: Request, contact_id: str) -> Response:
  """Restore one archived contact (``ACC-026``-``ACC-030``)."""
  started = await _start_mutation(request, _VERSION_ONLY_FIELDS)
  if isinstance(started, Response):
    return started
  principal, body = started
  identifier = _contact_id(contact_id)
  version = _positive_int(body["version"] or None, default=0)
  key = parse_canonical(body["idempotency_key"])
  if version is None or version < 1 or key is None:
    return await _reject_input(request, principal)

  context = context_of(request)
  result = await restore_contact(
    context.pool,
    context.clock,
    scope_of(principal),
    contact_id=identifier,
    expected_version=version,
    key=key,
    correlation_id=current_correlation_id(),
  )
  return await _mutation_response(request, result, action_url=_restore_url(request, identifier))


@router.post("/contacts/{contact_id}/reassign", name="contact_reassign")
async def contact_reassign(request: Request, contact_id: str) -> Response:
  """Move one contact to another active owner — admin only (``ACC-031``-``ACC-034``)."""
  started = await _start_mutation(request, _REASSIGN_FIELDS)
  if isinstance(started, Response):
    return started
  principal, body = started
  await _require_admin(request, principal, contact_id)
  identifier = _contact_id(contact_id)
  version = _positive_int(body["version"] or None, default=0)
  key = parse_canonical(body["idempotency_key"])
  if version is None or version < 1 or key is None:
    return await _reject_input(request, principal)

  context = context_of(request)
  scope = scope_of(principal)
  new_owner_id = parse_canonical(body["owner_id"])
  if new_owner_id is None:
    # ACC-032 with a malformed target: the contact is still resolved under
    # the scope predicate first, so a foreign one answers 404 and never
    # this 400 — the 409/400 ordering rule applied to a bad owner id.
    view = await get_for_detail(context.pool, scope, contact_id=identifier)
    page = await _detail_context(
      request, principal, view, reassign_errors={"owner_id": [CP_25_BAD_TARGET]}
    )
    return render(request, "contacts/detail.html", page, status_code=400)

  result = await reassign_contact(
    context.pool,
    context.clock,
    scope,
    contact_id=identifier,
    expected_version=version,
    new_owner_id=new_owner_id,
    key=key,
    correlation_id=current_correlation_id(),
  )
  if isinstance(result, Invalid):
    view = await get_for_detail(context.pool, scope, contact_id=identifier)
    page = await _detail_context(request, principal, view, reassign_errors=result.errors)
    return render(request, "contacts/detail.html", page, status_code=400)
  if isinstance(result, Stale):
    users = await list_assignable_users(context.pool)
    return await _stale_response(
      request,
      result,
      action_url=_reassign_url(request, identifier),
      owner_names={str(user.id): user.display_name for user in users},
    )
  return await _mutation_response(request, result, action_url=_reassign_url(request, identifier))


async def _mutation_response(
  request: Request,
  result: Applied | Stale | Blocked | Duplicate,
  *,
  action_url: str,
) -> Response:
  """Turn one fieldless mutation's outcome into its response."""
  if isinstance(result, Stale):
    return await _stale_response(request, result, action_url=action_url)
  if isinstance(result, Blocked):
    return await _blocked_response(request, result)
  if isinstance(result, Duplicate):
    return await _duplicate_response(request, result)
  return _applied_redirect(request, result)
