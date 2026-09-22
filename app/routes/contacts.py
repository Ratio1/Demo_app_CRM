"""The contact routes: the list, the forms, and the four mutations.

Each handler follows the one shape, in the one order: resolve the session,
read and check CSRF on an unsafe method, charge the budget, apply the
forced-reset gate, check the role where there is one, then do the work. A
refusal is **raised**, never rendered here — :mod:`app.routes.errors` owns
every status page — with one deliberate exception: the ``400`` of a
crafted request is returned from
:func:`~app.routes.pipeline.reject_input`, because it also writes the
``input_rejected`` row and that row belongs beside the decision that
produced it.

Three rules are worth reading before changing anything here.

*Nothing on this page is authorization.* ``can_create``, ``can.edit``,
``can.reassign`` and the absence of a panel are **UI hiding**; every one
of them is re-decided server-side by the route's own guards and by the
scope predicate inside the statement. Hiding a control is never a
substitute.

*An empty query value means the parameter was not supplied.* A
``<select>`` always submits something, so ``?kind=`` is the filter bar's
"any" option and not a value outside the enum; a **non-empty** value
outside an allowlist is a crafted-request ``400``.
One rule for ``q``, ``kind``, ``status``, ``sort``, ``dir``, ``page`` and
``per_page`` alike.

*A fragment is decided by two headers, not one.* htmx 2.0.10 sends
``HX-Request: true`` on a Back-button history restore as well, and swaps
that response into the history element with ``innerHTML`` — so a bare
``HX-Request`` check would swap a fragment in as the whole document.
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
from app.routes.cards import deal_card_context, stage_form_context
from app.routes.errors import CONTACTS_URL, conflict, redirect
from app.routes.pipeline import (
  is_fragment_request,
  positive_int,
  query_value,
  reject_input,
  stale_body,
  start_mutation,
  start_read,
)
from app.routes.rendering import (
  View,
  base_context,
  csrf_token_for_request,
  notice_for,
  render,
  scope_label_for,
)
from app.security.context import context_of
from app.security.failures import ContactNotFound
from app.security.idempotency import mint_key, parse_canonical
from app.security.principal import scope_of
from app.services.activities import (
  DEFAULT_PER_PAGE as ACTIVITY_PER_PAGE,
)
from app.services.activities import (
  SUMMARY_MAX,
  TimelineView,
  timeline_for_contact,
)
from app.services.contacts import (
  BAD_OWNER_TARGET_MESSAGE,
  DEFAULT_PER_PAGE,
  KIND_LABELS,
  MAX_PER_PAGE,
  Applied,
  Blocked,
  ContactListView,
  ContactView,
  Duplicate,
  Invalid,
  RestoreForm,
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
from app.services.deals import list_for_contact

if TYPE_CHECKING:
  from uuid import UUID

  from app.security.principal import Principal

__all__ = ["detail_page_context", "router"]

router = APIRouter()

#: The allowlisted query keys. Every other parameter **name** is ignored,
#: dropped before any other check; a repeated one of these is a
#: ``400``.
_LIST_KEYS: Final[tuple[str, ...]] = ("q", "status", "kind", "sort", "dir", "page", "per_page")

_SORT_KEYS: Final[frozenset[str]] = frozenset(
  {"name", "company", "email", "created_at", "updated_at"}
)
_DIRECTIONS: Final[frozenset[str]] = frozenset({"asc", "desc"})
_STATUSES: Final[frozenset[str]] = frozenset({"active", "archived", "all"})

_DEFAULT_SORT: Final = "updated_at"
_DEFAULT_DIRECTION: Final = "desc"
_DEFAULT_STATUS: Final = "active"

#: 254 is ``ck_contacts_email``'s upper bound and therefore the
#: longest **searched** column of the three, so a longer prefix can match
#: nothing that could ever be stored. 160 — the ``full_name``/``company``
#: bound — would wrongly refuse a legitimate long-email prefix.
_MAX_TERM_LENGTH: Final = 254

_DIGITS: Final = re.compile(r"\A[0-9]+\Z")

#: ``csrf_token`` and ``idempotency_key`` are on **every** form, are
#: never writable business fields, and are never accepted from a query
#: string. Anything outside a row's set — and any of ``id``, ``owner_id``,
#: ``archived_at``, ``created_at``, ``updated_at``, ``role`` — is a
#: crafted-request ``400``, rejected and never ignored.
_CREATE_FIELDS: Final[frozenset[str]] = frozenset(
  {"csrf_token", "idempotency_key", "name", "company", "email", "phone", "kind"}
)
_EDIT_FIELDS: Final[frozenset[str]] = _CREATE_FIELDS | {"version"}
_VERSION_ONLY_FIELDS: Final[frozenset[str]] = frozenset(
  {"csrf_token", "idempotency_key", "version"}
)
_REASSIGN_FIELDS: Final[frozenset[str]] = _VERSION_ONLY_FIELDS | {"owner_id"}

#: The form labels the 409-stale comparison panels use, in
#: :data:`app.services.contacts.CONTACT_FIELDS` order.
_FIELD_LABELS: Final[tuple[tuple[str, str], ...]] = (
  ("name", "Full name"),
  ("company", "Company"),
  ("email", "Work email"),
  ("phone", "Phone"),
  ("kind", "Type"),
)
_OWNER_LABEL: Final = "Owner"

#: *"Owner: you"* or *"Owner: {name}"*. The
#: template renders ``Owner: {{ owner_label }}``, so the **value** is
#: pre-formatted here: a record of one's own reads "you", never the
#: viewer's own display name repeated back at them.
_OWNER_SELF_LABEL: Final = "you"

#: The two empty states of the contact list.
_CONTACTS_NO_RESULTS_MESSAGE: Final = "No contacts match this search."
_CONTACTS_EMPTY_MESSAGE: Final = (
  "No contacts yet. Add your first contact to start tracking deals and activity."
)

#: The label for an owner id that names no
#: active user, which a 409-stale reassign panel can legitimately hold.
_UNKNOWN_USER_LABEL: Final = "removed user"

#: The create form renders this value pre-selected, so
#: the pair a user never touches still submits one — which is what makes
#: "the form never answers 400 for an untouched radio pair" true of the
#: shipped form rather than of the validator. The **value**, not a label:
#: it is compared against ``contact.kind`` in the template and against
#: :data:`~app.services.contacts.KIND_LABELS` in the service.
_DEFAULT_KIND: Final = "lead"

#: The field limits ``contacts/form.html`` renders as ``maxlength``
#:. A progressive convenience only: the
#: server-rendered error summary stays authoritative.
_FORM_LIMITS: Final[dict[str, int]] = {
  "full_name": 160,
  "company": 160,
  "email": 254,
  "phone": 32,
}

#: The two paging control ids. ``HX-Trigger`` is
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


def _parse_list_query(request: Request) -> _ListQuery | None:
  """Validate the contact list's query string.

  Returns
  -------
  _ListQuery | None
    ``None`` means ``400``: a repeated allowlisted key, a non-empty value
    outside an allowlist, a ``page`` or ``per_page`` that is not a positive
    integer, or a ``q`` longer than :data:`_MAX_TERM_LENGTH`. A ``page``
    **beyond the last** is not an error — it is an ordinary empty result
    — and a ``per_page`` above 100 is **clamped**, not
    refused.
  """
  raw: dict[str, str | None] = {}
  for key in _LIST_KEYS:
    ok, value = query_value(request, key)
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

  page = positive_int(raw["page"], default=1)
  if page is None:
    return None
  per_page = positive_int(raw["per_page"], default=DEFAULT_PER_PAGE)
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


def _contact_id(raw: str) -> UUID:
  """Return the path segment as a canonical id, or raise the one ``404``.

  Notes
  -----
  No database read happens for a non-canonical segment, and the answer is
  the **same** body as a foreign or missing contact with ``object_id``
  ``NULL`` in the deny row. A non-canonical id must not be a
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
  submission and on a replay, because no URL is ever stored.
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
  """Return the live-region text a swapped list announces."""
  if view.result_state == "ok":
    return f"{view.total} results. Page {view.page} of {view.pages}."
  if view.result_state == "no_results":
    return _CONTACTS_NO_RESULTS_MESSAGE
  return _CONTACTS_EMPTY_MESSAGE


def _results(request: Request, view: ContactListView, query: _ListQuery) -> View:
  """Build the ``results`` context from the service's view model.

  Notes
  -----
  ``prev_url``/``next_url`` are ``None`` **exactly** when the matching
  ``has_*`` is false, which is the template's instruction to render
  an inert ``<span aria-disabled="true">`` carrying the same visible label
  — not to omit the control, which would shift the layout at the first and
  last page.
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


def _owner_label(owner_name: str, *, is_own: bool) -> str:
  """Return the owner value: "you" for one's own record, else the name."""
  return _OWNER_SELF_LABEL if is_own else owner_name


def _contact_context(view: ContactView) -> dict[str, Any]:
  """Build the ``contact`` context — and nothing beyond it.

  Notes
  -----
  ``owner_id`` is deliberately absent: a foreign row's owner id stays out
  of every template, and the one screen that needs it gets it
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


def _timeline_url(request: Request, contact_id: UUID, *, page: int) -> str:
  """Return the ``/contacts/{id}/timeline`` URL for one page of the region.

  Notes
  -----
  Built from the route name and the **validated** page number, never from
  the raw query string, and page 1 carries no parameter at all — one page,
  one URL, which is what ``hx-push-url="true"`` puts in the history.
  """
  base = str(request.app.url_path_for("contact_timeline", contact_id=str(contact_id)))
  return base if page <= 1 else f"{base}?page={page}"


def _timeline(request: Request, contact_id: UUID, view: TimelineView) -> View:
  """Build the ``timeline`` sub-context.

  Notes
  -----
  ``prev_url``/``next_url`` are ``None`` **exactly** when the matching
  ``has_*`` is false — the template's instruction to render an inert
  ``<span aria-disabled="true">`` with the same visible label, not to omit
  the control. The rule, the macro and the markup are the list region's;
  only the URL builder differs.
  """
  return View(
    items=[
      {
        "id": str(item.id),
        "kind": item.kind,
        "kind_label": item.kind_label,
        "occurred_on": item.occurred_on,
        "summary": item.summary,
        "author_name": item.author_name,
      }
      for item in view.items
    ],
    total=view.total,
    page=view.page,
    pages=view.pages,
    per_page=view.per_page,
    range_start=view.range_start,
    range_end=view.range_end,
    has_prev=view.has_prev,
    has_next=view.has_next,
    prev_url=_timeline_url(request, contact_id, page=view.page - 1) if view.has_prev else None,
    next_url=_timeline_url(request, contact_id, page=view.page + 1) if view.has_next else None,
  )


async def _detail_context(
  request: Request,
  principal: Principal,
  view: ContactView,
  *,
  reassign_errors: dict[str, list[str]] | None = None,
  activity_errors: dict[str, list[str]] | None = None,
  activity_values: dict[str, str] | None = None,
  timeline_page: int = 1,
) -> dict[str, Any]:
  """Build the whole frozen context of ``contacts/detail.html``.

  Parameters
  ----------
  reassign_errors : dict[str, list[str]] | None, optional
    ``{"owner_id": [...]}`` when re-rendering after a bad reassign
    target, which is a ``400`` on this page and never a 409.
  activity_errors : dict[str, list[str]] | None, optional
    Field errors from a refused ``POST /activities``; the form is on this
    page, so its ``400`` re-renders this page.
  activity_values : dict[str, str] | None, optional
    What was submitted, echoed back so a rejected 1000-character summary is
    not lost: a refused submission always comes back with its text.
  timeline_page : int, optional
    Which page of the ``#timeline`` region to render; 1 on every render but
    the paging one.

  Notes
  -----
  Four idempotency keys are minted per render — archive, restore, reassign
  and the activity form — **plus one per deal**, because a page with N
  mutation forms carries N keys and each deal
  card draws its own stage control. ``deal_forms`` is that per-deal half:
  one key per *control render*, shared by the three forms the partial
  draws, only one of which can be submitted.

  The ``#deals`` region is a **full page render only**: it carries no
  ``hx-*`` attribute and has no fragment route, because there are exactly
  four swap targets on this page and none of them is this one. Every
  deal mutation already lands on ``303 /contacts/{id}…#deal-{id}``, a full
  server render, so the region has nothing to swap.

  The reassign panel is built only for an admin on an **active** contact:
  while the contact is archived it does not render at all, and a crafted
  POST then answers 409 ``archived_parent``.
  """
  context = context_of(request)
  scope = scope_of(principal)
  can_reassign = principal.is_admin and not view.is_archived
  # No archive clause on this read: the parent
  # read above has already decided whether this contact is viewable, and an
  # archived contact's workspace must still show what its owner is about to
  # restore. The stage controls are absent on every card while it is
  # archived, and a crafted POST meets 409 `archived_parent`.
  deals = await list_for_contact(context.runner, scope, contact_id=view.id)
  reassign: dict[str, Any] | None = None
  if can_reassign:
    users = await list_assignable_users(context.runner)
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
    scope_label=scope_label_for(principal),
    notice=notice_for(request, substitutions={"name": view.owner_name}),
  )
  timeline = await timeline_for_contact(
    context.runner,
    scope,
    contact_id=view.id,
    page=timeline_page,
    per_page=ACTIVITY_PER_PAGE,
  )
  page.update(
    contact=_contact_context(view),
    can={
      "edit": not view.is_archived,
      "archive": not view.is_archived,
      "restore": view.is_archived,
      "reassign": can_reassign,
      "add_deal": not view.is_archived,
      # UI hiding only, and false for exactly the reason `add_deal` is: an
      # archived contact accepts no new history. A crafted POST
      # still meets 409 `archived_parent`, decided inside the transaction.
      "add_activity": not view.is_archived,
    },
    deals=[deal_card_context(request, card) for card in deals],
    deal_forms={
      str(card.id): stage_form_context(
        idempotency_key=mint_key(), version=card.version, stage=card.stage
      )
      for card in deals
    },
    timeline=_timeline(request, view.id, timeline),
    activity_form=View(
      # The submitted values on a re-render, the defaults otherwise: `note`
      # pre-selected so an untouched radio quad still submits one — the
      # same rule the contact form's type pair follows — and today's
      # UTC date, which is the clock of record.
      values=activity_values
      or {
        "kind": "note",
        "occurred_on": context.clock.now().date().isoformat(),
        "summary": "",
      },
      errors=activity_errors or {},
      idempotency_key=str(mint_key()),
      limit=SUMMARY_MAX,
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
  """Build the whole frozen context of ``contacts/form.html``.

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
    scope_label=scope_label_for(principal),
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
    row are display names, never raw ids, and an id that names no active
    user renders "removed user", which is the honest
    label for a target that has since been disabled.

  Returns
  -------
  list[dict[str, Any]]
    ``differs`` is computed on the values themselves, so trailing
    whitespace is never reported as a change, and on the owner **id** for a
    reassign, so two users sharing a display name are still two values.
    Archive and restore produce an **empty** list: their form has no data
    field, only a version, and nothing requires at least one.
  """
  if not result.submitted:
    return []
  if "owner_id" in result.submitted:
    submitted_owner = result.submitted["owner_id"]
    names = owner_names or {}
    return [
      {
        "label": _OWNER_LABEL,
        "submitted": names.get(submitted_owner, _UNKNOWN_USER_LABEL),
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
  """Render ``errors/409.html`` ``context="stale"``.

  Notes
  -----
  ``keep_form.values`` carries the **raw** submitted values — the owner
  *id* for a reassign, not the display name — because "Keep my changes"
  re-posts them verbatim. Only the comparison panel renders names.

  ``body`` is the zero-field copy, and is always present so the template
  can read it under ``StrictUndefined``: ``None`` on a panel that has
  fields to compare (the screen keeps its ordinary orientation sentence),
  and :data:`~app.routes.pipeline.ZERO_FIELD_STALE_MESSAGE` on one in which
  **nothing** differs.
  """
  fields = _stale_fields(result, owner_names)
  return await conflict(
    request,
    context="stale",
    extra={
      "stale": {
        "object_label": result.current.full_name,
        "updated_at": result.current.updated_at,
        "fields": fields,
        "body": stale_body(fields),
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
  """Render ``errors/409.html`` with ``context="archived_parent"``.

  Notes
  -----
  ``body`` and ``state`` choose between "restore it first" and "that has
  already been done; the contact is {state} now". Without both keys the
  second sentence would be unreachable, and an archive of an
  already-archived contact would read as an error the user could fix.
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


def _archived_block(view: ContactView) -> Blocked:
  """Build the 409 ``archived_parent`` payload for a write the route refuses.

  Notes
  -----
  The route refuses a reassign against an archived contact itself, before
  the service is reached, on the one path that cannot get there: a
  non-canonical ``owner_id``, which is a field-error 400 on an **active**
  contact but must still be the archived-parent 409 on an archived one —
  restore first, then reassign.
  """
  return Blocked(
    contact_id=view.id,
    contact_name=view.full_name,
    body="restore_first",
    state="archived",
    restore_form=RestoreForm(idempotency_key=mint_key(), version=view.version),
  )


async def _duplicate_response(request: Request, result: Duplicate) -> Response:
  """Render ``errors/409.html`` ``context="duplicate"``."""
  return await conflict(
    request,
    context="duplicate",
    extra={"duplicate": {"record_url": _detail_url(request, result.contact_id)}},
  )


@router.get("/contacts", name="contacts")
async def contacts_page(request: Request) -> Response:
  """List, filter and search contacts — one route, two renderings.

  Returns
  -------
  Response
    ``200`` with ``partials/contact_results.html`` for an htmx fragment and
    ``contacts/list.html`` otherwise, from the **same** query handling: one
    route, two renderings, no second route table.
  """
  principal = await start_read(request)
  parsed = _parse_list_query(request)
  if parsed is None:
    return await reject_input(request, principal)

  context = context_of(request)
  view = await list_contacts(
    context.runner,
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
  fragment = is_fragment_request(request)
  # The focus rule: the container takes focus only when the control that
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
    scope_label=scope_label_for(principal),
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
  """Render the empty create form, with ``kind`` pre-selected.

  Notes
  -----
  Registered **before** ``/contacts/{contact_id}``: Starlette matches in
  registration order, and the other way round ``new`` would be read as a
  non-canonical id and answered ``404``.

  ``kind`` is the one field that arrives pre-filled:
  :data:`_DEFAULT_KIND` selects the ``Lead`` radio, because an unselected
  radio pair submits **no** field at all and would meet its field error on
  a form the user never touched. Every other field is empty — a default a
  user did not choose is a value nobody typed. The re-render after a failed
  ``POST`` deliberately does **not** apply it: there the echo is what was
  submitted, so the field error still reaches anyone who cleared the pair
  by hand.
  """
  principal = await start_read(request)
  return render(
    request,
    "contacts/form.html",
    _form_context(
      request,
      principal,
      mode="new",
      action_url=CONTACTS_URL,
      cancel_url=CONTACTS_URL,
      contact=_submitted_contact({"kind": _DEFAULT_KIND}, contact_id=None, version=None),
      owner_label=_OWNER_SELF_LABEL,
      errors={},
      idempotency_key=mint_key(),
    ),
  )


@router.post("/contacts", name="contact_create")
async def contact_create(request: Request) -> Response:
  """Create one contact owned by the actor."""
  started = await start_mutation(request, _CREATE_FIELDS)
  if isinstance(started, Response):
    return started
  principal, body = started
  key = parse_canonical(body["idempotency_key"])
  if key is None:
    return await reject_input(request, principal)

  context = context_of(request)
  result = await create_contact(
    context.runner,
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
        owner_label=_OWNER_SELF_LABEL,
        errors=result.errors,
        idempotency_key=mint_key(),
      ),
      status_code=400,
    )
  if isinstance(result, Duplicate):
    return await _duplicate_response(request, result)
  return _applied_redirect(request, result)


async def detail_page_context(
  request: Request,
  principal: Principal,
  *,
  contact_id: UUID,
  activity_errors: dict[str, list[str]] | None = None,
  activity_values: dict[str, str] | None = None,
  timeline_page: int = 1,
) -> dict[str, Any]:
  """Read one contact under the scope predicate and build its whole context.

  Parameters
  ----------
  contact_id : UUID
    An already-canonical id.

  Returns
  -------
  dict[str, Any]
    The frozen ``contacts/detail.html`` context — which is also the
    ``partials/timeline.html`` context, because the partial's keys are a
    subset of the page's: one route, two renderings, from one context.

  Raises
  ------
  app.security.failures.ContactNotFound
    For a foreign contact and for a missing one alike.

  Notes
  -----
  The one entry point ``app/routes/activities.py`` uses for both of its
  renders. Putting it here rather than there is what keeps the workspace's
  context built in exactly one place: the scoped read happens **first**, so
  neither a rejected activity body nor a crafted ``?page=`` can be answered
  before the scope predicate has decided.
  """
  context = context_of(request)
  view = await get_for_detail(context.runner, scope_of(principal), contact_id=contact_id)
  return await _detail_context(
    request,
    principal,
    view,
    activity_errors=activity_errors,
    activity_values=activity_values,
    timeline_page=timeline_page,
  )


@router.get("/contacts/{contact_id}", name="contact_detail")
async def contact_detail(request: Request, contact_id: str) -> Response:
  """Render one contact's workspace."""
  principal = await start_read(request)
  identifier = _contact_id(contact_id)
  page = await detail_page_context(request, principal, contact_id=identifier)
  return render(request, "contacts/detail.html", page)


@router.get("/contacts/{contact_id}/edit", name="contact_edit")
async def contact_edit(request: Request, contact_id: str) -> Response:
  """Render the edit form for one contact — ``303`` when it is archived.

  Notes
  -----
  An archived contact has no editable state to render: its detail page
  offers **restore only**, and the matching ``POST`` stays
  409 ``archived_parent``. Sending the form anyway would
  invite a submission whose only possible answer is that 409, so the
  ``GET`` answers ``303`` to the detail instead — the screen that carries
  the one action left.

  The redirect sits **after** :func:`get_for_detail`, so the scope
  predicate still decides first: a foreign archived contact is the
  ordinary ``404`` and this ``303`` can never become an existence oracle.
  It carries no ``?notice=`` — nothing happened, and a code outside the
  allowlist would be copy invented here.
  """
  principal = await start_read(request)
  identifier = _contact_id(contact_id)
  context = context_of(request)
  view = await get_for_detail(context.runner, scope_of(principal), contact_id=identifier)
  detail_url = _detail_url(request, identifier)
  if view.is_archived:
    return redirect(detail_url, request)
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
      owner_label=_owner_label(view.owner_name, is_own=view.is_own),
      errors={},
      idempotency_key=mint_key(),
    ),
  )


@router.post("/contacts/{contact_id}", name="contact_update")
async def contact_update(request: Request, contact_id: str) -> Response:
  """Edit one contact's five writable fields."""
  started = await start_mutation(request, _EDIT_FIELDS)
  if isinstance(started, Response):
    return started
  principal, body = started
  identifier = _contact_id(contact_id)
  version = positive_int(body["version"] or None, default=0)
  key = parse_canonical(body["idempotency_key"])
  if version is None or version < 1 or key is None:
    return await reject_input(request, principal)

  context = context_of(request)
  result = await update_contact(
    context.runner,
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
    # The owner line on the re-rendered form is the contact's owner, not
    # the editor's: an admin editing an agent's contact must not read as
    # its owner. Re-reading here also puts the scope predicate in front of
    # the field errors, so a foreign contact with a bad body is the same
    # 404 as a foreign contact with a good one.
    view = await get_for_detail(context.runner, scope_of(principal), contact_id=identifier)
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
        owner_label=_owner_label(view.owner_name, is_own=view.is_own),
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
  """Archive one active contact."""
  started = await start_mutation(request, _VERSION_ONLY_FIELDS)
  if isinstance(started, Response):
    return started
  principal, body = started
  identifier = _contact_id(contact_id)
  version = positive_int(body["version"] or None, default=0)
  key = parse_canonical(body["idempotency_key"])
  if version is None or version < 1 or key is None:
    return await reject_input(request, principal)

  context = context_of(request)
  result = await archive_contact(
    context.runner,
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
  """Restore one archived contact."""
  started = await start_mutation(request, _VERSION_ONLY_FIELDS)
  if isinstance(started, Response):
    return started
  principal, body = started
  identifier = _contact_id(contact_id)
  version = positive_int(body["version"] or None, default=0)
  key = parse_canonical(body["idempotency_key"])
  if version is None or version < 1 or key is None:
    return await reject_input(request, principal)

  context = context_of(request)
  result = await restore_contact(
    context.runner,
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
  """Move one contact to another active owner — admin only."""
  started = await start_mutation(request, _REASSIGN_FIELDS, admin_for=contact_id)
  if isinstance(started, Response):
    return started
  principal, body = started
  identifier = _contact_id(contact_id)
  version = positive_int(body["version"] or None, default=0)
  key = parse_canonical(body["idempotency_key"])
  if version is None or version < 1 or key is None:
    return await reject_input(request, principal)

  context = context_of(request)
  scope = scope_of(principal)
  new_owner_id = parse_canonical(body["owner_id"])
  if new_owner_id is None:
    # A malformed target: the contact is still resolved under
    # the scope predicate first, so a foreign one answers 404 and never
    # this 400 — the 409/400 ordering rule applied to a bad owner id.
    view = await get_for_detail(context.runner, scope, contact_id=identifier)
    if view.is_archived:
      return await _blocked_response(request, _archived_block(view))
    page = await _detail_context(
      request, principal, view, reassign_errors={"owner_id": [BAD_OWNER_TARGET_MESSAGE]}
    )
    return render(request, "contacts/detail.html", page, status_code=400)

  result = await reassign_contact(
    context.runner,
    context.clock,
    scope,
    contact_id=identifier,
    expected_version=version,
    new_owner_id=new_owner_id,
    key=key,
    correlation_id=current_correlation_id(),
  )
  if isinstance(result, Invalid):
    view = await get_for_detail(context.runner, scope, contact_id=identifier)
    page = await _detail_context(request, principal, view, reassign_errors=result.errors)
    return render(request, "contacts/detail.html", page, status_code=400)
  if isinstance(result, Stale):
    users = await list_assignable_users(context.runner)
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
