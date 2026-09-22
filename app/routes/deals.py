"""The Slice C route table: deals, the pipeline, the forms and the stage control.

Authority: ``contracts/slice-c.md`` §2(c) (the table itself — method, path,
name, CSRF, idempotency, template, context, success and error statuses),
§2(d) (the stage control's exact fields), §2(e) (the fragment predicate and
the focus rule), §1(e) (which transaction each call opens),
``ACCESS_MATRIX.md`` §1.1 (the check order), §1.2 (the status policy and
the H-08 unknown-parameter rule), §3.3/§3.4 (every cell), §4.5 rows 1, 2
and 7 (the deny-audit triples), §5.1-§5.3 (the field allowlists),
``CONTRACTS.md`` §8 (every context key, frozen).

Every handler runs :mod:`app.routes.pipeline`'s order — the **shipped**
one, not a copy — and a refusal is raised rather than rendered here, with
the one deliberate exception the contact table already makes: the ``400``
of a crafted request is returned from
:func:`~app.routes.pipeline.reject_input`, because it also writes §4.5 row
7 and that row belongs beside the decision that produced it.

Four rules are worth reading before changing anything here.

*Registration order is contract.* ``/deals/pipeline`` is registered
**before** ``/deals/{deal_id}``. Starlette matches in order, and the other
way round the literal path would be read as a non-canonical deal id and
answered ``404``.

*A deal id and a parent id are refused differently, on purpose.* A deal id
is the **object being addressed**: non-canonical is the identical ``404``
of ``ACC-202``, with no read. A parent id on the two create surfaces is an
**input being validated**: non-canonical is ``400`` + §4.5 row 7, which is
``ACC-231`` verbatim. So ``/contacts/<garbage>`` is 404 while
``/contacts/<garbage>/deals/new`` is 400 — surface-dependent, no read
either way, and recorded as finding F-6 for the council.

*Nothing on these pages is authorization.* ``can.edit``,
``can.change_stage``, the absence of a stage control and the omission of
the current stage from the ``<select>`` are **UI hiding**; every one is
re-decided inside the transaction, and a crafted ``POST`` meets 409
``archived_parent``, 409 ``stage_terminal`` or 400 all the same
(``ACCESS_MATRIX.md`` §1.4).

*No mutation is ever enhanced* (**R15**). There is no ``hx-post`` anywhere
in this slice: every create, edit and stage move is a plain form ``POST``
answered with a ``303``, and only the two list ``GET``s have an htmx path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlencode

from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import Response

from app.logging import current_correlation_id
from app.routes.cards import contact_url, deal_card_context, deal_url, stage_form_context
from app.routes.errors import CONTACTS_URL, bad_request, conflict, redirect
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
from app.security.audit import OBJECT_DEAL
from app.security.context import context_of
from app.security.failures import DealNotFound
from app.security.idempotency import mint_key, parse_canonical
from app.security.principal import scope_of
from app.services.deals import (
  DEFAULT_PER_PAGE,
  MAX_PER_PAGE,
  STAGE_LABELS,
  TITLE_MAX,
  Applied,
  Blocked,
  DealListView,
  DealView,
  Duplicate,
  Invalid,
  PipelineView,
  SameStage,
  StageTerminal,
  Stale,
  blocked_parent,
  build_deal_query,
  change_stage,
  create_for_contact,
  get_for_detail,
  list_deals,
  parent_for_form,
  pipeline,
  update_deal,
)
from app.services.money import canonical_amount, format_day, format_eur

if TYPE_CHECKING:
  from uuid import UUID

  from app.security.principal import Principal

__all__ = ["router"]

router = APIRouter()

DEALS_URL: Final = "/deals"
PIPELINE_URL: Final = "/deals/pipeline"

#: ``ACCESS_MATRIX.md`` §5.2, deals row. Every other parameter **name** is
#: ignored, dropped before duplicates are counted (H-08); a repeated one of
#: these is a ``400`` (``SEC-076``).
_LIST_KEYS: Final[tuple[str, ...]] = ("q", "stage", "status", "sort", "dir", "page", "per_page")

#: The pipeline allowlists ``status`` **only** — §5.2 gives that surface no
#: sort key and no pager — so ``?sort=x`` there is an unknown name and is
#: ignored rather than rejected.
_PIPELINE_KEYS: Final[tuple[str, ...]] = ("status",)

_SORT_KEYS: Final[frozenset[str]] = frozenset(
  {"title", "amount", "close_date", "stage", "created_at"}
)
_DIRECTIONS: Final[frozenset[str]] = frozenset({"asc", "desc"})
_STATUSES: Final[frozenset[str]] = frozenset({"active", "archived", "all"})
_STAGES: Final[frozenset[str]] = frozenset(STAGE_LABELS)

#: §5.2: the deal list's default sort is ``created_at`` — the contact
#: list's is ``updated_at``, and the difference is in the matrix, not a slip.
_DEFAULT_SORT: Final = "created_at"
_DEFAULT_DIRECTION: Final = "desc"
_DEFAULT_STATUS: Final = "active"

#: §2(c). The deal search reads ``title_lower`` alone, whose CHECK bounds it
#: at 160, so a longer prefix could match nothing storable. The contacts
#: bound is 254 for the same reason, computed from a different column.
_MAX_TERM_LENGTH: Final = TITLE_MAX

#: §2(d). ``csrf_token`` and ``idempotency_key`` are on **every** form, are
#: never writable business fields and are never accepted from a query
#: string. **No ``contact_id``** on create — the parent is the path, and
#: submitting one is a crafted-request ``400``; no ``stage`` (``ACC-211``);
#: no ``contact_id`` on edit (``ACC-217``); no ``owner_id`` anywhere, which
#: ``deals`` has no column for at all (``ACC-212``).
_CREATE_FIELDS: Final[frozenset[str]] = frozenset(
  {"csrf_token", "idempotency_key", "title", "amount", "close_date"}
)
_EDIT_FIELDS: Final[frozenset[str]] = _CREATE_FIELDS | {"version"}
_TERMINAL_FIELDS: Final[frozenset[str]] = frozenset({"csrf_token", "idempotency_key", "version"})
_STAGE_FIELDS: Final[frozenset[str]] = _TERMINAL_FIELDS | {"to_stage"}

#: ``UX_FLOWS.md`` §6.7 ``CP-127`` — the labels the 409-stale comparison
#: panels use, in :data:`app.services.deals.DEAL_FIELDS` order.
_FIELD_LABELS: Final[tuple[tuple[str, str], ...]] = (
  ("title", "Title"),
  ("amount", "Amount"),
  ("close_date", "Close date"),
)
_STAGE_LABEL: Final = "Stage"

#: ``UX_FLOWS.md`` §6.5. ``CP-41`` is the count announcement every list swap
#: makes; ``CP-102`` and ``CP-48`` are the deal list's own two states.
_CP_102_NO_RESULTS: Final = "No deals match these filters."
_CP_48_EMPTY: Final = "No deals yet. Open a contact and add the first deal."

#: The field limit ``deals/form.html`` renders as ``maxlength``
#: (``CONTRACTS.md`` §8.2). A progressive convenience only: the
#: server-rendered error summary stays authoritative (**R28**, **R31**).
_FORM_LIMITS: Final[dict[str, int]] = {"title": TITLE_MAX}

#: The two paging control ids §2(e) pins. ``HX-Trigger`` is client-supplied,
#: so it is matched against exactly these, never echoed, and decides focus
#: only — never authorization.
_PAGER_PREV: Final = "page-prev"
_PAGER_NEXT: Final = "page-next"

#: ``UX_FLOWS.md`` §4.7 — the breadcrumb label of the list every deal
#: belongs under. A constant, never derived from a request.
_BREADCRUMB_CONTACTS: Final = "Contacts"


@dataclass(frozen=True, slots=True)
class _ListQuery:
  """One validated ``GET /deals`` query string."""

  q: str | None
  stage: str | None
  status: str
  sort: str
  direction: str
  page: int
  per_page: int


def _parse_list_query(request: Request) -> _ListQuery | None:
  """Validate the deal list's query string (``ACC-307``-``ACC-309``).

  Returns
  -------
  _ListQuery | None
    ``None`` means ``400``: a repeated allowlisted key, a non-empty value
    outside an allowlist, a ``page`` or ``per_page`` that is not a positive
    integer, or a ``q`` longer than :data:`_MAX_TERM_LENGTH`. A ``page``
    **beyond the last** is not an error — it is an ordinary empty result —
    and a ``per_page`` above 100 is **clamped**, not refused (``ACC-309``).
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
  stage = raw["stage"]
  if stage is not None and stage not in _STAGES:
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
    stage=stage,
    status=status,
    sort=sort,
    direction=direction,
    page=page,
    per_page=min(per_page, MAX_PER_PAGE),
  )


def _parse_pipeline_status(request: Request) -> str | None:
  """Validate ``GET /deals/pipeline``'s one allowlisted key.

  Returns
  -------
  str | None
    The status, or ``None`` for the ``400`` of a repeated key or a value
    outside the three. The pipeline takes no ``sort``, ``dir``, ``page`` or
    ``q``, so those names are simply unknown here and are ignored (H-08).
  """
  for key in _PIPELINE_KEYS:
    ok, value = query_value(request, key)
    if not ok:
      return None
    status = value or _DEFAULT_STATUS
    if status not in _STATUSES:
      return None
    return status
  return _DEFAULT_STATUS


def _deal_id(raw: str) -> UUID:
  """Return the path segment as a canonical deal id, or raise the one ``404``.

  Notes
  -----
  No database read happens for a non-canonical segment, and the answer is
  the **same** body as a foreign or missing deal with ``object_id`` ``NULL``
  in the deny row. A non-canonical id must not be a cheaper 404 than a
  canonical one.
  """
  parsed = parse_canonical(raw)
  if parsed is None:
    raise DealNotFound(None)
  return parsed


def _edit_url(request: Request, deal_id: UUID) -> str:
  """Return the relative ``/deals/{id}/edit`` path."""
  return str(request.app.url_path_for("deal_edit", deal_id=str(deal_id)))


def _stage_url(request: Request, deal_id: UUID) -> str:
  """Return the relative ``/deals/{id}/stage`` path."""
  return str(request.app.url_path_for("deal_stage", deal_id=str(deal_id)))


def _won_url(request: Request, deal_id: UUID) -> str:
  """Return the relative ``/deals/{id}/won`` path."""
  return str(request.app.url_path_for("deal_won", deal_id=str(deal_id)))


def _lost_url(request: Request, deal_id: UUID) -> str:
  """Return the relative ``/deals/{id}/lost`` path."""
  return str(request.app.url_path_for("deal_lost", deal_id=str(deal_id)))


def _new_url(request: Request, contact_id: UUID) -> str:
  """Return the relative ``/contacts/{id}/deals/new`` path."""
  return str(request.app.url_path_for("deal_new", contact_id=str(contact_id)))


def _create_url(request: Request, contact_id: UUID) -> str:
  """Return the relative ``/contacts/{id}/deals`` path."""
  return str(request.app.url_path_for("deal_create", contact_id=str(contact_id)))


def _list_url(query: _ListQuery, *, page: int) -> str:
  """Return the canonical ``/deals`` URL for one page of this query.

  Notes
  -----
  Built from the **validated** values, never from the raw query string, so
  an unknown parameter a client supplied is dropped rather than carried
  forward, and every default is omitted — one query has one URL.
  """
  parameters: list[tuple[str, str]] = []
  if query.q:
    parameters.append(("q", query.q))
  if query.stage:
    parameters.append(("stage", query.stage))
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
  return f"{DEALS_URL}?{urlencode(parameters)}" if parameters else DEALS_URL


def _announce(view: DealListView) -> str:
  """Return the live-region text for a swapped list (``CP-41``/``CP-102``/``CP-48``)."""
  if view.result_state == "ok":
    return f"{view.total} results. Page {view.page} of {view.pages}."
  if view.result_state == "no_results":
    return _CP_102_NO_RESULTS
  return _CP_48_EMPTY


def _results(request: Request, view: DealListView, query: _ListQuery) -> View:
  """Build ``CONTRACTS.md`` §8.3's ``results`` from the service's view model.

  Notes
  -----
  ``prev_url``/``next_url`` are ``None`` **exactly** when the matching
  ``has_*`` is false, which is the template's instruction to render
  **R24**'s inert ``<span aria-disabled="true">`` carrying the same visible
  label — not to omit the control.
  """
  return View(
    items=[deal_card_context(request, row) for row in view.items],
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
    clear_url=DEALS_URL,
  )


def _stages(request: Request, view: PipelineView) -> list[dict[str, Any]]:
  """Build ``deals/pipeline.html``'s ``stages`` — five columns, always.

  Notes
  -----
  ``count`` and ``amount`` come from the engine's aggregate and **not** from
  ``len(deals)`` or a Python sum (**PIN C6**, ``ACC-302``), so a column
  whose card list is capped still reports the true total. The card carries
  no stage control on this surface (**R22**).
  """
  return [
    {
      "key": column.key,
      "label": column.label,
      "count": column.count,
      "amount": column.amount,
      "deals": [deal_card_context(request, card) for card in column.deals],
    }
    for column in view.stages
  ]


def _deal_context(view: DealView) -> dict[str, Any]:
  """Build ``CONTRACTS.md`` §8.2's ``deal`` — and nothing beyond it."""
  return {
    "id": str(view.id),
    "title": view.title,
    "amount": view.amount,
    "close_date": view.close_date,
    "stage": view.stage,
    "stage_label": view.stage_label,
    "stage_changed_at": view.stage_changed_at,
    "version": view.version,
    "created_at": view.created_at,
    "updated_at": view.updated_at,
  }


def _contact_context(view: DealView) -> dict[str, Any]:
  """Build ``deals/detail.html``'s frozen ``contact`` sub-context.

  Notes
  -----
  Five keys and no ``owner_id``: §8's rule 1 keeps a foreign row's owner id
  out of every template, and ``is_archived`` is here because the deal的
  archived state **is** its parent's.
  """
  return {
    "id": str(view.contact_id),
    "full_name": view.contact_name,
    "is_archived": view.contact_is_archived,
    "owner_name": view.owner_name,
    "is_own": view.is_own,
  }


def _breadcrumb(request: Request, view: DealView) -> list[dict[str, str]]:
  """Build the deal detail's breadcrumb: the list, then the parent."""
  return [
    {"label": _BREADCRUMB_CONTACTS, "url": CONTACTS_URL},
    {"label": view.contact_name, "url": contact_url(request, view.contact_id)},
  ]


def _form_context(
  request: Request,
  principal: Principal,
  *,
  mode: str,
  action_url: str,
  cancel_url: str,
  deal: dict[str, Any],
  contact: dict[str, str],
  errors: dict[str, list[str]],
  idempotency_key: UUID,
) -> dict[str, Any]:
  """Build the whole frozen context of ``deals/form.html`` (§8.2).

  Notes
  -----
  A fresh key is minted for every render, the re-render after a failed
  ``POST`` included: nothing was consumed by a submission that did not
  reach the receipt table, and offering the submitted key back would turn
  the user's next attempt into a 409 ``duplicate``.
  """
  page = base_context(
    page_title="New deal" if mode == "new" else "Edit deal",
    principal=principal,
    csrf_token=csrf_token_for_request(request),
    private=True,
    nav_active="deals",
    scope_label=scope_label_for(principal),
    notice=notice_for(request),
  )
  page.update(
    mode=mode,
    action_url=action_url,
    cancel_url=cancel_url,
    deal=deal,
    contact=contact,
    errors=errors,
    idempotency_key=str(idempotency_key),
    limits=dict(_FORM_LIMITS),
  )
  return page


def _submitted_deal(
  body: dict[str, str], *, deal_id: str | None, version: int | None
) -> dict[str, Any]:
  """Echo a rejected submission back into ``deals/form.html``'s ``deal``.

  Notes
  -----
  The **raw** strings, not the parsed values: ``UX_FLOWS.md`` §3.13
  preserves what was typed, so an amount the parser refused comes back
  exactly as it was entered rather than as a ``€`` rendering of something
  the user did not write.
  """
  return {
    "id": deal_id,
    "title": body.get("title", ""),
    "amount": body.get("amount", ""),
    "close_date": body.get("close_date", ""),
    "version": version,
  }


def _stored_deal(view: DealView) -> dict[str, Any]:
  """Build ``deals/form.html``'s ``deal`` from the stored row, for an edit.

  Notes
  -----
  ``amount`` is the **canonical** ``1250.00`` and never the ``€`` string:
  the field is a ``type="text" inputmode="decimal"`` input whose value is
  re-parsed by the same strict pattern on submit. ``close_date`` is ISO,
  which is what ``<input type="date">`` puts on the wire (**R31**).
  """
  return {
    "id": str(view.id),
    "title": view.title,
    "amount": canonical_amount(view.amount),
    "close_date": "" if view.close_date is None else view.close_date.isoformat(),
    "version": view.version,
  }


def _applied_to_contact(request: Request, result: Applied) -> Response:
  """Turn an :class:`~app.services.deals.Applied` into the workspace ``303``.

  Notes
  -----
  ``UX_FLOWS.md`` §2 step 6 and §4.8 pin one destination for every create
  and every stage move, from either screen:
  ``/contacts/{contact_id}?notice=…#deal-{deal_id}``. Not "back where you
  came from" — that needs a ``return_to`` field, which is in no allowlist
  (``ACC-011``), and ``Referer`` is never trusted (``SEC-041``).
  """
  target = contact_url(request, result.contact_id)
  return redirect(f"{target}?notice={result.notice}#deal-{result.deal_id}", request)


def _applied_to_deal(request: Request, result: Applied) -> Response:
  """Turn an edit's :class:`~app.services.deals.Applied` into its ``303``."""
  return redirect(f"{deal_url(request, result.deal_id)}?notice={result.notice}", request)


def _stale_fields(result: Stale) -> list[dict[str, Any]]:
  """Build ``stale.fields`` — submitted beside current, for every field.

  Returns
  -------
  list[dict[str, Any]]
    One row per writable field for an edit, or the single ``Stage`` row for
    a stage change (``UX_FLOWS.md`` §3.9). ``differs`` is computed on the
    **canonical** values — the quantized amount string, the ISO date, the
    stage token — so a difference is a difference in the record and never
    in how it was spelled or displayed.

  Notes
  -----
  Both sides render through the same two formatters the rest of the
  application uses, so the panel cannot disagree with the page it came
  from. An empty value is rendered as the empty string and the template
  turns it into "(empty)".
  """
  if "to_stage" in result.submitted:
    submitted_stage = result.submitted["to_stage"]
    return [
      {
        "label": _STAGE_LABEL,
        "submitted": STAGE_LABELS.get(submitted_stage, submitted_stage),
        "current": result.current.stage_label,
        "differs": submitted_stage != result.current.stage,
      }
    ]
  current_amount = canonical_amount(result.current.amount)
  current_close = "" if result.current.close_date is None else result.current.close_date.isoformat()
  current_shown = {
    "title": result.current.title,
    "amount": format_eur(result.current.amount),
    "close_date": ""
    if result.current.close_date is None
    else format_day(result.current.close_date),
  }
  canonical_current = {
    "title": result.current.title,
    "amount": current_amount,
    "close_date": current_close,
  }
  fields: list[dict[str, Any]] = []
  for name, label in _FIELD_LABELS:
    submitted = result.submitted.get(name, "")
    if name == "amount":
      shown = format_eur(Decimal(submitted)) if submitted else ""
    elif name == "close_date":
      shown = format_day(date.fromisoformat(submitted)) if submitted else ""
    else:
      shown = submitted
    fields.append(
      {
        "label": label,
        "submitted": shown,
        "current": current_shown[name],
        "differs": submitted != canonical_current[name],
      }
    )
  return fields


async def _stale_response(request: Request, result: Stale, *, action_url: str) -> Response:
  """Render ``errors/409.html`` ``context="stale"`` (**PIN 3**, ``ACC-215``).

  Notes
  -----
  ``keep_form.values`` carries the **normalized** submitted values, because
  "Keep my changes" re-posts them verbatim against the **current** version
  with a **fresh** key. ``body`` is **R69**'s shared predicate: the generic
  sentence whenever no rendered field differs — which for a stage change is
  the "someone already made this move" case ``UX_FLOWS.md`` §3.9 calls out.
  """
  fields = _stale_fields(result)
  return await conflict(
    request,
    context="stale",
    extra={
      "stale": {
        "object_label": result.current.title,
        "updated_at": result.current.updated_at,
        "fields": fields,
        "body": stale_body(fields),
        "keep_form": View(
          action_url=action_url,
          values=dict(result.submitted),
          version=result.version,
          idempotency_key=str(result.idempotency_key),
        ),
        "reload_url": _edit_url(request, result.deal_id),
      }
    },
  )


async def _blocked_response(request: Request, result: Blocked) -> Response:
  """Render ``errors/409.html`` ``context="archived_parent"`` (``ACC-208``/``216``/``222``).

  Notes
  -----
  The payload is the parent's: ``ACC-224`` gives a deal no archive state of
  its own, so the only thing that can unblock the write is restoring the
  **contact**, and the primary action is that real ``POST`` form.
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
        # The two keys Slice B added to §8.4's frozen row so `CP-23` is
        # reachable. A deal write under an archived parent is always
        # "restore it first", never "that has already been done".
        "body": "cp_13",
        "state": "archived",
      }
    },
  )


async def _duplicate_response(request: Request, result: Duplicate) -> Response:
  """Render ``errors/409.html`` ``context="duplicate"`` (``ACC-226``, ``SQL-028``)."""
  return await conflict(
    request,
    context="duplicate",
    extra={"duplicate": {"record_url": deal_url(request, result.deal_id)}},
  )


async def _stage_terminal_response(request: Request, result: StageTerminal) -> Response:
  """Render ``errors/409.html`` ``context="stage_terminal"`` (``ACC-220``).

  Notes
  -----
  ``CP-35`` — *"{Won|Lost} deals cannot be moved to another stage"* — is the
  page's sentence, and ``stage_label`` is the substitution it takes from the
  row this transaction read. Reachable only by a crafted request: the
  control is **absent** on a terminal deal, not disabled (**R22**).
  """
  return await conflict(
    request,
    context="stage_terminal",
    extra={
      "stage_terminal": {
        "deal_url": deal_url(request, result.deal_id),
        "stage_label": result.stage_label,
      }
    },
  )


@router.get("/deals", name="deals")
async def deals_page(request: Request) -> Response:
  """List, filter and search deals — one route, two renderings (**PIN 5**).

  Returns
  -------
  Response
    ``200`` with ``partials/deal_results.html`` for an htmx fragment and
    ``deals/list.html`` otherwise, from the **same** query handling: one
    route, two renderings, no second route table (``CONTRACTS.md`` §8 rule
    3).

  Notes
  -----
  ``can_create`` is ``false`` here and says so in the frozen context: a deal
  is always created **under a contact**, so the entry point is the
  workspace's "New deal" action and never this page (``UX_FLOWS.md`` §4.7).
  """
  principal = await start_read(request)
  parsed = _parse_list_query(request)
  if parsed is None:
    return await reject_input(request, principal, object_type=OBJECT_DEAL)

  context = context_of(request)
  view = await list_deals(
    context.runner,
    scope_of(principal),
    query=build_deal_query(
      term=parsed.q,
      stage=parsed.stage,
      status=parsed.status,
      sort=parsed.sort,
      direction=parsed.direction,
      page=parsed.page,
      per_page=parsed.per_page,
    ),
  )
  results = _results(request, view, parsed)
  fragment = is_fragment_request(request)
  # R24's focus rule: the container takes focus only when the control that
  # triggered the request has disappeared. `HX-Trigger` is client-supplied,
  # so it is matched against exactly the two pager ids, never echoed, and
  # decides focus only. A full page load is not a swap, so it is never set.
  trigger = request.headers.get("hx-trigger", "")
  focus_region = fragment and (
    (trigger == _PAGER_PREV and not view.has_prev) or (trigger == _PAGER_NEXT and not view.has_next)
  )
  page = base_context(
    page_title="Deals",
    principal=principal,
    csrf_token=csrf_token_for_request(request),
    private=True,
    nav_active="deals",
    announce=_announce(view) if fragment else None,
    scope_label=scope_label_for(principal),
    notice=None if fragment else notice_for(request),
  )
  page.update(
    query={
      "q": parsed.q or "",
      "stage": parsed.stage or "",
      "status": parsed.status,
      "sort": parsed.sort,
      "dir": parsed.direction,
      "page": parsed.page,
    },
    results=results,
    can_create=False,
    focus_region=focus_region,
  )
  template = "partials/deal_results.html" if fragment else "deals/list.html"
  return render(request, template, page)


@router.get("/deals/pipeline", name="deals_pipeline")
async def deals_pipeline(request: Request) -> Response:
  """Render the five-column pipeline — read-only (**R22**, ``ACC-302``).

  Notes
  -----
  Registered **before** ``/deals/{deal_id}``: Starlette matches in
  registration order, and the other way round ``pipeline`` would be read as
  a non-canonical deal id and answered ``404``.

  The columns come from one ``SERIALIZABLE, READ ONLY`` snapshot, so a
  header and its cards cannot disagree, and **no stage control renders on
  a pipeline card** — the pipeline is a report, and the control lives on
  the workspace card and the deal detail (**R22**).
  """
  principal = await start_read(request)
  status = _parse_pipeline_status(request)
  if status is None:
    return await reject_input(request, principal, object_type=OBJECT_DEAL)

  context = context_of(request)
  view = await pipeline(context.runner, scope_of(principal), status=status)
  fragment = is_fragment_request(request)
  page = base_context(
    page_title="Pipeline",
    principal=principal,
    csrf_token=csrf_token_for_request(request),
    private=True,
    nav_active="deals",
    # The pipeline has no pager and no sort, so nothing can disappear under
    # the control that triggered a swap: §2(e) makes its announcement and
    # its focus move unconditionally absent.
    announce=None,
    scope_label=scope_label_for(principal),
    notice=None if fragment else notice_for(request),
  )
  page.update(query={"status": status}, stages=_stages(request, view))
  template = "partials/pipeline.html" if fragment else "deals/pipeline.html"
  return render(request, template, page)


@router.get("/contacts/{contact_id}/deals/new", name="deal_new")
async def deal_new(request: Request, contact_id: str) -> Response:
  """Render the empty create form for one contact (``ACC-228``-``ACC-231``).

  Notes
  -----
  The parent id is an **input**, so a non-canonical one is ``400`` + §4.5
  row 7 (``ACC-231``) and never a 404: a syntactically invalid id carries
  no information about what exists, and answering 400 keeps ``ACC-228``'s
  404 reserved for well-formed ids.

  ``stage`` is not a field — a new deal is always ``new`` (``ACC-211``), and
  ``CP-33`` says so on the page — and there is no ``contact_id`` input
  either: the parent is the path, and the ``POST`` re-resolves it inside
  the transaction.
  """
  principal = await start_read(request)
  parent_id = parse_canonical(contact_id)
  if parent_id is None:
    return await reject_input(request, principal, object_type=OBJECT_DEAL)

  context = context_of(request)
  parent = await parent_for_form(context.runner, scope_of(principal), contact_id=parent_id)
  if isinstance(parent, Blocked):
    return await _blocked_response(request, parent)
  return render(
    request,
    "deals/form.html",
    _form_context(
      request,
      principal,
      mode="new",
      action_url=_create_url(request, parent.id),
      cancel_url=contact_url(request, parent.id),
      deal=_submitted_deal({}, deal_id=None, version=None),
      contact={"id": str(parent.id), "full_name": parent.full_name},
      errors={},
      idempotency_key=mint_key(),
    ),
  )


@router.post("/contacts/{contact_id}/deals", name="deal_create")
async def deal_create(request: Request, contact_id: str) -> Response:
  """Create one deal under one contact (``ACC-205``-``ACC-211``)."""
  started = await start_mutation(request, _CREATE_FIELDS, object_type=OBJECT_DEAL)
  if isinstance(started, Response):
    return started
  principal, body = started
  parent_id = parse_canonical(contact_id)
  key = parse_canonical(body["idempotency_key"])
  if parent_id is None or key is None:
    return await reject_input(request, principal, object_type=OBJECT_DEAL)

  context = context_of(request)
  scope = scope_of(principal)
  result = await create_for_contact(
    context.runner,
    context.clock,
    scope,
    contact_id=parent_id,
    submitted=body,
    key=key,
    correlation_id=current_correlation_id(),
  )
  if isinstance(result, Invalid):
    # The parent is re-resolved before the field errors are rendered, so a
    # foreign parent is the same 404 with a bad body as with a good one and
    # an archived one is the same 409 (ACCESS_MATRIX.md §1.1's order: scope,
    # then archived state, then the fields).
    parent = await parent_for_form(context.runner, scope, contact_id=parent_id)
    if isinstance(parent, Blocked):
      return await _blocked_response(request, parent)
    return render(
      request,
      "deals/form.html",
      _form_context(
        request,
        principal,
        mode="new",
        action_url=_create_url(request, parent.id),
        cancel_url=contact_url(request, parent.id),
        deal=_submitted_deal(body, deal_id=None, version=None),
        contact={"id": str(parent.id), "full_name": parent.full_name},
        errors=result.errors,
        idempotency_key=mint_key(),
      ),
      status_code=400,
    )
  if isinstance(result, Blocked):
    return await _blocked_response(request, result)
  if isinstance(result, Duplicate):
    return await _duplicate_response(request, result)
  return _applied_to_contact(request, result)


@router.get("/deals/{deal_id}", name="deal_detail")
async def deal_detail(request: Request, deal_id: str) -> Response:
  """Render one deal, with its stage control (``ACC-201``-``ACC-204``).

  Notes
  -----
  Readable under an archived parent, with ``can.edit`` and
  ``can.change_stage`` false and the control therefore absent (ask
  **A-8**): the archive hides a contact's deals from the **lists**, and
  making the record itself disappear would turn an archive into an erasure.
  """
  principal = await start_read(request)
  identifier = _deal_id(deal_id)
  context = context_of(request)
  view = await get_for_detail(context.runner, scope_of(principal), deal_id=identifier)
  page = base_context(
    page_title=view.title,
    principal=principal,
    csrf_token=csrf_token_for_request(request),
    private=True,
    nav_active="deals",
    scope_label=scope_label_for(principal),
    notice=notice_for(request, substitutions={"stage": view.stage_label}),
  )
  page.update(
    deal=_deal_context(view),
    contact=_contact_context(view),
    can={"edit": view.can_edit, "change_stage": view.can_change_stage},
    stage_form=stage_form_context(
      idempotency_key=mint_key(), version=view.version, stage=view.stage
    ),
    breadcrumb=_breadcrumb(request, view),
  )
  return render(request, "deals/detail.html", page)


@router.get("/deals/{deal_id}/edit", name="deal_edit")
async def deal_edit(request: Request, deal_id: str) -> Response:
  """Render the edit form for one deal — ``409`` under an archived parent.

  Notes
  -----
  Ask **A-8**: rendering a form whose ``POST`` could only ever answer 409
  ``archived_parent`` (``ACC-216``) invites a submission with one possible
  outcome, so the ``GET`` answers that 409 directly and offers the action
  that can actually unblock it — restoring the parent.

  The refusal sits **after** the scoped read, so the scope predicate still
  decides first and a foreign deal under an archived contact stays the
  ordinary ``404`` (``ACC-214``).
  """
  principal = await start_read(request)
  identifier = _deal_id(deal_id)
  context = context_of(request)
  scope = scope_of(principal)
  view = await get_for_detail(context.runner, scope, deal_id=identifier)
  if view.contact_is_archived:
    return await _blocked_response(
      request, await blocked_parent(context.runner, scope, contact_id=view.contact_id)
    )
  return render(
    request,
    "deals/form.html",
    _form_context(
      request,
      principal,
      mode="edit",
      action_url=deal_url(request, identifier),
      cancel_url=deal_url(request, identifier),
      deal=_stored_deal(view),
      contact={"id": str(view.contact_id), "full_name": view.contact_name},
      errors={},
      idempotency_key=mint_key(),
    ),
  )


@router.post("/deals/{deal_id}", name="deal_update")
async def deal_update(request: Request, deal_id: str) -> Response:
  """Edit one deal's three writable fields (``ACC-213``-``ACC-217``)."""
  started = await start_mutation(request, _EDIT_FIELDS, object_type=OBJECT_DEAL)
  if isinstance(started, Response):
    return started
  principal, body = started
  identifier = _deal_id(deal_id)
  version = positive_int(body["version"] or None, default=0)
  key = parse_canonical(body["idempotency_key"])
  if version is None or version < 1 or key is None:
    return await reject_input(request, principal, object_type=OBJECT_DEAL)

  context = context_of(request)
  scope = scope_of(principal)
  result = await update_deal(
    context.runner,
    context.clock,
    scope,
    deal_id=identifier,
    expected_version=version,
    submitted=body,
    key=key,
    correlation_id=current_correlation_id(),
  )
  if isinstance(result, Invalid):
    # Re-read first, for the same reason the create does: the scope
    # predicate and the parent's archive state both rank above a field
    # error (ACCESS_MATRIX.md §1.1).
    view = await get_for_detail(context.runner, scope, deal_id=identifier)
    if view.contact_is_archived:
      return await _blocked_response(
        request, await blocked_parent(context.runner, scope, contact_id=view.contact_id)
      )
    return render(
      request,
      "deals/form.html",
      _form_context(
        request,
        principal,
        mode="edit",
        action_url=deal_url(request, identifier),
        cancel_url=deal_url(request, identifier),
        deal=_submitted_deal(body, deal_id=str(identifier), version=version),
        contact={"id": str(view.contact_id), "full_name": view.contact_name},
        errors=result.errors,
        idempotency_key=mint_key(),
      ),
      status_code=400,
    )
  if isinstance(result, Stale):
    return await _stale_response(request, result, action_url=deal_url(request, identifier))
  if isinstance(result, Blocked):
    return await _blocked_response(request, result)
  if isinstance(result, Duplicate):
    return await _duplicate_response(request, result)
  return _applied_to_deal(request, result)


async def _move(
  request: Request, deal_id: str, *, to_stage: str | None, action_url_name: str
) -> Response:
  """Run one stage move — the body of the three stage routes.

  Parameters
  ----------
  request : Request
    The inbound request.
  deal_id : str
    The raw path segment.
  to_stage : str | None
    ``None`` on ``/stage``, where the target is a **body field** validated
    against the five; the literal target on ``/won`` and ``/lost``, where it
    is in the **path** — so a terminal move cannot be produced by editing a
    lateral form's hidden input, and those two routes have nothing to
    validate beyond the version and the key (§2(d)).
  action_url_name : str
    The route name "Keep my changes" re-posts to on a 409 ``stale``.

  Returns
  -------
  Response
  """
  fields = _TERMINAL_FIELDS if to_stage is not None else _STAGE_FIELDS
  started = await start_mutation(request, fields, object_type=OBJECT_DEAL)
  if isinstance(started, Response):
    return started
  principal, body = started
  identifier = _deal_id(deal_id)
  version = positive_int(body["version"] or None, default=0)
  key = parse_canonical(body["idempotency_key"])
  target = to_stage if to_stage is not None else body["to_stage"]
  if version is None or version < 1 or key is None or target not in _STAGES:
    # An out-of-enum `to_stage` is an allowlist rejection, not a graph
    # decision: §4.5 row 7, and the 400 never reaches the service.
    return await reject_input(request, principal, object_type=OBJECT_DEAL)

  context = context_of(request)
  result = await change_stage(
    context.runner,
    context.clock,
    scope_of(principal),
    deal_id=identifier,
    expected_version=version,
    to_stage=target,
    key=key,
    correlation_id=current_correlation_id(),
  )
  if isinstance(result, SameStage):
    # ACC-219: a no-op is not a mutation and gets no receipt — and no deny
    # row either, because it is a conflict decision about a row this actor
    # may see and not an input the allowlist refused (§2(a) note 7).
    return await bad_request(request)
  if isinstance(result, StageTerminal):
    return await _stage_terminal_response(request, result)
  if isinstance(result, Stale):
    action_url = str(request.app.url_path_for(action_url_name, deal_id=str(identifier)))
    return await _stale_response(request, result, action_url=action_url)
  if isinstance(result, Blocked):
    return await _blocked_response(request, result)
  if isinstance(result, Duplicate):
    return await _duplicate_response(request, result)
  return _applied_to_contact(request, result)


@router.post("/deals/{deal_id}/stage", name="deal_stage")
async def deal_stage(request: Request, deal_id: str) -> Response:
  """Move one deal to another stage (``ACC-218``-``ACC-223``).

  Notes
  -----
  ``to_stage`` accepts **all five** values (``ACC-218``: *"``to_stage`` from
  the enum"*): ``won``/``lost`` posted here behave exactly as the dedicated
  routes do. Narrowing the enum would make matrix-derived tests fail and
  buy nothing, because a crafted ``POST`` bypasses the ``<details>``
  confirmation either way — the real control is the server-side graph.
  """
  return await _move(request, deal_id, to_stage=None, action_url_name="deal_stage")


@router.post("/deals/{deal_id}/won", name="deal_won")
async def deal_won(request: Request, deal_id: str) -> Response:
  """Mark one deal won — a terminal move behind ``CP-28``'s confirmation (**R22**)."""
  return await _move(request, deal_id, to_stage="won", action_url_name="deal_won")


@router.post("/deals/{deal_id}/lost", name="deal_lost")
async def deal_lost(request: Request, deal_id: str) -> Response:
  """Mark one deal lost — a terminal move behind ``CP-29``'s confirmation (**R22**)."""
  return await _move(request, deal_id, to_stage="lost", action_url_name="deal_lost")
