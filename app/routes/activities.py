"""``POST /activities`` and the ``#timeline`` fragment.

An activity has no ``GET`` route of its own: the form lives inside
``contacts/detail.html``, and so does the timeline it appends to.

The form posts from that page: it posts
to **``/activities``** with the parent in a hidden ``contact_id`` field, so
the path carries no id and the body does. That is the one place this
surface differs from the deal create, and it changes exactly one thing —
the parent is an **input**, so a non-canonical ``contact_id`` is the
crafted-request ``400`` rather than a path 404, while a well-formed foreign
or missing one is the identical ``404`` the scoped read produces.

The handler order is ``start_mutation``'s, unchanged: session, body, CSRF,
content type, budget, forced-reset gate, body allowlist. Nothing on the
workspace is authorization — ``can.add_activity`` hides a control, and the
service re-decides every one of them server-side inside the transaction.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import Response

from app.logging import current_correlation_id
from app.routes.contacts import detail_page_context
from app.routes.errors import conflict, redirect
from app.routes.pipeline import (
  is_fragment_request,
  positive_int,
  query_value,
  reject_input,
  start_mutation,
  start_read,
)
from app.routes.rendering import render
from app.security.context import context_of
from app.security.idempotency import parse_canonical
from app.security.principal import scope_of
from app.services.activities import Duplicate, Invalid, log_activity
from app.services.deals import Blocked, parent_for_form

if TYPE_CHECKING:
  from uuid import UUID

  from app.services.activities import Applied

__all__ = ["router"]

router = APIRouter()

#: The form's exact accepted set, matching ``contacts/detail.html``.
#: Anything else in the body is a crafted request and a ``400``, never an
#: ignored field: silence makes mass assignment untestable. ``created_by_user_id`` is absent because
#: the author is the session, and ``id`` because ids are generated server-side.
_CREATE_FIELDS: Final[frozenset[str]] = frozenset(
  {"csrf_token", "idempotency_key", "contact_id", "kind", "occurred_on", "summary"}
)

#: The timeline fragment's one allowlisted query key. Every other name is
#: dropped before any check; a repeated ``page`` is a ``400``.
_PAGE_KEY: Final = "page"


def _contact_url(request: Request, contact_id: UUID) -> str:
  """Return the relative ``/contacts/{id}`` path, from the route name."""
  return str(request.app.url_path_for("contact_detail", contact_id=str(contact_id)))


def _applied_redirect(request: Request, result: Applied) -> Response:
  """Turn an :class:`~app.services.activities.Applied` into its ``303``.

  Notes
  -----
  The destination is fixed:
  ``/contacts/{id}?notice=activity_logged#timeline`` — the workspace, with
  the region anchored, on a first submission and on a replay alike. The URL
  is rebuilt from the route name and the allowlisted notice code; nothing is
  stored, and no free text travels in it.
  """
  return redirect(
    f"{_contact_url(request, result.contact_id)}?notice={result.notice}#timeline", request
  )


async def _blocked_response(request: Request, result: Blocked) -> Response:
  """Render ``errors/409.html`` ``context="archived_parent"``."""
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
        # Logging against an archived contact is always "restore it first",
        # never "that has already been done" — the same two keys the deal
        # routes pass.
        "body": "cp_13",
        "state": "archived",
      }
    },
  )


async def _duplicate_response(request: Request, result: Duplicate) -> Response:
  """Render ``errors/409.html`` ``context="duplicate"``."""
  return await conflict(
    request,
    context="duplicate",
    extra={"duplicate": {"record_url": f"{_contact_url(request, result.contact_id)}#timeline"}},
  )


@router.post("/activities", name="activity_create")
async def activity_create(request: Request) -> Response:
  """Append one activity to one contact's history.

  Notes
  -----
  A field error re-renders the **workspace**, not a form page of its own:
  an activity has no ``GET`` route, so the form exists only inside
  ``contacts/detail.html`` and that is where the error
  summary has to appear. The re-render goes through the contact route's own
  context builder, which re-reads the contact under the scope predicate — so
  a bad body against a foreign contact is still the identical 404, and the
  submitted values are echoed back into the form rather than lost.
  """
  started = await start_mutation(request, _CREATE_FIELDS)
  if isinstance(started, Response):
    return started
  principal, body = started
  key = parse_canonical(body["idempotency_key"])
  parent_id = parse_canonical(body["contact_id"])
  if key is None or parent_id is None:
    return await reject_input(request, principal)

  context = context_of(request)
  result = await log_activity(
    context.runner,
    context.clock,
    scope_of(principal),
    contact_id=parent_id,
    submitted=body,
    key=key,
    correlation_id=current_correlation_id(),
  )
  if isinstance(result, Invalid):
    # The pipeline's check order, applied to the one path the service
    # cannot apply it on: validation runs before the transaction opens, so a
    # bad body under an ARCHIVED parent would otherwise re-render a workspace
    # whose add-activity form is hidden — an error summary linking to fields
    # that are not on the page. `parent_for_form` is the deal create's own
    # resolver and the same statement, so the archived answer is identical on
    # both surfaces, and a foreign parent still raises ContactNotFound first.
    parent = await parent_for_form(context.runner, scope_of(principal), contact_id=parent_id)
    if isinstance(parent, Blocked):
      return await _blocked_response(request, parent)
    page = await detail_page_context(
      request,
      principal,
      contact_id=parent_id,
      activity_errors=result.errors,
      activity_values=result.values,
    )
    return render(request, "contacts/detail.html", page, status_code=400)
  if isinstance(result, Blocked):
    return await _blocked_response(request, result)
  if isinstance(result, Duplicate):
    return await _duplicate_response(request, result)
  return _applied_redirect(request, result)


@router.get("/contacts/{contact_id}/timeline", name="contact_timeline")
async def contact_timeline(request: Request, contact_id: str) -> Response:
  """Serve one page of the ``#timeline`` region — fragment or whole workspace.

  Notes
  -----
  One route, two renderings, exactly as ``GET /contacts`` serves
  ``#contact-results``: an htmx
  fragment gets ``partials/timeline.html``, anything else gets the full
  ``contacts/detail.html`` **with the timeline already on the requested
  page**. The full render is what makes ``hx-push-url="true"`` safe — this
  URL enters the history, and a Back or a refresh must not produce a bare
  partial on screen as the whole document.

  A history-restore request is deliberately **not** a fragment
  (:func:`~app.routes.pipeline.is_fragment_request`): htmx 2.0.10 swaps that
  response into the history element with ``innerHTML``.

  The contact id is a **path** segment here, as on every other contact
  surface, so a non-canonical one is the crafted-request ``400`` its
  siblings answer — ``GET /contacts/{id}`` itself answers 404, and the
  difference is deliberate: this route's id reaches a region, not a page.
  """
  principal = await start_read(request)
  identifier = parse_canonical(contact_id)
  if identifier is None:
    return await reject_input(request, principal)

  ok, raw_page = query_value(request, _PAGE_KEY)
  if not ok:
    return await reject_input(request, principal)
  page_number = positive_int(raw_page, default=1)
  if page_number is None:
    return await reject_input(request, principal)

  fragment = is_fragment_request(request)
  page = await detail_page_context(
    request, principal, contact_id=identifier, timeline_page=page_number
  )
  template = "partials/timeline.html" if fragment else "contacts/detail.html"
  return render(request, template, page)
