"""``GET /dashboard`` — the screen ``/`` and the nav wordmark already point at.

Three tiles and a recent-activity list: no fourth tile, and no charts.

There is nothing to validate: the screen takes no query parameter, no sort
and no page, so the handler is ``start_read`` plus one service call. What it
must get right is the scope — and that is not decided here at all: the three
statements behind :func:`app.services.dashboard.dashboard` carry the
ownership conjunct themselves, so an agent's tiles count their own records
because of the SQL, not because of anything this module does.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import Response

from app.routes.pipeline import start_read
from app.routes.rendering import (
  base_context,
  csrf_token_for_request,
  notice_for,
  render,
  scope_label_for,
)
from app.security.context import context_of
from app.security.principal import scope_of
from app.services.dashboard import dashboard

if TYPE_CHECKING:
  from app.services.activities import RecentItemView
  from app.services.dashboard import DashboardView

__all__ = ["router"]

router = APIRouter()


def _recent_context(request: Request, items: tuple[RecentItemView, ...]) -> list[dict[str, Any]]:
  """Build ``recent_activities`` — the rendered keys, plus the contact's URL.

  Notes
  -----
  ``contact_owner_name`` is in the frozen shape and the template renders it
  for an **admin only**: an agent sees only their own records, so repeating
  their own name on every row would be noise, and no other owner's name can
  reach an agent's page anyway — the statement's predicate saw to that.
  """
  return [
    {
      "id": str(item.id),
      "contact_id": str(item.contact_id),
      "contact_url": str(
        request.app.url_path_for("contact_detail", contact_id=str(item.contact_id))
      ),
      "contact_name": item.contact_name,
      "contact_owner_name": item.contact_owner_name,
      "kind": item.kind,
      "kind_label": item.kind_label,
      "occurred_on": item.occurred_on,
      "summary": item.summary,
      "author_name": item.author_name,
    }
    for item in items
  ]


def _totals_context(view: DashboardView) -> dict[str, Any]:
  """Build ``totals`` — the five numbers exactly as the engine returned them."""
  return {
    "visible_contacts": view.totals.visible_contacts,
    "open_count": view.totals.open_count,
    "open_amount": view.totals.open_amount,
    "won_count": view.totals.won_count,
    "won_amount": view.totals.won_amount,
  }


@router.get("/dashboard", name="dashboard")
async def dashboard_page(request: Request) -> Response:
  """Render the three tiles and the recent-activity list.

  Notes
  -----
  ``GET /`` redirects here (``app/routes/auth.py``) and the nav wordmark
  links here from every private page, so this route is the landing screen
  for every signed-in session.
  """
  principal = await start_read(request)
  context = context_of(request)
  view = await dashboard(context.runner, scope_of(principal))
  page = base_context(
    page_title="Dashboard",
    principal=principal,
    csrf_token=csrf_token_for_request(request),
    private=True,
    nav_active="dashboard",
    scope_label=scope_label_for(principal),
    notice=notice_for(request),
  )
  page.update(
    totals=_totals_context(view),
    recent_activities=_recent_context(request, view.recent_activities),
    is_empty=view.is_empty,
  )
  return render(request, "dashboard.html", page)
