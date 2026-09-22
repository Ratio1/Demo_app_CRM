"""The dashboard: three tiles and a recent list, from one read-only snapshot.

The context is ``totals``, ``recent_activities`` and ``is_empty``, and the
screen is three tiles with no fourth.

Two properties carry this module.

*Every number is the engine's.* ``contacts.count_visible``,
``deals.dashboard_totals`` and ``activities.recent_for_dashboard`` are three
statements under the same ownership predicate; nothing here counts a list,
sums an amount or filters a stage in Python. An
agent's tiles are their own records, an admin's are unfiltered, and the
difference is a SQL conjunct that is present or absent — never a boolean
passed into one statement.

*The three statements share one snapshot.* They run inside a single
``SERIALIZABLE, READ ONLY`` transaction (the shape ``deals.pipeline``
already uses), because the tiles and the list are read side by side: at
``READ COMMITTED`` a deal won between two statements shows as a total that
disagrees with the history under it. Read-only is a property of the
transaction — a write inside it is refused with ``25006`` — not of this
module's good behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.db.repositories import activities as activities_repo
from app.db.repositories import contacts as contacts_repo
from app.db.repositories import deals as deals_repo
from app.services.activities import RecentItemView, recent_item

if TYPE_CHECKING:
  from decimal import Decimal

  from app.db.pool import PoolConnection
  from app.db.retry import TransactionRunner
  from app.security.principal import Scope

__all__ = ["DashboardView", "Totals", "dashboard"]


@dataclass(frozen=True, slots=True)
class Totals:
  """The dashboard's ``totals`` — five numbers, three tiles."""

  visible_contacts: int
  open_count: int
  open_amount: Decimal
  won_count: int
  won_amount: Decimal


@dataclass(frozen=True, slots=True)
class DashboardView:
  """The whole screen: the tiles, the recent list and whether it is all empty."""

  totals: Totals
  recent_activities: tuple[RecentItemView, ...]
  is_empty: bool


async def dashboard(runner: TransactionRunner, scope: Scope) -> DashboardView:
  """Read the dashboard for one principal, in one read-only snapshot.

  Parameters
  ----------
  runner : TransactionRunner
    The process runner.
  scope : Scope
    The viewer's scope, applied inside all three statements.

  Returns
  -------
  DashboardView
    ``is_empty`` is true only when this principal has no visible contact, no
    open or won deal and no activity at all — the state the screen's
    "nothing here yet" panel is for. It is derived from the numbers the
    engine returned, so it can never disagree with the tiles beside it.
  """

  async def _read(conn: PoolConnection) -> DashboardView:
    visible_contacts = await contacts_repo.count_visible(conn, scope)
    totals = await deals_repo.dashboard_totals(conn, scope)
    recent = await activities_repo.recent_for_dashboard(
      conn, scope, limit=activities_repo.RECENT_LIMIT
    )
    items = tuple(recent_item(row) for row in recent)
    return DashboardView(
      totals=Totals(
        visible_contacts=visible_contacts,
        open_count=totals.open_count,
        open_amount=totals.open_amount,
        won_count=totals.won_count,
        won_amount=totals.won_amount,
      ),
      recent_activities=items,
      is_empty=(
        visible_contacts == 0 and totals.open_count == 0 and totals.won_count == 0 and not items
      ),
    )

  return await runner.read_only_serializable(_read, op="dashboard")
