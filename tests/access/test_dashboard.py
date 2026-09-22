"""``GET /dashboard`` — plan §4 task 6: totals against independently computed fixtures.

Every total below is computed **in this file**, from `Decimal` arithmetic
over the exact rows this test inserted through the real HTTP surface —
never copied from what the page itself renders — so a bug that miscounts
or mis-sums on the server side cannot also make the test agree with it.

Two traps this file works around (see each test's own note): `is_empty`
hides the tiles entirely for a principal with nothing visible, and the
admin's dashboard sums **every** row in the shared `crm_test` database, so
an admin assertion is a **delta** across a fixture insert, never an
absolute number.
"""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

import httpx
import pytest
from conftest import (
  LoggedInPrincipal,
  ProvisionedUser,
  create_contact,
  create_deal,
  extract_csrf_token,
  extract_hidden_field,
  extract_scoped_hidden_field,
  login_via_http,
)

pytestmark = pytest.mark.asyncio

_FAR_FUTURE_DATE = "2099-01-01"

_CONTACTS_TILE = re.compile(r'Contacts</p>\s*<p class="stat-tile-value">(\d+)</p>')
_OPEN_TILE = re.compile(
  r'Open deals</p>\s*<p class="stat-tile-value">(\d+)</p>\s*'
  r'<p class="stat-tile-note">€\s*([\d,]+\.\d{2})'
)
_WON_TILE = re.compile(
  r'Won deals</p>\s*<p class="stat-tile-value">(\d+)</p>\s*'
  r'<p class="stat-tile-note">€\s*([\d,]+\.\d{2})'
)


class DashboardTotals:
  """The three tiles, parsed off a rendered `dashboard.html`, never off the app's own numbers."""

  def __init__(self, html: str) -> None:
    contacts_match = _CONTACTS_TILE.search(html)
    open_match = _OPEN_TILE.search(html)
    won_match = _WON_TILE.search(html)
    assert contacts_match is not None, "no Contacts tile found — is_empty may be hiding it"
    assert open_match is not None, "no Open deals tile found — is_empty may be hiding it"
    assert won_match is not None, "no Won deals tile found — is_empty may be hiding it"
    self.visible_contacts = int(contacts_match.group(1))
    self.open_count = int(open_match.group(1))
    self.open_amount = Decimal(open_match.group(2).replace(",", ""))
    self.won_count = int(won_match.group(1))
    self.won_amount = Decimal(won_match.group(2).replace(",", ""))


async def _dashboard(principal: LoggedInPrincipal) -> DashboardTotals:
  response = await principal.client.get("/dashboard")
  assert response.status_code == 200
  return DashboardTotals(response.text)


async def _mark_deal_won(principal: LoggedInPrincipal, *, deal_id: str) -> None:
  """Drive `POST /deals/{id}/won` for a deal still at its first version."""
  detail = await principal.client.get(f"/deals/{deal_id}")
  assert detail.status_code == 200
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  version = extract_hidden_field(detail.text, "version")
  response = await principal.client.post(
    f"/deals/{deal_id}/won",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert response.status_code == 303, f"marking the deal won failed: {response.status_code}"


async def _archive_contact_scoped(principal: LoggedInPrincipal, *, contact_id: str) -> None:
  """Archive `contact_id`, reading `version` from the archive form specifically.

  `tests/conftest.py`'s shared `archive_contact` reads `version` with
  `extract_hidden_field` (the *first* match anywhere on the page), which is
  only correct when the contact carries no deal card of its own — a deal's
  stage-control form also carries a `version` hidden field, and once that
  deal has been mutated (moved, won) its `version` no longer equals the
  contact's. This dashboard fixture deliberately builds contacts that
  already own a mutated deal, so it scopes the read to the archive form's
  own `<form action="/contacts/{id}/archive">` instead.
  """
  detail = await principal.client.get(f"/contacts/{contact_id}")
  assert detail.status_code == 200
  csrf_token = extract_csrf_token(detail.text)
  form_action = f"/contacts/{contact_id}/archive"
  idempotency_key = extract_scoped_hidden_field(
    detail.text, form_action=form_action, name="idempotency_key"
  )
  version = extract_scoped_hidden_field(detail.text, form_action=form_action, name="version")
  response = await principal.client.post(
    form_action,
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert response.status_code == 303, f"archiving the contact failed: {response.status_code}"


async def _forced_reset_client(http_client_factory: Any, provision_agent: Any) -> httpx.AsyncClient:
  """Log in a freshly provisioned agent but skip the forced password change."""
  user: ProvisionedUser = provision_agent()
  client: httpx.AsyncClient = http_client_factory()
  login_response = await login_via_http(client, email=user.email, password=user.password)
  assert login_response.status_code == 303
  assert login_response.headers.get("location") == "/account/password"
  return client


# ---------------------------------------------------------------------------
# Totals: independently computed per agent, admin checked as a delta.
# ---------------------------------------------------------------------------


async def test_agent_dashboard_totals_match_independently_computed_fixtures(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """Each agent's tiles equal exactly what this test built for them, and nothing of the other's.

  Agent A: two visible contacts (one carries three deals — one marked
  `won` at 1250.00, two left open at 99.99 and 300.01 — the other carries
  none) plus a third contact, archived, whose own deal must be excluded
  from both the visible-contact count and the deal totals (`c.archived_at
  IS NULL` in both `contacts.count_visible` and `deals.dashboard_totals`).
  Agent B: one visible contact, one open deal at 42.00.
  """
  contact_a1 = await create_contact(agent_a, name="Dashboard A1", email=None)
  won_deal = await create_deal(
    agent_a, contact_id=contact_a1.id, title="A1 won deal", amount="1250.00"
  )
  await create_deal(agent_a, contact_id=contact_a1.id, title="A1 open deal one", amount="99.99")
  await create_deal(agent_a, contact_id=contact_a1.id, title="A1 open deal two", amount="300.01")
  await _mark_deal_won(agent_a, deal_id=won_deal.id)

  await create_contact(agent_a, name="Dashboard A2", email=None)

  contact_a3 = await create_contact(agent_a, name="Dashboard A3 Archived", email=None)
  await create_deal(agent_a, contact_id=contact_a3.id, title="A3 excluded deal", amount="777.00")
  await _archive_contact_scoped(agent_a, contact_id=contact_a3.id)

  contact_b1 = await create_contact(agent_b, name="Dashboard B1", email=None)
  await create_deal(agent_b, contact_id=contact_b1.id, title="B1 open deal", amount="42.00")

  totals_a = await _dashboard(agent_a)
  assert totals_a.visible_contacts == 2
  assert totals_a.open_count == 2
  assert totals_a.open_amount == Decimal("99.99") + Decimal("300.01")
  assert totals_a.won_count == 1
  assert totals_a.won_amount == Decimal("1250.00")

  totals_b = await _dashboard(agent_b)
  assert totals_b.visible_contacts == 1
  assert totals_b.open_count == 1
  assert totals_b.open_amount == Decimal("42.00")
  assert totals_b.won_count == 0
  assert totals_b.won_amount == Decimal("0.00")


async def test_admin_dashboard_totals_are_the_sum_over_everyone_measured_as_a_delta(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """Admin's tiles include both agents' records — asserted as a delta, never an absolute number.

  `crm_test` is shared across the whole session, so an admin's dashboard
  sums whatever every other test module has already left in it; only the
  *change* this test's own fixture insert produces is independently
  computable here.
  """
  before = await _dashboard(admin)

  contact_a = await create_contact(agent_a, name="Admin Delta A", email=None)
  await create_deal(agent_a, contact_id=contact_a.id, title="Admin delta A open", amount="123.45")
  won_deal = await create_deal(
    agent_a, contact_id=contact_a.id, title="Admin delta A won", amount="1000.00"
  )
  await _mark_deal_won(agent_a, deal_id=won_deal.id)

  contact_b = await create_contact(agent_b, name="Admin Delta B", email=None)
  await create_deal(agent_b, contact_id=contact_b.id, title="Admin delta B open", amount="10.55")

  after = await _dashboard(admin)

  assert after.visible_contacts - before.visible_contacts == 2
  assert after.open_count - before.open_count == 2
  assert after.open_amount - before.open_amount == Decimal("123.45") + Decimal("10.55")
  assert after.won_count - before.won_count == 1
  assert after.won_amount - before.won_amount == Decimal("1000.00")


# ---------------------------------------------------------------------------
# is_empty: a brand-new agent with nothing visible gets the empty state, not
# zero-valued tiles.
# ---------------------------------------------------------------------------


async def test_dashboard_is_empty_state_for_a_fresh_agent_with_nothing_visible(
  agent_a: LoggedInPrincipal,
) -> None:
  """A freshly provisioned agent with nothing visible gets the "Nothing here yet" panel."""
  response = await agent_a.client.get("/dashboard")
  assert response.status_code == 200
  assert "Nothing here yet" in response.text
  assert _CONTACTS_TILE.search(response.text) is None, "the tiles must not render in is_empty"


# ---------------------------------------------------------------------------
# recent_activities: scoped like every other list, and dropped when the
# parent contact is archived.
# ---------------------------------------------------------------------------


async def test_dashboard_recent_activities_are_scoped(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """Agent A sees their own recent activity; agent B does not; admin sees it too.

  Agent B is given a contact of their own first: with nothing visible at
  all, B's dashboard collapses to the ``is_empty`` panel, and the
  recent-activities section (and its ``summary`` text) would then be
  absent for that reason rather than because the scope predicate excluded
  A's row — the same trap the totals tests above work around. Asserting
  ``id="h-recent"`` alongside proves the section actually rendered.
  """
  contact = await create_contact(agent_a, name="Recent Scoped Contact", email=None)
  detail = await agent_a.client.get(f"/contacts/{contact.id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_scoped_hidden_field(
    detail.text, form_action="/activities", name="idempotency_key"
  )
  summary = "Dashboard recent-list scope probe."
  logged = await agent_a.client.post(
    "/activities",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "contact_id": contact.id,
      "kind": "note",
      "occurred_on": _FAR_FUTURE_DATE,
      "summary": summary,
    },
  )
  assert logged.status_code == 303

  await create_contact(agent_b, name="Recent Scoped B Own Contact", email=None)

  own_response = await agent_a.client.get("/dashboard")
  assert summary in own_response.text

  foreign_response = await agent_b.client.get("/dashboard")
  assert 'id="h-recent"' in foreign_response.text, "B's own recent section must still render"
  assert summary not in foreign_response.text

  admin_response = await admin.client.get("/dashboard")
  assert summary in admin_response.text


async def test_dashboard_recent_activities_drop_when_the_parent_is_archived(
  agent_a: LoggedInPrincipal,
) -> None:
  """An activity under an archived contact drops from the recent list (`c.archived_at IS NULL`).

  A second, never-archived contact is created first: without it,
  archiving the only contact this agent owns also drops
  ``visible_contacts`` to zero, which collapses the whole page to the
  ``is_empty`` panel — the recent section (and the summary text with it)
  would then be absent regardless of whether the archive-scoping clause
  did anything. ``id="h-recent"`` is asserted to prove the section itself
  is still rendering.
  """
  await create_contact(agent_a, name="Recent Archive-Drop Survivor Contact", email=None)
  contact = await create_contact(agent_a, name="Recent Archive-Drop Contact", email=None)
  detail = await agent_a.client.get(f"/contacts/{contact.id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_scoped_hidden_field(
    detail.text, form_action="/activities", name="idempotency_key"
  )
  summary = "Dashboard archive-drop probe."
  logged = await agent_a.client.post(
    "/activities",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "contact_id": contact.id,
      "kind": "note",
      "occurred_on": _FAR_FUTURE_DATE,
      "summary": summary,
    },
  )
  assert logged.status_code == 303

  before_archive = await agent_a.client.get("/dashboard")
  assert summary in before_archive.text

  await _archive_contact_scoped(agent_a, contact_id=contact.id)

  after_archive = await agent_a.client.get("/dashboard")
  assert 'id="h-recent"' in after_archive.text, "the recent section must still render"
  assert summary not in after_archive.text


# ---------------------------------------------------------------------------
# Cheap access cells: the redirect from `/`, the anon redirect, forced-reset.
# ---------------------------------------------------------------------------


async def test_root_redirects_signed_in_user_to_dashboard(agent_a: LoggedInPrincipal) -> None:
  """`GET /` is `303 /dashboard` for a signed-in agent — the 404 the plan names first."""
  response = await agent_a.client.get("/")
  assert response.status_code == 303
  assert response.headers.get("location") == "/dashboard"
  dashboard_response = await agent_a.client.get("/dashboard")
  assert dashboard_response.status_code == 200


async def test_anonymous_dashboard_request_redirects_to_login(
  anon_client: httpx.AsyncClient,
) -> None:
  """A session-less `GET /dashboard` is `303 /login...`, never a 404 or a 500."""
  response = await anon_client.get("/dashboard")
  assert response.status_code == 303
  assert response.headers.get("location", "").split("?", 1)[0] == "/login"


async def test_forced_reset_cannot_reach_the_dashboard(
  http_client_factory: Any, provision_agent: Any
) -> None:
  """`FRST` gets `403` on `GET /dashboard` — the forced-reset gate, not a field error."""
  forced_client = await _forced_reset_client(http_client_factory, provision_agent)
  response = await forced_client.get("/dashboard")
  assert response.status_code == 403
