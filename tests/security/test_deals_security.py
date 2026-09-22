"""Slice C deal-surface security — SEC-001/002/005/006/076 on deals, money, CSRF, R67, R69.

Authority: ``ACCESS_MATRIX.md`` §7 (the IDs below), §5.1/§5.2 (writable
fields, sort/filter allowlists), §4.5 row 5 (the forced-reset deny-audit
triple, R67); ``contracts/slice-c.md`` §2(a) (``app/services/money.py``,
the amount classification order and `CP-69*` copy ids), §2(c) (route
table, CSRF on every mutating POST), §2(f) (R67 as a Slice C backend
task), §1(f)/§2(g) hook 5 (the money parametrized table).

Reuses ``tests/conftest.py``'s three-principal fixtures and Slice C's
``create_deal`` helper rather than duplicating it — this module is about a
different axis of the same deal surface (injection/allowlist/XSS/CSRF/
money), not a different fixture story. Nothing here can pass before
``app/routes/deals.py`` and ``app/services/money.py`` ship.

The money tests below drive the **shipped** ``app.services.money`` module
directly (it landed mid-session — see ``AmountError.message`` and the
``CP_##`` string constants it exports) rather than an assumed shape.

R70 (the cookieless-vs-presented-cookie 401 fragment body) needs
``ManualClock`` control for its "presented but dead" half and therefore
lives in ``tests/inprocess/test_deals_error_context.py`` (the transport
``ACC-037`` itself uses), not here; see that module for both halves.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from conftest import (
  LoggedInPrincipal,
  create_contact,
  create_deal,
  extract_csrf_token,
  extract_hidden_field,
  fresh_idempotency_key,
)

pytestmark = pytest.mark.asyncio

_CONTACT_FIELDS = {
  "name": "Deal Security Contact",
  "company": "Acme Corp",
  "phone": "+1 555 0202",
  "kind": "lead",
}


async def _own_contact(agent: LoggedInPrincipal) -> str:
  """Create a fresh, active contact owned by ``agent`` and return its id."""
  contact = await create_contact(agent, **_CONTACT_FIELDS)
  return contact.id


# ---------------------------------------------------------------------------
# R68 — the two DB-shared global rate buckets are clean at the start of this
# module (the module-scoped autouse fixture in tests/conftest.py ran first).
# Deliberately the FIRST test defined in this file: pytest runs a module's
# tests in source order, and this assertion is only meaningful before any
# OTHER test in this same module has itself logged in and nudged the
# counters — a later position would observe this module's own traffic, not
# the fixture's effect. R68's fixture is module-scoped, so it reruns (and
# re-clears) once per file regardless of what an EARLIER module left behind.
# ---------------------------------------------------------------------------


async def test_r68_global_rate_buckets_are_clear_at_module_start(db_connection: Any) -> None:
  """`login_global`/`preauth_global` carry no leftover counter rows from an earlier module."""
  cursor = await db_connection.execute(
    "SELECT count(*) FROM rate_budget WHERE bucket IN ('login_global', 'preauth_global')"
  )
  row = await cursor.fetchone()
  assert row is not None
  assert int(row[0]) == 0, (
    "the R68 module-scoped autouse fixture should have cleared both global buckets "
    "before this module's first test ran"
  )


# ---------------------------------------------------------------------------
# SEC-001 — SQLi corpus in deal fields changes no query semantics.
# ---------------------------------------------------------------------------

_SQLI_CORPUS: tuple[str, ...] = (
  "'; DROP TABLE deals; --",
  "' OR '1'='1",
  "1; SELECT pg_sleep(5)--",
)


@pytest.mark.parametrize("payload", _SQLI_CORPUS)
async def test_sec001_sqli_corpus_in_deal_title_changes_no_query_semantics(
  agent_a: LoggedInPrincipal, payload: str
) -> None:
  """An SQLi payload in `title` is inert data: never a `500`, never echoed unescaped."""
  contact_id = await _own_contact(agent_a)
  new_form = await agent_a.client.get(f"/contacts/{contact_id}/deals/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  response = await agent_a.client.post(
    f"/contacts/{contact_id}/deals",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "title": payload,
      "amount": "10.00",
      "close_date": "",
    },
  )
  assert response.status_code != 500
  assert payload not in response.text


@pytest.mark.parametrize("payload", _SQLI_CORPUS)
async def test_sec001_sqli_corpus_in_deal_search_q_changes_no_query_semantics(
  agent_a: LoggedInPrincipal, payload: str
) -> None:
  """An SQLi payload in `/deals?q=` never produces a `500` and never widens the result set."""
  response = await agent_a.client.get("/deals", params={"q": payload})
  assert response.status_code == 200


# ---------------------------------------------------------------------------
# SEC-002 / ACC-307-309 (allowlists) — SEC-076 twin for the deal surfaces.
# ---------------------------------------------------------------------------


async def test_sec076_a_repeated_allowlisted_deal_query_parameter_is_400(
  agent_a: LoggedInPrincipal,
) -> None:
  """`?sort=title&sort=amount` on `/deals` is `400`, never first-wins or last-wins."""
  response = await agent_a.client.get("/deals?sort=title&sort=amount")
  assert response.status_code == 400


async def test_sec076_an_unknown_repeated_deal_query_parameter_is_ignored(
  agent_a: LoggedInPrincipal,
) -> None:
  """An unrepeated **unknown** name is dropped before duplicates are ever counted (H-08)."""
  response = await agent_a.client.get("/deals?utm_source=x&utm_source=y")
  assert response.status_code == 200


async def test_sec076_a_repeated_form_field_on_deal_create_is_400(
  agent_a: LoggedInPrincipal,
) -> None:
  """A repeated `title` form field on `POST /contacts/{id}/deals` is `400`."""
  contact_id = await _own_contact(agent_a)
  new_form = await agent_a.client.get(f"/contacts/{contact_id}/deals/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  response = await agent_a.client.post(
    f"/contacts/{contact_id}/deals",
    content=(
      f"csrf_token={csrf_token}&idempotency_key={idempotency_key}"
      "&title=First&title=Second&amount=10.00&close_date="
    ),
    headers={"content-type": "application/x-www-form-urlencoded"},
  )
  assert response.status_code == 400


async def test_deal_list_pipeline_status_filter_outside_allowlist_is_400(
  agent_a: LoggedInPrincipal,
) -> None:
  """`?status=` outside `{active, archived, all}` is `400` on both list and pipeline."""
  list_response = await agent_a.client.get("/deals?status=deleted")
  assert list_response.status_code == 400
  pipeline_response = await agent_a.client.get("/deals/pipeline?status=deleted")
  assert pipeline_response.status_code == 400


async def test_pipeline_allowlists_no_sort_key_an_unknown_one_is_ignored(
  agent_a: LoggedInPrincipal,
) -> None:
  """`/deals/pipeline` allowlists `status` only — an unknown `?sort=` there is ignored, not 400."""
  response = await agent_a.client.get("/deals/pipeline?sort=amount")
  assert response.status_code == 200


# ---------------------------------------------------------------------------
# SEC-005 — a stored and a reflected XSS corpus render inert, on the deal
# list, pipeline and detail.
# ---------------------------------------------------------------------------

_XSS_CORPUS: tuple[str, ...] = (
  "<script>alert(1)</script>",
  '"><img src=x onerror=alert(1)>',
  "<svg onload=alert(1)>",
)


@pytest.mark.parametrize("payload", _XSS_CORPUS)
async def test_sec005_xss_in_deal_title_renders_inert_everywhere(
  agent_a: LoggedInPrincipal, payload: str
) -> None:
  """A hostile `title` survives create, then renders escaped on list, pipeline and detail."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id, title=payload)
  detail = await agent_a.client.get(f"/deals/{deal.id}")
  assert detail.status_code == 200
  assert payload not in detail.text
  listing = await agent_a.client.get("/deals")
  assert payload not in listing.text
  pipeline = await agent_a.client.get("/deals/pipeline")
  assert payload not in pipeline.text


async def test_sec006_a_hostile_deal_title_never_reaches_an_hx_attribute_value(
  agent_a: LoggedInPrincipal,
) -> None:
  """A value built to break out of an `hx-*` attribute never appears unescaped near one."""
  contact_id = await _own_contact(agent_a)
  payload = '"><b hx-get="/deals/evil">breakout</b>'
  await create_deal(agent_a, contact_id=contact_id, title=payload)
  listing = await agent_a.client.get("/deals")
  assert payload not in listing.text


# ---------------------------------------------------------------------------
# PIN C1's money parser is a pure-Python unit and has no `await` in it at
# all, so it lives in its own module, `tests/unit/test_money.py` — matching
# `tests/unit/test_password_policy.py`'s convention and avoiding a spurious
# `PytestWarning: marked with '@pytest.mark.asyncio' but it is not an async
# function` on every one of its cases under this file's module-level
# `pytestmark`.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# CSRF on every new Slice C mutating POST (SEC-020 twin, one per route).
# ---------------------------------------------------------------------------


async def test_csrf_missing_token_is_403_on_every_deal_mutation(agent_a: LoggedInPrincipal) -> None:
  """Every one of Slice C's five mutating POSTs is `403` with `csrf_token` omitted entirely."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)

  create_response = await agent_a.client.post(
    f"/contacts/{contact_id}/deals",
    data={
      "idempotency_key": fresh_idempotency_key(),
      "title": "x",
      "amount": "1.00",
      "close_date": "",
    },
  )
  assert create_response.status_code == 403

  update_response = await agent_a.client.post(
    f"/deals/{deal.id}",
    data={
      "idempotency_key": fresh_idempotency_key(),
      "version": "1",
      "title": "x",
      "amount": "1.00",
      "close_date": "",
    },
  )
  assert update_response.status_code == 403

  for suffix in ("stage", "won", "lost"):
    data = {"idempotency_key": fresh_idempotency_key(), "version": "1"}
    if suffix == "stage":
      data["to_stage"] = "qualified"
    response = await agent_a.client.post(f"/deals/{deal.id}/{suffix}", data=data)
    assert response.status_code == 403, f"POST /deals/{{id}}/{suffix} without csrf_token"


async def test_csrf_stale_token_is_403_on_every_deal_mutation(
  agent_a: LoggedInPrincipal,
) -> None:
  """Every one of Slice C's five mutating POSTs is `403` with a plausible but wrong token."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  wrong_token = "0" * 64

  create_response = await agent_a.client.post(
    f"/contacts/{contact_id}/deals",
    data={
      "csrf_token": wrong_token,
      "idempotency_key": fresh_idempotency_key(),
      "title": "x",
      "amount": "1.00",
      "close_date": "",
    },
  )
  assert create_response.status_code == 403

  for suffix in ("stage", "won", "lost"):
    data = {"csrf_token": wrong_token, "idempotency_key": fresh_idempotency_key(), "version": "1"}
    if suffix == "stage":
      data["to_stage"] = "qualified"
    response = await agent_a.client.post(f"/deals/{deal.id}/{suffix}", data=data)
    assert response.status_code == 403, f"POST /deals/{{id}}/{suffix} with a wrong csrf_token"


# ---------------------------------------------------------------------------
# R67 — the forced-reset deny-audit row (`authz.py::deny_forced_reset`).
# ---------------------------------------------------------------------------


async def test_r67_forced_reset_block_writes_exactly_one_deny_audit_row(
  http_client_factory: Any, provision_agent: Any, db_connection: Any
) -> None:
  """A `403` forced-reset block on a deal route writes one `(user, forced_reset_blocked, denied)`.

  `ACCESS_MATRIX.md` §4.5 row 5: the actor's own user id is `object_id`,
  never the resource that was asked for. Best-effort per R67 — this test
  only asserts the row exists after an ordinary block, not the swallow
  path (a forced database failure), which is `SQL-005`'s wider concern.
  """
  from conftest import ProvisionedUser, login_via_http

  user: ProvisionedUser = provision_agent()
  client: httpx.AsyncClient = http_client_factory()
  login_response = await login_via_http(client, email=user.email, password=user.password)
  assert login_response.status_code == 303
  assert login_response.headers.get("location") == "/account/password"

  cursor = await db_connection.execute(
    "SELECT count(*) FROM audit_events a JOIN users u ON u.id = a.actor_user_id "
    "WHERE u.email_norm = %(email)s AND a.action = 'forced_reset_blocked' "
    "AND a.object_type = 'user' AND a.outcome = 'denied'",
    {"email": user.email.strip().lower()},
  )
  before_row = await cursor.fetchone()
  assert before_row is not None
  before = int(before_row[0])

  response = await client.get("/deals/00000000-0000-4000-8000-000000000000")
  assert response.status_code == 403

  cursor = await db_connection.execute(
    "SELECT count(*) FROM audit_events a JOIN users u ON u.id = a.actor_user_id "
    "WHERE u.email_norm = %(email)s AND a.action = 'forced_reset_blocked' "
    "AND a.object_type = 'user' AND a.outcome = 'denied'",
    {"email": user.email.strip().lower()},
  )
  after_row = await cursor.fetchone()
  assert after_row is not None
  after = int(after_row[0])
  assert after - before == 1, "exactly one forced_reset_blocked deny row for this GET"


# ---------------------------------------------------------------------------
# R69 — the stage-change 409-stale render uses the GENERIC (fieldless) body,
# because a stage change submits only `to_stage`+`version`, never
# title/amount/close_date.
# ---------------------------------------------------------------------------


async def test_r69_stage_change_stale_conflict_uses_the_generic_fieldless_body(
  agent_a: LoggedInPrincipal,
) -> None:
  """A stale stage-change 409 carries no per-field diff table — `not any(f.differs)` is vacuous.

  R69: this is the deal twin of archive/restore's fieldless stale panel —
  a stage change never submits `title`/`amount`/`close_date`, so the
  predicate that selects the generic body is trivially true every time,
  and the 409's existing heading is unchanged (`CP-12`'s heading, per the
  ruling's own reading).
  """
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  detail = await agent_a.client.get(f"/deals/{deal.id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  stale_version = extract_hidden_field(detail.text, "version")

  first_move = await agent_a.client.post(
    f"/deals/{deal.id}/stage",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": stale_version,
      "to_stage": "qualified",
    },
  )
  assert first_move.status_code == 303

  second_move = await agent_a.client.post(
    f"/deals/{deal.id}/stage",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": fresh_idempotency_key(),
      "version": stale_version,
      "to_stage": "proposal",
    },
  )
  assert second_move.status_code == 409
  assert "differs" not in second_move.text.lower()
  assert '<table class="field-diff"' not in second_move.text
