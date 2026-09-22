"""``ACC-037`` and PIN 5, through the real route table (ruling R54).

Authority: ``ACCESS_MATRIX.md`` §7 ``ACC-037`` (the ``HX-Request`` answer to
a dead/forced-reset session on a private ``GET``); ``contracts/slice-b.md``
§2(e) (the fragment predicate and PIN 5's dual render); rulings **R65**
(2026-09-22, Slice B gate round 1 — the ``401`` branch appends
``?notice=session_ended`` only when a cookie was presented, mirroring the
``303`` branch's rule) and **R26** (``HX-Redirect`` is acted on before the
``responseHandling`` decision, so it is honoured on any status).

``ACC-037``'s expiry case needs ``ManualClock`` control, and this module's
other two cases are grouped alongside it rather than split across
transports, per ``tests/README.md``'s "Three transports" rule: everything
here that is clock-independent (cases a and c, and PIN 5) could equally run
over ``live_server``, but keeping the whole cell in one module keeps the
three sibling assertions readable together.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from conftest import (
  LoggedInPrincipal,
  ProvisionedUser,
  complete_forced_reset,
  create_contact,
  login_via_http,
)

if TYPE_CHECKING:
  from app.security.clock import ManualClock

pytestmark = pytest.mark.asyncio

_CREATE_FIELDS = {
  "name": "HX Session Test Contact",
  "company": "Acme Corp",
  "email": "hx-session@example.test",
  "phone": "+1 555 0107",
  "kind": "lead",
}


async def _ready_principal(
  in_process_client: httpx.AsyncClient, provision_agent: Any
) -> LoggedInPrincipal:
  """Provision, log in and complete the forced reset for one in-process agent."""
  user: ProvisionedUser = provision_agent()
  login_response = await login_via_http(in_process_client, email=user.email, password=user.password)
  assert login_response.status_code == 303, (
    f"first login for a freshly provisioned agent failed (status {login_response.status_code})"
  )
  user = await complete_forced_reset(in_process_client, user=user)
  return LoggedInPrincipal(user=user, client=in_process_client)


# ---------------------------------------------------------------------------
# ACC-037 — the HX-Request answer to a dead or forced-reset session.
# ---------------------------------------------------------------------------


async def test_acc037a_no_cookie_at_all_is_401_with_a_bare_login_redirect(
  in_process_client: httpx.AsyncClient,
) -> None:
  """R65: a first-time visitor (no cookie at all) with `HX-Request` never reads `CP-07`.

  `401` with `HX-Redirect: /login` **exactly** — no `?notice=session_ended`
  — because no cookie was ever presented, mirroring the `303` branch's
  rule (`ACC-037`/`R26`, ruling **R65**).
  """
  response = await in_process_client.get("/contacts", headers={"HX-Request": "true"})
  assert response.status_code == 401
  assert response.headers.get("hx-redirect") == "/login", (
    "a request carrying no cookie at all must never be told its session 'ended'; "
    f"got HX-Redirect: {response.headers.get('hx-redirect')!r}"
  )
  assert "<html" not in response.text.lower(), "the HX-Request answer must be the compact fragment"


async def test_acc037b_expired_session_cookie_is_401_with_session_ended_notice(
  in_process_client: httpx.AsyncClient, clock: ManualClock, provision_agent: Any
) -> None:
  """A cookie that WAS presented but no longer names a live session appends the notice.

  Unlike case (a): the client's cookie jar carries a real, once-valid
  session cookie, so the `?notice=session_ended` code is exactly what
  `CP-07` exists to tell this visitor.
  """
  from app.security.sessions import IDLE_TTL

  user: ProvisionedUser = provision_agent()
  login_response = await login_via_http(in_process_client, email=user.email, password=user.password)
  assert login_response.status_code == 303

  clock.advance(IDLE_TTL + timedelta(seconds=1))

  response = await in_process_client.get("/contacts", headers={"HX-Request": "true"})
  assert response.status_code == 401
  assert response.headers.get("hx-redirect") == "/login?notice=session_ended", (
    f"got HX-Redirect: {response.headers.get('hx-redirect')!r}"
  )
  assert "<html" not in response.text.lower()


async def test_acc037c_forced_reset_session_is_403_with_password_redirect(
  in_process_client: httpx.AsyncClient, provision_agent: Any
) -> None:
  """A LIVE session still under a forced password reset gets `403` + `HX-Redirect` (step 2)."""
  user: ProvisionedUser = provision_agent()
  login_response = await login_via_http(in_process_client, email=user.email, password=user.password)
  assert login_response.status_code == 303
  assert login_response.headers.get("location") == "/account/password", (
    "a freshly create-user'd agent must land on the forced-reset form on first login"
  )

  response = await in_process_client.get("/contacts", headers={"HX-Request": "true"})
  assert response.status_code == 403
  assert response.headers.get("hx-redirect") == "/account/password"
  assert "<html" not in response.text.lower()


# ---------------------------------------------------------------------------
# PIN 5 — the dual render: a fragment on a genuine HX-Request, the full
# page otherwise, and the full page again on a Back-button history restore
# (contracts/slice-b.md §2(e), which htmx 2.0.10 sends as HX-Request: true
# *and* HX-History-Restore-Request: true — probe 1).
# ---------------------------------------------------------------------------


async def test_pin5_hx_request_gets_the_fragment_not_the_full_page(
  in_process_client: httpx.AsyncClient, provision_agent: Any
) -> None:
  """A genuine htmx fragment `GET` renders the partial, never a full document."""
  principal = await _ready_principal(in_process_client, provision_agent)
  await create_contact(principal, **_CREATE_FIELDS)

  response = await in_process_client.get("/contacts", headers={"HX-Request": "true"})
  assert response.status_code == 200
  assert "<html" not in response.text.lower(), "a fragment response must not carry <html>"
  assert 'id="contact-results"' in response.text
  assert "hx-swap-oob" in response.text, "the OOB #announce sibling only renders on a fragment"


async def test_pin5_a_full_page_load_with_no_hx_headers_gets_the_whole_document(
  in_process_client: httpx.AsyncClient, provision_agent: Any
) -> None:
  """No `HX-*` header at all -> `contacts/list.html`, the whole document."""
  principal = await _ready_principal(in_process_client, provision_agent)
  await create_contact(principal, **_CREATE_FIELDS)

  response = await in_process_client.get("/contacts")
  assert response.status_code == 200
  assert "<html" in response.text.lower()
  assert 'id="contact-results"' in response.text, (
    "the full page includes the same partial, so this id is present both ways"
  )


async def test_pin5_history_restore_request_gets_the_whole_document_not_the_fragment(
  in_process_client: httpx.AsyncClient, provision_agent: Any
) -> None:
  """`HX-Request: true` PLUS `HX-History-Restore-Request: true` still gets the full page.

  htmx 2.0.10's default ``historyRestoreAsHxRequest: true`` makes a
  Back-button cache-miss restore carry **both** headers and swap the
  response into the history element with ``innerHTML`` — a bare
  ``HX-Request`` check would wrongly answer with the fragment and put a
  fragment on screen as the whole document (§2(e), probe 1).
  """
  principal = await _ready_principal(in_process_client, provision_agent)
  await create_contact(principal, **_CREATE_FIELDS)

  response = await in_process_client.get(
    "/contacts", headers={"HX-Request": "true", "HX-History-Restore-Request": "true"}
  )
  assert response.status_code == 200
  assert "<html" in response.text.lower(), (
    "a history-restore request must get the full page, never the bare fragment"
  )
