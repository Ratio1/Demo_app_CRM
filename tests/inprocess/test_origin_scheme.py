"""The session cookie's name/`Secure`, `Strict-Transport-Security`, and cross-scheme `Origin`.

The process itself always serves plain HTTP — no TLS listener anywhere in
this application — so it is the *stored* public origin's scheme, and
nothing else, that decides two things: the session cookie's name and
`Secure` flag
(`app.security.sessions.cookie_name`/`cookie_secure`) and whether
`Strict-Transport-Security` is sent at all
(`app.security.headers.apply_security_headers`). `live_server`
(`tests/security/*`, `tests/e2e/*`) now serves the `http://` half of that
contract at the real wire. This module covers the `https://` half
(`Secure`, `__Host-`, HSTS) the same way `tests/inprocess` covers every
other exact, non-flaky assertion — and adds a second, independent
in-process client (`http_mode_in_process_client`) for the `http://` half,
so both halves of one contract are proved from the same machinery.

`response.cookies` (httpx's parsed jar) keeps only a cookie's name and
value and drops every attribute, so `Secure`'s presence or absence is read
off the literal `Set-Cookie` header string instead, throughout this
module.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from conftest import ProvisionedUser, extract_csrf_token, login_via_http

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# https://crm.test — Secure, __Host-, HSTS.
# ---------------------------------------------------------------------------


async def test_https_mode_cookie_is_dunder_host_crm_session_with_secure(
  in_process_client: httpx.AsyncClient, provision_agent: Any
) -> None:
  """Under the default `https://crm.test` origin, login sets `__Host-crm_session` with `Secure`."""
  user: ProvisionedUser = provision_agent()
  response = await login_via_http(in_process_client, email=user.email, password=user.password)
  assert response.status_code == 303
  set_cookie = response.headers.get("set-cookie", "")
  assert set_cookie.startswith("__Host-crm_session="), set_cookie
  assert "; Secure" in set_cookie, set_cookie
  assert "HttpOnly" in set_cookie
  assert "SameSite=lax" in set_cookie
  assert "Domain=" not in set_cookie


async def test_https_mode_response_carries_strict_transport_security(
  in_process_client: httpx.AsyncClient,
) -> None:
  """Under `https://crm.test`, a checked response carries the pinned HSTS header."""
  response = await in_process_client.get("/login")
  hsts = response.headers.get("strict-transport-security", "")
  assert "max-age=31536000" in hsts
  assert "includeSubDomains" in hsts


# ---------------------------------------------------------------------------
# http://crm.test — the unprefixed cookie, no Secure, no HSTS, everything
# else unchanged.
# ---------------------------------------------------------------------------


async def test_http_mode_cookie_is_crm_session_without_secure_or_dunder_host_prefix(
  http_mode_in_process_client: httpx.AsyncClient, provision_agent: Any
) -> None:
  """Under `http://crm.test`, login sets the unprefixed `crm_session` cookie, without `Secure`.

  Everything else about the cookie — `HttpOnly`, `SameSite=Lax`, `Path=/`,
  no `Domain` — stays identical to the `https://` case above; only the
  name and `Secure` move.
  """
  user: ProvisionedUser = provision_agent()
  response = await login_via_http(
    http_mode_in_process_client, email=user.email, password=user.password
  )
  assert response.status_code == 303
  set_cookie = response.headers.get("set-cookie", "")
  assert set_cookie.startswith("crm_session="), set_cookie
  assert not set_cookie.startswith("__Host-crm_session="), set_cookie
  assert "Secure" not in set_cookie, set_cookie
  assert "HttpOnly" in set_cookie
  assert "SameSite=lax" in set_cookie
  assert "Domain=" not in set_cookie


async def test_http_mode_response_carries_no_strict_transport_security_header(
  http_mode_in_process_client: httpx.AsyncClient,
) -> None:
  """Under `http://crm.test`, no response carries `Strict-Transport-Security`.

  The header is a promise this deployment cannot keep on a plain-HTTP
  origin — omitted, not sent with a value that would be a lie.
  """
  response = await http_mode_in_process_client.get("/login")
  assert "strict-transport-security" not in response.headers


async def test_http_mode_login_private_page_logout_journey_works_end_to_end(
  http_mode_in_process_client: httpx.AsyncClient, provision_agent: Any
) -> None:
  """Login, a private page, and CSRF-guarded logout all work normally under `http://crm.test`."""
  client = http_mode_in_process_client
  user: ProvisionedUser = provision_agent()

  login_response = await login_via_http(client, email=user.email, password=user.password)
  assert login_response.status_code == 303, (
    f"login under the http:// origin failed (status {login_response.status_code})"
  )

  private = await client.get("/account/password")
  assert private.status_code == 200, (
    f"the freshly authenticated session could not reach a private page "
    f"(status {private.status_code})"
  )

  csrf_token = extract_csrf_token(private.text)
  logout_response = await client.post("/logout", data={"csrf_token": csrf_token})
  assert logout_response.status_code == 303
  assert logout_response.headers.get("clear-site-data") == '"cache", "storage"'
  expiry_cookie = logout_response.headers.get("set-cookie", "")
  assert expiry_cookie.startswith("crm_session="), expiry_cookie
  assert "Max-Age=0" in expiry_cookie
  assert "Secure" not in expiry_cookie

  after_logout = await client.get("/account/password")
  assert after_logout.status_code in (303, 401), (
    "the page must no longer be reachable once the session cookie has been expired"
  )


async def test_http_mode_logout_without_a_valid_csrf_token_is_still_403(
  http_mode_in_process_client: httpx.AsyncClient, provision_agent: Any
) -> None:
  """CSRF protection is unaffected by the stored origin's scheme: a bad token is still 403."""
  client = http_mode_in_process_client
  user: ProvisionedUser = provision_agent()
  login_response = await login_via_http(client, email=user.email, password=user.password)
  assert login_response.status_code == 303

  response = await client.post("/logout", data={"csrf_token": "0" * 64})
  assert response.status_code == 403


# ---------------------------------------------------------------------------
# Cross-scheme Origin: the exact, literal-string match refuses a header
# claiming the *other* scheme even though the host is identical.
# ---------------------------------------------------------------------------


async def test_an_https_origin_header_against_an_http_stored_origin_is_403(
  http_mode_in_process_client: httpx.AsyncClient,
) -> None:
  """A `POST` whose `Origin` claims `https://` is refused when the stored origin is `http://`."""
  response = await http_mode_in_process_client.post(
    "/logout", data={"csrf_token": "irrelevant"}, headers={"Origin": "https://crm.test"}
  )
  assert response.status_code == 403


async def test_an_http_origin_header_against_an_https_stored_origin_is_403(
  in_process_client: httpx.AsyncClient,
) -> None:
  """A `POST` whose `Origin` claims `http://` is refused when the stored origin is `https://`."""
  response = await in_process_client.post(
    "/logout", data={"csrf_token": "irrelevant"}, headers={"Origin": "http://crm.test"}
  )
  assert response.status_code == 403
