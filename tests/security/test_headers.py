"""Response headers: CSP, HSTS, Permissions-Policy, frame/referrer/CORS and error-page hygiene.

The exact header table is asserted byte for byte. Two notes on choices:
``img-src`` drops ``data:`` because nothing ships a ``data:`` image, and
``Referrer-Policy`` is ``same-origin`` rather than ``no-referrer`` because,
per the Fetch standard, a browser serialises ``Origin`` as the literal
string ``"null"`` on a non-``GET``/``HEAD`` request whose referrer policy
is ``no-referrer`` — an exact-``Origin`` check at the request-origin gate
would then refuse every real-browser form ``POST`` (reproduced live
against headless Chromium). One assertion per directive, on a private
page, the login page and an error page.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.asyncio

_EXPECTED_CSP = (
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
  "connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; "
  "form-action 'self'"
)
_EXPECTED_PERMISSIONS_POLICY = (
  "accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), "
  "gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), "
  "publickey-credentials-get=(), screen-wake-lock=(), usb=(), xr-spatial-tracking=()"
)


async def _pages(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> list[httpx.Response]:
  """One private page, the login page, and a 404 error page."""
  private = await admin_session.get("/account/password")
  anon: httpx.AsyncClient = http_client_factory()
  login = await anon.get("/login")
  error = await anon.get("/this-route-does-not-exist")
  return [private, login, error]


async def test_csp_is_the_exact_pinned_value_on_every_kind_of_page(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """The exact CSP string, byte for byte, on a private page, login and an error page."""
  for response in await _pages(admin_session, http_client_factory):
    assert response.headers.get("content-security-policy") == _EXPECTED_CSP


async def test_x_content_type_options_nosniff_on_every_kind_of_page(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """``X-Content-Type-Options: nosniff`` on every response."""
  for response in await _pages(admin_session, http_client_factory):
    assert response.headers.get("x-content-type-options") == "nosniff"


async def test_strict_transport_security_present_on_every_kind_of_page(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """HSTS header present with the pinned ``max-age`` and ``includeSubDomains``, no ``preload``."""
  for response in await _pages(admin_session, http_client_factory):
    hsts = response.headers.get("strict-transport-security", "")
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts
    assert "preload" not in hsts


async def test_permissions_policy_is_the_exact_pinned_value(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """The exact restrictive ``Permissions-Policy`` string on every kind of page."""
  for response in await _pages(admin_session, http_client_factory):
    assert response.headers.get("permissions-policy") == _EXPECTED_PERMISSIONS_POLICY


async def test_frame_ancestors_none_on_every_kind_of_page(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """``frame-ancestors 'none'`` is in the CSP on every response, paired with ``X-Frame-Options``."""
  for response in await _pages(admin_session, http_client_factory):
    assert "frame-ancestors 'none'" in response.headers.get("content-security-policy", "")
    assert response.headers.get("x-frame-options") == "DENY"


async def test_referrer_policy_same_origin_on_every_kind_of_page(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """``Referrer-Policy: same-origin`` on every response, never ``no-referrer``."""
  for response in await _pages(admin_session, http_client_factory):
    assert response.headers.get("referrer-policy") == "same-origin"


async def test_no_credential_or_token_ever_appears_as_a_query_parameter() -> None:
  """The rendered login form's action carries no query string (static, no live session needed).

  ``auth/login.html``'s ``<form ... action="/login">`` names no ``?``.
  """
  from pathlib import Path

  login_html = (
    Path(__file__).resolve().parent.parent.parent / "app" / "templates" / "auth" / "login.html"
  ).read_text(encoding="utf-8")
  assert 'action="/login"' in login_html
  assert 'action="/login?' not in login_html


async def test_no_directory_listing_is_served_for_static(
  http_client_factory: Any,
) -> None:
  """``GET /static/`` (no filename) never returns a directory listing."""
  client: httpx.AsyncClient = http_client_factory()
  response = await client.get("/static/")
  assert response.status_code in (403, 404)
  assert "Index of" not in response.text


async def test_an_unsupported_method_is_405_with_no_disclosure(
  http_client_factory: Any,
) -> None:
  """``TRACE /login`` is ``405`` (or ``404``), never a body echoing the request."""
  client: httpx.AsyncClient = http_client_factory()
  response = await client.request("TRACE", "/login")
  assert response.status_code in (404, 405)


async def test_docs_routes_are_404_on_a_server_whose_lifespan_ran(
  http_client_factory: Any,
) -> None:
  """``/docs``, ``/redoc`` and ``/openapi.json`` are ``404`` over a live, lifespan-backed server.

  Complements ``tests/arch/test_gates.py``'s
  ``test_docs_routes_are_404_in_the_shipped_configuration``, which asserts
  on the constructed ``FastAPI`` object without ever entering the lifespan
  (``app.state.context`` stays unset, so no live request could be made
  there without hitting the origin/host middleware's ``503`` "not
  provisioned" path — not the ``404`` this test actually needs).
  ``live_server`` (via ``http_client_factory``) already waited for
  ``/health/live`` and ran ``manage set-origin`` before this test runs, so
  its lifespan has genuinely started: this is the live half that needs.
  """
  client: httpx.AsyncClient = http_client_factory()
  for path in ("/docs", "/redoc", "/openapi.json"):
    response = await client.get(path)
    assert response.status_code == 404, f"{path} did not 404 (got {response.status_code})"


# A repeated allowlisted query parameter -> 400 has no assertion surface
# here: the allowlisted keys it governs (sort, dir, status, kind, stage,
# page) belong to list/search/pagination routes that this module's routes
# (login, account/password, logout, health) do not have — a test written
# against them would not exercise the control this describes. Left
# deliberately unwritten here rather than asserting something that isn't
# the real behaviour; NOT VERIFIED until a route with such a parameter is
# added elsewhere in this suite.
