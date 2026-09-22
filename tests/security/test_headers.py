"""Response headers — SEC-026, SEC-027, SEC-028, SEC-070 through SEC-076.

Authority: ``ACCESS_MATRIX.md`` §7; ``slice-a.md`` §2.6 (the exact header
table). One assertion per directive, on a private page, the login page and
an error page, per ``PLAN.md`` §6's security-gate description.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.asyncio

_EXPECTED_CSP = (
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
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


async def test_sec070_csp_is_the_exact_pinned_value_on_every_kind_of_page(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """The exact CSP string, byte for byte, on a private page, login and an error page."""
  for response in await _pages(admin_session, http_client_factory):
    assert response.headers.get("content-security-policy") == _EXPECTED_CSP


async def test_sec071_x_content_type_options_nosniff_on_every_kind_of_page(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """``X-Content-Type-Options: nosniff`` on every response."""
  for response in await _pages(admin_session, http_client_factory):
    assert response.headers.get("x-content-type-options") == "nosniff"


async def test_sec072_strict_transport_security_present_on_every_kind_of_page(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """HSTS header present with the pinned ``max-age`` and ``includeSubDomains``, no ``preload``."""
  for response in await _pages(admin_session, http_client_factory):
    hsts = response.headers.get("strict-transport-security", "")
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts
    assert "preload" not in hsts


async def test_sec073_permissions_policy_is_the_exact_pinned_value(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """The exact restrictive ``Permissions-Policy`` string on every kind of page."""
  for response in await _pages(admin_session, http_client_factory):
    assert response.headers.get("permissions-policy") == _EXPECTED_PERMISSIONS_POLICY


async def test_sec026_frame_ancestors_none_on_every_kind_of_page(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """``frame-ancestors 'none'`` is in the CSP on every response, paired with ``X-Frame-Options``."""
  for response in await _pages(admin_session, http_client_factory):
    assert "frame-ancestors 'none'" in response.headers.get("content-security-policy", "")
    assert response.headers.get("x-frame-options") == "DENY"


async def test_sec027_referrer_policy_no_referrer_on_every_kind_of_page(
  admin_session: httpx.AsyncClient, http_client_factory: Any
) -> None:
  """``Referrer-Policy: no-referrer`` on every response."""
  for response in await _pages(admin_session, http_client_factory):
    assert response.headers.get("referrer-policy") == "no-referrer"


async def test_sec028_no_credential_or_token_ever_appears_as_a_query_parameter() -> None:
  """The rendered login form's action carries no query string (static, no live session needed).

  ``auth/login.html``'s ``<form ... action="/login">`` names no ``?``.
  """
  from pathlib import Path

  login_html = (
    Path(__file__).resolve().parent.parent.parent / "app" / "templates" / "auth" / "login.html"
  ).read_text(encoding="utf-8")
  assert 'action="/login"' in login_html
  assert 'action="/login?' not in login_html


async def test_sec074_no_directory_listing_is_served_for_static(
  http_client_factory: Any,
) -> None:
  """``GET /static/`` (no filename) never returns a directory listing."""
  client: httpx.AsyncClient = http_client_factory()
  response = await client.get("/static/")
  assert response.status_code in (403, 404)
  assert "Index of" not in response.text


async def test_sec075_an_unsupported_method_is_405_with_no_disclosure(
  http_client_factory: Any,
) -> None:
  """``TRACE /login`` is ``405`` (or ``404``), never a body echoing the request."""
  client: httpx.AsyncClient = http_client_factory()
  response = await client.request("TRACE", "/login")
  assert response.status_code in (404, 405)


# SEC-076 (repeated allowlisted query parameter -> 400) has no assertion
# surface in Slice A: the allowlisted keys it governs (sort, dir, status,
# kind, stage, page) belong to list/search/pagination routes that do not
# exist until Slices B-D. Slice A's own routes (login, account/password,
# logout, health) take no allowlisted query key at all, so a test written
# against them would not exercise the control this ID names. Left
# deliberately unwritten here rather than asserting something that isn't
# the real behaviour; NOT VERIFIED until a later slice adds such a route.
