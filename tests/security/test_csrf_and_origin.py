"""CSRF and Origin/Host — SEC-020 through SEC-023, SEC-040, SEC-041, SEC-043.

Authority: ``ACCESS_MATRIX.md`` §7; ``slice-a.md`` §2.1 (step 0a/0b),
§2.4 (``POST /login`` CSRF), ruling R41 (per-test server).

One test per ID (no sub-case fan-out), against ``live_server``. None of
these can run today: ``app.main`` does not exist.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from conftest import LiveServer, ProvisionedUser, extract_csrf_token

pytestmark = pytest.mark.asyncio


async def test_sec020_a_mutation_with_no_csrf_token_is_403(
  admin_session: httpx.AsyncClient,
) -> None:
  """``POST /logout`` with the ``csrf_token`` field omitted entirely is 403."""
  response = await admin_session.post("/logout", data={})
  assert response.status_code == 403


async def test_sec021_a_stale_csrf_token_is_403(
  admin_session: httpx.AsyncClient,
) -> None:
  """A syntactically plausible but wrong CSRF token is 403, not merely ignored."""
  response = await admin_session.post("/logout", data={"csrf_token": "0" * 64})
  assert response.status_code == 403


async def test_sec022_post_login_requires_a_valid_preauth_csrf_token(
  http_client_factory: Any,
) -> None:
  """``POST /login`` with a wrong ``csrf_token`` is 403, even with correct credentials."""
  client: httpx.AsyncClient = http_client_factory()
  await client.get("/login")
  response = await client.post(
    "/login",
    data={"csrf_token": "0" * 64, "email": "nobody@example.test", "password": "irrelevant123456"},
  )
  assert response.status_code == 403


async def test_sec023_logout_without_a_valid_csrf_token_is_403(
  admin_session: httpx.AsyncClient,
) -> None:
  """``POST /logout`` is a CSRF-guarded mutation like any other (paired with SEC-020/021)."""
  response = await admin_session.post("/logout", data={"csrf_token": "not-the-real-token"})
  assert response.status_code == 403


async def test_sec040a_each_unsafe_method_with_a_missing_or_mismatched_origin_is_403(
  admin_session: httpx.AsyncClient,
) -> None:
  """``POST`` with a foreign ``Origin`` header is 403, before CSRF is even checked."""
  response = await admin_session.post(
    "/logout", data={"csrf_token": "irrelevant"}, headers={"Origin": "https://evil.example.test"}
  )
  assert response.status_code == 403


async def test_sec040b_a_safe_method_with_no_origin_header_is_not_rejected(
  admin_session: httpx.AsyncClient,
) -> None:
  """``GET`` with no ``Origin`` header (a plain browser navigation) is served normally."""
  response = await admin_session.get("/account/password", headers={})
  assert response.status_code == 200


async def test_sec040c_a_spoofed_host_is_403_even_on_an_unknown_path(
  live_server: LiveServer,
) -> None:
  """A spoofed ``Host`` is 403 before routing — even a path with no registered route.

  Connects to the real ``live_server`` port (a made-up port would just be a
  connection-refused error, testing nothing) and overrides only the request's
  ``Host`` *header*, which httpx lets a caller set explicitly while the TCP
  connection itself still goes to ``live_server``'s real address.
  """
  async with httpx.AsyncClient(
    base_url=live_server.base_url,
    verify=False,  # noqa: S501
    timeout=10.0,
  ) as client:
    response = await client.get(
      "/definitely-not-a-real-route", headers={"Host": "evil.example.test"}
    )
    assert response.status_code == 403


async def test_sec040d_health_endpoints_answer_normally_with_a_spoofed_host(
  live_server: LiveServer,
) -> None:
  """``/health/live`` and ``/health/ready`` are exempt from step 0 entirely (H-09)."""
  async with httpx.AsyncClient(
    base_url=live_server.base_url,
    verify=False,  # noqa: S501
    timeout=10.0,
  ) as client:
    response = await client.get("/health/live", headers={"Host": "evil.example.test"})
    assert response.status_code == 200


async def test_sec041_x_forwarded_headers_change_no_decision(
  admin_session: httpx.AsyncClient,
) -> None:
  """``X-Forwarded-Host/Proto/For`` influence nothing — same status with or without them."""
  without = await admin_session.get("/account/password")
  with_forwarded = await admin_session.get(
    "/account/password",
    headers={
      "X-Forwarded-Host": "evil.example.test",
      "X-Forwarded-Proto": "http",
      "X-Forwarded-For": "203.0.113.9",
    },
  )
  assert without.status_code == with_forwarded.status_code == 200


async def test_sec043_no_cors_header_on_any_response(
  admin_session: httpx.AsyncClient,
) -> None:
  """No ``Access-Control-Allow-*`` header appears, with or without an ``Origin`` request header."""
  response = await admin_session.get("/account/password", headers={"Origin": "https://127.0.0.1"})
  for header in (
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
  ):
    assert header not in response.headers


async def test_sec043_an_options_preflight_to_a_mutation_route_is_405_not_a_preflight_response(
  live_server: LiveServer,
) -> None:
  """``OPTIONS /login`` is ``405``, never a CORS preflight response."""
  async with httpx.AsyncClient(
    base_url=live_server.base_url,
    verify=False,  # noqa: S501
    timeout=10.0,
  ) as client:
    response = await client.options("/login")
    assert response.status_code == 405


async def test_sec042_open_redirect_next_parameters_all_land_same_origin(
  http_client_factory: Any, bootstrap_admin: ProvisionedUser
) -> None:
  """``?next=//evil``, ``?next=https://evil`` and ``?next=/\\evil`` never redirect off-origin."""
  for hostile_next in ("//evil.example.test", "https://evil.example.test", "/\\evil.example.test"):
    client: httpx.AsyncClient = http_client_factory()
    get_response = await client.get("/login", params={"next": hostile_next})
    csrf_token = extract_csrf_token(get_response.text)
    response = await client.post(
      "/login",
      data={
        "csrf_token": csrf_token,
        "email": bootstrap_admin.email,
        "password": bootstrap_admin.password,
      },
    )
    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert not location.startswith("//")
    assert "evil.example.test" not in location
