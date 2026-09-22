"""Log redaction.

The structured log record keys are exactly ``ts, level, event, method, path,
status, duration_ms, correlation_id, actor_id`` — never a body, cookie,
header, SQL text, traceback, password or query string.

Drives a failed login (401), a spoofed-``Host`` request (403) and an
unknown path (404) through ``live_server`` and reads its own ``log_path``
(the uvicorn subprocess's combined stdout/stderr) — the whole process
stream, not only the log formatter. Never prints that stream's contents;
only asserts on it.

**The 500 and 503 legs are NOT VERIFIED here.** There is no fault-injection
hook yet (a way to force an internal error on demand without also breaking
the fixtures that provision the test itself), so this module cannot
honestly claim to have driven either. A dedicated fault-injection fixture
should close this gap rather than this file asserting something it never
actually forced.
"""

from __future__ import annotations

import httpx
import pytest
from conftest import LiveServer, extract_csrf_token

pytestmark = pytest.mark.asyncio

#: A distinctive fictional term, chosen so it cannot appear in the stream by
#: coincidence.
_DISTINCTIVE_TERM = "zarquon-x7f3@example.test"
_DISTINCTIVE_PASSWORD = "zarquon-secret-passphrase-9f2e"


def _assert_absent(haystack: bytes, needle: str, *, label: str) -> None:
  """Assert ``needle`` is absent from ``haystack`` without ever rendering either.

  Parameters
  ----------
  haystack : bytes
    The captured stream.
  needle : str
    The secret or sensitive fragment that must not appear.
  label : str
    What ``needle`` represents, for the failure message — never ``needle``
    itself, and never a slice of ``haystack``: pytest's assertion rewriting
    would otherwise print both operands of a plain ``assert needle not in
    haystack`` on failure, which is exactly the leak this test exists to
    catch.
  """
  if needle.encode("utf-8") in haystack:
    pytest.fail(f"{label} leaked into the process log stream (content redacted from this report)")


async def test_a_failed_login_leaks_no_password_or_cookie(
  live_server: LiveServer, http_client_factory: object
) -> None:
  """A failed login with a distinctive password leaves no trace of it in the log stream."""
  client: httpx.AsyncClient = http_client_factory()  # type: ignore[operator]
  get_response = await client.get("/login")
  csrf_token = extract_csrf_token(get_response.text)
  await client.post(
    "/login",
    data={
      "csrf_token": csrf_token,
      "email": _DISTINCTIVE_TERM,
      "password": _DISTINCTIVE_PASSWORD,
    },
  )
  stream = live_server.log_path.read_bytes()
  _assert_absent(stream, _DISTINCTIVE_PASSWORD, label="the submitted password")
  cookie_value = client.cookies.get("crm_session")
  if cookie_value:
    _assert_absent(stream, cookie_value, label="the raw session cookie value")


async def test_positive_the_structured_record_strips_the_query_string(
  live_server: LiveServer, http_client_factory: object
) -> None:
  """A request to a path carrying a distinctive query string logs ``path`` with it stripped.

  Proves the replacement for uvicorn's own access line does not reintroduce
  the leak it was added to close, by driving it through ``/login?next=...``
  and asserting the distinctive value is absent from the stream.
  """
  client: httpx.AsyncClient = http_client_factory()  # type: ignore[operator]
  await client.get("/login", params={"next": f"/{_DISTINCTIVE_TERM}"})
  stream = live_server.log_path.read_bytes()
  _assert_absent(stream, _DISTINCTIVE_TERM, label="the query string value")


async def test_a_spoofed_host_403_leaks_nothing_either(
  live_server: LiveServer, http_client_factory: object
) -> None:
  """The step-0 403 for a spoofed ``Host`` leaves no trace of the spoofed value in the stream."""
  spoofed_host = f"{_DISTINCTIVE_TERM.replace('@', '-')}.evil.invalid"
  async with httpx.AsyncClient(
    base_url=live_server.base_url,
    timeout=10.0,
  ) as client:
    response = await client.get("/account/password", headers={"Host": spoofed_host})
    assert response.status_code == 403
  stream = live_server.log_path.read_bytes()
  _assert_absent(stream, spoofed_host, label="the spoofed Host value")


async def test_error_pages_carry_only_a_correlation_id(
  http_client_factory: object,
) -> None:
  """A 404 page's body carries a correlation id and no other diagnostic detail."""
  import re

  client: httpx.AsyncClient = http_client_factory()  # type: ignore[operator]
  response = await client.get("/this-route-does-not-exist")
  assert response.status_code == 404
  body = response.text
  assert "Traceback" not in body
  assert 'File "' not in body
  uuid_pattern = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
  )
  assert uuid_pattern.search(body) is not None, "no correlation id found in the error page body"


async def test_crlf_in_a_login_field_cannot_forge_a_log_line(
  live_server: LiveServer, http_client_factory: object
) -> None:
  """A CRLF-laced email field cannot inject a fabricated JSON log line."""
  forged_marker = "FORGED_EVENT_MARKER_9f2e"
  client: httpx.AsyncClient = http_client_factory()  # type: ignore[operator]
  get_response = await client.get("/login")
  csrf_token = extract_csrf_token(get_response.text)
  await client.post(
    "/login",
    data={
      "csrf_token": csrf_token,
      "email": f'attacker@example.test\r\n{{"event": "{forged_marker}"}}',
      "password": "irrelevant-password-value",
    },
  )
  stream = live_server.log_path.read_bytes()
  _assert_absent(stream, forged_marker, label="a CRLF-forged log line")
