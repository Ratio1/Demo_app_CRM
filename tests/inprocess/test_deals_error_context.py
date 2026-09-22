"""The cookieless-vs-presented-cookie `401` fragment body, through the real route table.

``app/routes/errors.py``'s ``_REGION_TEXT[401]`` is a pair, selected by
whether a session cookie was presented — presented -> "Your session ended.
Sign in to continue." (unchanged); cookieless -> "Sign in to continue." (no
"Your session ended" sentence). This module asserts BOTH halves against the
real, shipped ``app/routes/errors.py``, driven through a deal route rather
than duplicating the existing contact-route assertions.

The existing contact-route session-expiry test
(``tests/inprocess/test_contacts_hx_session.py``) does not assert on
response body TEXT — it stops at the ``HX-Redirect`` header — so this file
adds the text assertion rather than flipping an existing one.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from conftest import ProvisionedUser, login_via_http

if TYPE_CHECKING:
  from app.security.clock import ManualClock

pytestmark = pytest.mark.asyncio

#: A canonical-shaped id that names nothing — the surface under test never
#: reaches the object read (the 401 fires at step 1, before any lookup).
_SOME_DEAL_ID = "00000000-0000-4000-8000-000000000000"


async def test_cookieless_hx_401_reads_sign_in_to_continue_only(
  in_process_client: httpx.AsyncClient,
) -> None:
  """No cookie at all + `HX-Request`: the fragment body is exactly `"Sign in to continue."`.

  No "Your session ended" sentence — that would tell a first-time,
  never-authenticated visitor their session "ended", which it never did.
  """
  response = await in_process_client.get(f"/deals/{_SOME_DEAL_ID}", headers={"HX-Request": "true"})
  assert response.status_code == 401
  assert response.headers.get("hx-redirect") == "/login"
  assert "Sign in to continue." in response.text
  assert "Your session ended" not in response.text
  assert "<html" not in response.text.lower(), "the HX-Request answer must be the compact fragment"


async def test_presented_but_dead_cookie_hx_401_keeps_full_session_ended_message(
  in_process_client: httpx.AsyncClient, clock: ManualClock, provision_agent: Any
) -> None:
  """A cookie that WAS presented but no longer names a live session keeps the full message."""
  from app.security.sessions import IDLE_TTL

  user: ProvisionedUser = provision_agent()
  login_response = await login_via_http(in_process_client, email=user.email, password=user.password)
  assert login_response.status_code == 303

  clock.advance(IDLE_TTL + timedelta(seconds=1))

  response = await in_process_client.get(f"/deals/{_SOME_DEAL_ID}", headers={"HX-Request": "true"})
  assert response.status_code == 401
  assert response.headers.get("hx-redirect") == "/login?notice=session_ended"
  assert "Your session ended. Sign in to continue." in response.text
