"""R70 — the cookieless-vs-presented-cookie `401` fragment body, through the real route table.

Authority: ``contracts/slice-c.md`` §2(f) (R70, a Slice C backend task,
built beside R67/R69); ``ACCESS_MATRIX.md`` §7 (``ACC-037``, ``SEC-025``);
``tests/inprocess/test_contacts_hx_session.py`` (the ``ACC-037``/PIN 5
tests this module sits beside — same transport, same reason: R70's
"presented but dead" half needs ``ManualClock`` control the same way
``ACC-037b`` does).

Ruling **R70** (2026-09-22): ``app/routes/errors.py``'s
``_REGION_TEXT[401]`` becomes a pair, selected by whether a session
cookie was presented — presented -> ``"Your session ended. Sign in to
continue."`` (``CP-07``, unchanged); **cookieless -> ``"Sign in to
continue."``** (no "Your session ended" sentence). This module asserts
BOTH halves against the real, shipped ``app/routes/errors.py``, driven
through a deal route (the surface R70 was built for in Slice C) rather
than duplicating the existing contact-route assertions.

Neither existing ``ACC-037`` test (``tests/inprocess/test_contacts_hx_session.py``)
asserts on response body TEXT today — both stop at the ``HX-Redirect``
header — so this file adds the text assertion rather than flipping an
existing one (checked before writing this module, per the task's
instruction not to duplicate).
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


async def test_r70_cookieless_hx_401_reads_sign_in_to_continue_only(
  in_process_client: httpx.AsyncClient,
) -> None:
  """No cookie at all + `HX-Request`: the fragment body is exactly `"Sign in to continue."`.

  No "Your session ended" sentence — that would tell a first-time,
  never-authenticated visitor their session "ended", which it never did.
  """
  response = await in_process_client.get(
    f"/deals/{_SOME_DEAL_ID}", headers={"HX-Request": "true"}
  )
  assert response.status_code == 401
  assert response.headers.get("hx-redirect") == "/login"
  assert "Sign in to continue." in response.text
  assert "Your session ended" not in response.text
  assert "<html" not in response.text.lower(), "the HX-Request answer must be the compact fragment"


async def test_r70_presented_but_dead_cookie_hx_401_keeps_cp07(
  in_process_client: httpx.AsyncClient, clock: ManualClock, provision_agent: Any
) -> None:
  """A cookie that WAS presented but no longer names a live session keeps `CP-07` in full."""
  from app.security.sessions import IDLE_TTL

  user: ProvisionedUser = provision_agent()
  login_response = await login_via_http(in_process_client, email=user.email, password=user.password)
  assert login_response.status_code == 303

  clock.advance(IDLE_TTL + timedelta(seconds=1))

  response = await in_process_client.get(
    f"/deals/{_SOME_DEAL_ID}", headers={"HX-Request": "true"}
  )
  assert response.status_code == 401
  assert response.headers.get("hx-redirect") == "/login?notice=session_ended"
  assert "Your session ended. Sign in to continue." in response.text
