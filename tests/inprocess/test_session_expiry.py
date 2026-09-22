"""Session expiry, end to end through the real route table.

The three TTLs — pre-auth, idle and absolute — are also proved
*at the repository layer* in ``tests/security/test_sessions.py``
(``read_live_session`` given an explicit ``now``). This module proves the
same three properties **through the served application** instead — the
real ``GET``/``POST /login`` and ``GET /account/password`` handlers, the
real middleware stack, the real CSRF check — using ``in_process_client``
and the injected ``ManualClock`` it shares with the app under test, so
every advance below moves the whole application's notion of "now" in one
call and no test here ever sleeps.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from conftest import ProvisionedUser, extract_csrf_token, login_via_http

if TYPE_CHECKING:
  from app.security.clock import ManualClock

pytestmark = pytest.mark.asyncio

#: A dedicated, never-registered identifier — this module never needs a
#: real account for the pre-auth half (the first case authenticates
#: nobody; only the *pre-auth row's* age is under test).
_NOBODY_EMAIL = "nobody+preauth-expiry@example.test"
_IRRELEVANT_PASSWORD = "irrelevant123456"  # fictional, never a real credential


async def test_preauth_session_is_refused_10min01s_after_get_login_but_a_fresh_one_still_works(
  in_process_client: httpx.AsyncClient, clock: ManualClock
) -> None:
  """A pre-auth CSRF token older than ``PREAUTH_TTL`` is refused before credential checking (403).

  Mirrors, through the real route, what the repository-layer pre-auth
  expiry test already proves: the boundary is ``PREAUTH_TTL`` (10
  minutes), plus one second past it. The control half (a *fresh* pre-auth
  session at the same advanced instant reaching credential checking
  normally) is what proves the ``403`` above is genuinely the expiry and
  not some other side effect of having advanced the clock.
  """
  from app.security.sessions import PREAUTH_TTL

  get_response = await in_process_client.get("/login")
  assert get_response.status_code == 200
  stale_csrf_token = extract_csrf_token(get_response.text)

  clock.advance(PREAUTH_TTL + timedelta(seconds=1))

  stale_response = await in_process_client.post(
    "/login",
    data={
      "csrf_token": stale_csrf_token,
      "email": _NOBODY_EMAIL,
      "password": _IRRELEVANT_PASSWORD,
    },
  )
  assert stale_response.status_code == 403, (
    "a POST /login carrying a pre-auth CSRF token older than PREAUTH_TTL must be refused "
    f"before credential checking; got {stale_response.status_code}"
  )

  fresh_get = await in_process_client.get("/login")
  assert fresh_get.status_code == 200
  fresh_csrf_token = extract_csrf_token(fresh_get.text)
  assert fresh_csrf_token != stale_csrf_token, (
    "GET /login after the old pre-auth row expired must mint a genuinely new one, "
    "not silently keep serving the dead token"
  )
  fresh_response = await in_process_client.post(
    "/login",
    data={
      "csrf_token": fresh_csrf_token,
      "email": _NOBODY_EMAIL,
      "password": _IRRELEVANT_PASSWORD,
    },
  )
  assert fresh_response.status_code == 401, (
    "a fresh pre-auth session at the same advanced instant must reach credential checking "
    f"(401 invalid), not be refused the way the stale one was; got {fresh_response.status_code}"
  )


async def test_idle_30min_expiry_ends_a_full_session_through_the_real_route(
  in_process_client: httpx.AsyncClient, clock: ManualClock, provision_agent: Any
) -> None:
  """A full session with no activity for ``IDLE_TTL`` (30 min) is dead on the next request.

  Uses a dedicated agent from ``provision_agent`` (never the shared
  ``bootstrap_admin``), consistent with the rest of this suite's isolation
  rule for anything that authenticates.
  """
  from app.security.sessions import IDLE_TTL

  agent: ProvisionedUser = provision_agent()
  login_response = await login_via_http(
    in_process_client, email=agent.email, password=agent.password
  )
  assert login_response.status_code == 303, (
    f"login as the freshly provisioned agent failed (status {login_response.status_code})"
  )

  still_live = await in_process_client.get("/account/password")
  assert still_live.status_code == 200, "the session must be live immediately after login"

  clock.advance(IDLE_TTL + timedelta(seconds=1))

  after_idle = await in_process_client.get("/account/password")
  assert after_idle.status_code == 303, (
    f"a session idle for more than IDLE_TTL must be treated as dead (303 to /login), "
    f"got {after_idle.status_code}"
  )
  assert "/login" in after_idle.headers.get("location", "")


async def test_absolute_8h_expiry_ends_a_full_session_even_with_continuous_idle_touches(
  in_process_client: httpx.AsyncClient, clock: ManualClock, provision_agent: Any
) -> None:
  """``ABSOLUTE_TTL`` (8 h) ends a session even though every gap stays well inside ``IDLE_TTL``.

  Proves the two bounds are independent, through the real route, the same
  property the repository-layer test proves for idle-vs-absolute
  independence: touching the session regularly (every 25 minutes —
  comfortably under the 30-minute idle bound, and comfortably over
  ``TOUCH_INTERVAL`` so each touch actually extends the idle window) keeps
  it alive past where idle expiry alone would have killed it, but the
  absolute 8-hour bound still ends it once total elapsed time crosses that
  boundary.
  """
  from app.security.sessions import ABSOLUTE_TTL, IDLE_TTL

  step = timedelta(minutes=25)
  assert step < IDLE_TTL, "the step must stay inside the idle window or this proves nothing new"

  agent: ProvisionedUser = provision_agent()
  login_response = await login_via_http(
    in_process_client, email=agent.email, password=agent.password
  )
  assert login_response.status_code == 303, (
    f"login as the freshly provisioned agent failed (status {login_response.status_code})"
  )

  elapsed = timedelta(0)
  max_iterations = int((ABSOLUTE_TTL + step + step) / step) + 1
  final_status: int | None = None
  for iteration in range(max_iterations):
    clock.advance(step)
    elapsed += step
    response = await in_process_client.get("/account/password")
    final_status = response.status_code
    if response.status_code != 200:
      break
    assert elapsed < ABSOLUTE_TTL, (
      f"iteration {iteration}: still 200 at {elapsed} elapsed, past ABSOLUTE_TTL "
      f"({ABSOLUTE_TTL}) despite regular idle touches — the absolute bound did not fire"
    )
  else:
    pytest.fail(f"session never expired after {max_iterations} touches spanning {elapsed}")

  assert final_status == 303, (
    f"the request that finally crosses ABSOLUTE_TTL must be a 303 to /login, got {final_status}"
  )
  assert elapsed >= ABSOLUTE_TTL, (
    f"the session died at {elapsed} elapsed, before ABSOLUTE_TTL ({ABSOLUTE_TTL}) — "
    "idle touches should have kept it alive until the absolute bound, not before"
  )
