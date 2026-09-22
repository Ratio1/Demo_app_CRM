"""Throttle lock recovery and global-budget windows, driven by ``ManualClock``.

The failure-rate constants under test: ``LOGIN_FAILURES=5``,
``LOGIN_WINDOW=15min``, ``LOGIN_LOCK=15min``, ``BUDGET_WINDOW=1min``.
Throttle/budget window tests use the in-process app with ``ManualClock`` so
a `:00`-minute-boundary flake is eliminated by advancing the clock, not by
timing the burst.

Two properties this module proves that ``tests/security/test_throttle_and_budget.py``
(``live_server``, real wall clock) cannot prove without either sleeping for
real or risking a flake:

1. **A login lock actually lifts.** ``test_throttle_and_budget.py`` proves
   the 6th failure is ``429``; nothing there proves the lock is
   *temporary*, because doing so over the wire would mean sleeping 15
   real minutes. Here, the clock is advanced past ``LOGIN_LOCK`` and the
   very next attempt is asserted to succeed.
2. **A global budget trip is deterministic, and recovery is exact.** A
   burst driven over real wall-clock time can straddle the budget
   window's ``:00`` boundary depending on when in the real minute the
   test happens to run, splitting the count across two windows and
   sometimes never tripping at all. Every request in the bursts below is
   sent without ever advancing the clock in between, so every one of them
   computes the identical ``window_start_of(now)`` and the count is exact
   and reproducible; recovery is then proved by advancing the clock past
   ``BUDGET_WINDOW`` before the next request, never by waiting.

Isolation: this module shares ``login_throttle``/``rate_budget`` with
``test_throttle_and_budget.py`` (the same two DB-shared, global tables),
so it relies on the same discipline — a dedicated identity per test
(``provision_agent``/a fixed never-registered address) and
``tests/inprocess/conftest.py``'s own autouse clear of both tables before
and after every test here.
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

LOGIN_FAILURE_THRESHOLD = 5
_WRONG_PASSWORD = "definitely-wrong-pw"  # fictional, never a real credential


async def _failed_login(client: httpx.AsyncClient, *, email: str) -> httpx.Response:
  """One deliberately wrong-password login attempt, CSRF included."""
  get_response = await client.get("/login")
  csrf_token = extract_csrf_token(get_response.text)
  return await client.post(
    "/login", data={"csrf_token": csrf_token, "email": email, "password": _WRONG_PASSWORD}
  )


async def test_login_lock_engages_at_the_6th_failure_and_lifts_after_login_lock_elapses(
  in_process_client: httpx.AsyncClient, clock: ManualClock, provision_agent: Any
) -> None:
  """After 5 failures the 6th is ``429``; after ``LOGIN_LOCK`` (15 min) a real login succeeds.

  Targets a freshly provisioned, dedicated agent (never the shared
  ``bootstrap_admin``), matching the rest of this suite's throttle
  isolation rule.
  """
  from app.security.throttle import LOGIN_LOCK

  agent: ProvisionedUser = provision_agent()

  statuses = [
    (await _failed_login(in_process_client, email=agent.email)).status_code
    for _ in range(LOGIN_FAILURE_THRESHOLD)
  ]
  assert statuses == [401] * LOGIN_FAILURE_THRESHOLD

  locked_response = await _failed_login(in_process_client, email=agent.email)
  assert locked_response.status_code == 429
  retry_after = locked_response.headers.get("retry-after")
  assert retry_after is not None and int(retry_after) > 0

  # A correct password does not bypass the lock either: the throttle state
  # is checked before any credential is verified (app.services.auth.login).
  still_locked_get = await in_process_client.get("/login")
  still_locked_csrf = extract_csrf_token(still_locked_get.text)
  still_locked_response = await in_process_client.post(
    "/login",
    data={"csrf_token": still_locked_csrf, "email": agent.email, "password": agent.password},
  )
  assert still_locked_response.status_code == 429, (
    "the correct password must not bypass an active lock"
  )

  clock.advance(LOGIN_LOCK + timedelta(seconds=1))

  recovered_response = await login_via_http(
    in_process_client, email=agent.email, password=agent.password
  )
  assert recovered_response.status_code == 303, (
    f"a correct login one second past LOGIN_LOCK must succeed, got {recovered_response.status_code}"
  )


async def test_the_global_preauth_budget_trips_deterministically_in_one_fixed_window(
  in_process_client: httpx.AsyncClient,
) -> None:
  """A burst of 130 pre-auth ``GET /login`` requests (over the 120/min budget) yields a 429.

  The clock is never advanced during the burst (this test never requests
  ``clock`` itself, and nothing else in it advances one), so every request
  computes the exact same ``window_start_of(now)`` — the count cannot be
  split across two windows by real elapsed time the way a wall-clock
  version can.
  """
  from app.security.throttle import PREAUTH_GLOBAL_LIMIT

  statuses = [
    (await in_process_client.get("/login")).status_code for _ in range(PREAUTH_GLOBAL_LIMIT + 10)
  ]
  assert 429 in statuses


async def test_the_global_preauth_budget_recovers_exactly_one_window_later(
  in_process_client: httpx.AsyncClient, clock: ManualClock
) -> None:
  """After a burst trips the global pre-auth budget, one request past ``BUDGET_WINDOW`` succeeds.

  Recovery is proved by advancing the clock past ``BUDGET_WINDOW``, not by
  sending a moderate burst and hoping *some* of it lands in a fresh
  real-time window — an exact recovery window rather than a weakest-true
  caveat.
  """
  from app.security.throttle import BUDGET_WINDOW, PREAUTH_GLOBAL_LIMIT

  tripped = [
    (await in_process_client.get("/login")).status_code for _ in range(PREAUTH_GLOBAL_LIMIT + 10)
  ]
  assert 429 in tripped, "setup: the burst must trip the budget before recovery can be proved"

  clock.advance(BUDGET_WINDOW + timedelta(seconds=1))

  recovered = await in_process_client.get("/login")
  assert recovered.status_code == 200, (
    f"a single request one second into the next window must be admitted, "
    f"got {recovered.status_code}"
  )
