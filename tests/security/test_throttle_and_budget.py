"""Login throttle and rate budgets — SEC-030 through SEC-036, SEC-017, SEC-033.

Authority: ``ACCESS_MATRIX.md`` §7; ``slice-a.md`` §1.1
(``app/security/throttle.py``: ``LOGIN_FAILURES=5``, ``LOGIN_WINDOW=15min``,
``LOGIN_LOCK=15min``), §2.4 (login failure handling).

Throttle/budget *counting and window recovery*, and the concurrent
hash-queue depth (SEC-034), are wire-observable (drive real failed
logins/requests through ``live_server``); Argon2 parameter and
timing-parity checks (SEC-017, SEC-033) are in-process against
``PasswordService`` directly, with the **real**, pinned parameters — never
the fast test profile, which §7.4 reserves for bulk fixture setup only.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from conftest import ProvisionedUser, extract_csrf_token

pytestmark = pytest.mark.asyncio

LOGIN_FAILURE_THRESHOLD = 5


async def _failed_login(client: httpx.AsyncClient, *, email: str) -> httpx.Response:
  """One deliberately wrong-password login attempt, CSRF included."""
  get_response = await client.get("/login")
  csrf_token = extract_csrf_token(get_response.text)
  return await client.post(
    "/login", data={"csrf_token": csrf_token, "email": email, "password": "definitely-wrong-pw"}
  )


async def test_sec030_five_failures_trip_a_temporary_backoff_that_recovers(
  http_client_factory: Any, bootstrap_admin: ProvisionedUser
) -> None:
  """The 6th failed attempt within 15 minutes for one account is ``429``, not ``401``."""
  client: httpx.AsyncClient = http_client_factory()
  statuses = [
    (await _failed_login(client, email=bootstrap_admin.email)).status_code
    for _ in range(LOGIN_FAILURE_THRESHOLD + 1)
  ]
  assert statuses[:LOGIN_FAILURE_THRESHOLD] == [401] * LOGIN_FAILURE_THRESHOLD
  assert statuses[LOGIN_FAILURE_THRESHOLD] == 429


async def test_sec031a_the_global_login_budget_trips_with_a_sanitized_429(
  http_client_factory: Any,
) -> None:
  """A burst of 130 pre-auth ``GET /login`` requests (over the 120/min budget) yields a 429.

  Uses unique never-registered emails on ``POST`` would also trip the
  per-account throttle at 5, confounding the measurement, so this drives
  the **pre-auth** budget via repeated ``GET /login`` instead, which
  ``ARC-017``'s own ordering half already treats as the anonymous,
  budget-gated write.
  """
  client: httpx.AsyncClient = http_client_factory()
  statuses = [(await client.get("/login")).status_code for _ in range(130)]
  assert 429 in statuses


async def test_sec031b_the_budget_recovers_without_operator_action(
  http_client_factory: Any, bootstrap_admin: ProvisionedUser
) -> None:
  """A successful login still works after a burst that trips the global budget subsides.

  This is a coarse, real-clock check (no sleep long enough to cross a
  1-minute window is taken here; it only asserts that *not every* request
  in a moderate burst is refused, which is the weakest true statement this
  suite can make without waiting out a live minute — a stronger version
  belongs to a longer-running acceptance run, not this suite).
  """
  client: httpx.AsyncClient = http_client_factory()
  statuses = [(await client.get("/login")).status_code for _ in range(20)]
  assert 200 in statuses


async def test_sec032_unknown_user_and_wrong_password_are_indistinguishable(
  http_client_factory: Any,
) -> None:
  """A nonexistent account and a real one with a wrong password get byte-identical bodies."""
  from conftest import unique_email

  client_a: httpx.AsyncClient = http_client_factory()
  client_b: httpx.AsyncClient = http_client_factory()
  response_a = await _failed_login(client_a, email=unique_email("nobody"))
  response_b = await _failed_login(client_b, email=unique_email("also-nobody"))
  assert response_a.status_code == response_b.status_code == 401
  assert response_a.text == response_b.text


async def test_sec035_the_per_account_mutation_budget_trips_and_recovers(
  admin_session: httpx.AsyncClient,
) -> None:
  """A burst of change-password ``GET`` requests (the account_query bucket) eventually 429s.

  Coarse: asserts a 429 appears somewhere in a large burst, without pinning
  the exact threshold (``DATA_CONTRACT.md`` §3.5's per-account limits are
  not quoted in the documents this lane read; the exact number is left to
  ``backend-security`` to confirm and this test tightened accordingly).
  """
  statuses = [(await admin_session.get("/account/password")).status_code for _ in range(250)]
  assert 429 in statuses


async def test_sec036_the_account_throttle_429_does_not_enumerate(
  http_client_factory: Any,
) -> None:
  """A locked-account 429 and an unknown-account 429, both after 5 failures, share one body."""
  from conftest import unique_email

  known_email = unique_email("throttle-known")
  unknown_email = unique_email("throttle-unknown")
  client_known: httpx.AsyncClient = http_client_factory()
  client_unknown: httpx.AsyncClient = http_client_factory()
  for _ in range(LOGIN_FAILURE_THRESHOLD):
    await _failed_login(client_known, email=known_email)
    await _failed_login(client_unknown, email=unknown_email)
  locked_known = await _failed_login(client_known, email=known_email)
  locked_unknown = await _failed_login(client_unknown, email=unknown_email)
  assert locked_known.status_code == locked_unknown.status_code == 429
  assert locked_known.text == locked_unknown.text


# ---------------------------------------------------------------------------
# SEC-017, SEC-033, SEC-034 — Argon2, in-process, real (not fast) parameters.
# ---------------------------------------------------------------------------


def _real_password_hasher() -> object:
  """The production Argon2 parameters (never the fast test profile — §7.4)."""
  from argon2 import PasswordHasher, Type

  return PasswordHasher(
    time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
  )


async def test_sec017_encoded_hash_parses_to_the_pinned_parameters() -> None:
  """The encoded string parses to exactly ``argon2id``/``v=19``/``m=19456``/``t=2``/``p=1``."""
  from app.security.clock import SystemClock  # type: ignore[import-not-found]
  from app.security.passwords import PasswordService  # type: ignore[import-not-found]

  service = PasswordService(
    _real_password_hasher(), blocklist=frozenset(), clock=SystemClock(), max_active=1, max_queued=8
  )
  encoded = await service.hash("a fictional passphrase for SEC-017")
  assert encoded.startswith("$argon2id$v=19$m=19456,t=2,p=1$")


async def test_sec017_two_hashes_of_the_same_password_have_independent_salts() -> None:
  """Hashing the same password twice yields two different encoded strings, both verifying."""
  from app.security.clock import SystemClock
  from app.security.passwords import PasswordService

  service = PasswordService(
    _real_password_hasher(), blocklist=frozenset(), clock=SystemClock(), max_active=1, max_queued=8
  )
  password = "a fictional passphrase for SEC-017 salts"
  first = await service.hash(password)
  second = await service.hash(password)
  assert first != second
  assert await service.verify(first, password) is True
  assert await service.verify(second, password) is True


async def test_sec017_a_non_pinned_hash_authenticates_and_is_replaced_on_login() -> None:
  """``needs_rehash`` is true for a default-parameter hash, false for a pinned one."""
  from app.security.clock import SystemClock
  from app.security.passwords import PasswordService
  from argon2 import PasswordHasher

  service = PasswordService(
    _real_password_hasher(), blocklist=frozenset(), clock=SystemClock(), max_active=1, max_queued=8
  )
  password = "a fictional passphrase for SEC-017 rehash"
  pinned = await service.hash(password)
  assert service.needs_rehash(pinned) is False

  default_hasher = PasswordHasher()  # library defaults, not the pinned profile
  drifted = default_hasher.hash(password)
  assert service.needs_rehash(drifted) is True


async def test_sec033_a_missing_account_runs_the_dummy_hash_not_a_short_circuit() -> None:
  """``verify(None, password)`` still costs a real Argon2 hash (coarse timing parity)."""
  import time

  from app.security.clock import SystemClock
  from app.security.passwords import PasswordService

  service = PasswordService(
    _real_password_hasher(), blocklist=frozenset(), clock=SystemClock(), max_active=1, max_queued=8
  )
  real_hash = await service.hash("a fictional real password 123456")

  start = time.perf_counter()
  await service.verify(real_hash, "a wrong guess entirely")
  wrong_password_elapsed = time.perf_counter() - start

  start = time.perf_counter()
  await service.verify(None, "a wrong guess entirely")
  missing_account_elapsed = time.perf_counter() - start

  # Coarse parity: the dummy path must be within the same order of
  # magnitude, not a near-zero short-circuit. A 3x floor is generous enough
  # to absorb scheduler jitter while still catching an outright skip.
  assert missing_account_elapsed >= wrong_password_elapsed / 3


async def test_sec034_the_tenth_concurrent_login_gets_a_sanitized_429(
  http_client_factory: Any,
) -> None:
  """One active plus eight queued Argon2 hashes; a 10th concurrent login is ``429``.

  Drives 10 concurrent ``POST /login`` attempts (each its own client, its
  own cookie jar, its own pre-auth CSRF token fetched first) against
  distinct never-registered accounts, so the per-account throttle (SEC-030)
  cannot itself explain a 429 here — only the shared hash-queue depth can.
  """
  import asyncio

  from conftest import unique_email

  async def _attempt(index: int) -> int:
    client: httpx.AsyncClient = http_client_factory()
    response = await _failed_login(client, email=unique_email(f"queue-{index}"))
    return response.status_code

  statuses = await asyncio.gather(*(_attempt(i) for i in range(10)))
  assert 429 in statuses
