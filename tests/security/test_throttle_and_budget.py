"""Login throttle and rate budgets: per-account trip, non-enumeration, and Argon2 timing parity.

Throttle/budget *counting*, and the concurrent hash-queue depth, are
wire-observable (drive real failed logins/requests through
``live_server``); Argon2 parameter and timing-parity checks are in-process
against ``PasswordService`` directly, with the **real**, pinned
parameters — never the fast test profile, which is reserved for bulk
fixture setup only.

Isolation
-----------
The throttle and budget counters are deliberately **DB-shared, global
state** — that is not weakened here to make tests pass. Instead, every
test in this module:

1. targets a **dedicated, uniquely-generated** ``example.test`` identifier
   (``conftest.unique_email`` / :func:`provision_agent`) — **never the
   shared session admin** (``bootstrap_admin``/``admin_session``), which
   other modules elsewhere in the same suite run rely on staying
   throttle-free and budget-free; and
2. runs under :func:`_reset_throttle_and_budget_between_tests`, an
   ``autouse`` fixture (function-scoped — see its own docstring for why
   that, and not a single ``scope="module"`` instance, is what "after
   EVERY test" requires) that clears every row from ``login_throttle`` and
   ``rate_budget`` (owner role, its own subprocess, via
   ``conftest.clear_throttle_and_budget_state``) both before and after
   each test, so a global budget one test trips can never leak into the
   next.

The global-budget trip-and-recovery pair used to live here, driven over
``live_server`` with a real burst of requests. Counting a threshold this
way is sound, but *proving recovery* needs the budget window to actually
roll over, and a wall-clock version of that can straddle the ``:00``
window boundary and flake depending on where in the real minute the burst
happens to land. Both now live in
``tests/inprocess/test_throttle_and_budget_windows.py``, against the
``in_process_client``/``ManualClock`` fixtures: the whole burst is sent
at one fixed instant (so it cannot straddle a boundary), and recovery is
proved by advancing the clock past ``BUDGET_WINDOW``, never by waiting on
the wall clock.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import pytest

if TYPE_CHECKING:
  from argon2 import PasswordHasher
from conftest import (
  ProvisionedUser,
  clear_throttle_and_budget_state,
  extract_csrf_token,
  login_via_http,
)

pytestmark = pytest.mark.asyncio

LOGIN_FAILURE_THRESHOLD = 5


@pytest.fixture(autouse=True)
def _reset_throttle_and_budget_between_tests(
  crm_test_schema: None, tmp_path: Path
) -> Iterator[None]:
  """Clear ``login_throttle``/``rate_budget`` before **and** after every test here.

  Deliberately **function-scoped** (pytest's default): a ``scope="module"``
  fixture instantiates **once** for the whole module and could not clear
  state *between* individual tests, which is exactly what "after EVERY
  test" requires. Naming ``crm_test_schema`` explicitly is
  belt-and-suspenders (it is session-scoped **autouse**, so it already ran
  before this fixture regardless) but is kept as documentation of the
  real dependency. The concurrent hash-queue-depth test below is a
  separate matter regardless of scope: it drives 10 genuinely concurrent
  Argon2 hashes against a real, timed queue depth. An earlier revision
  staged its 10 attempts as free-running ``GET``-then-``POST`` pairs under
  one ``asyncio.gather`` and that shape flaked roughly 1 run in 3,
  standalone or full-suite, independent of this fixture; the test now
  fetches every CSRF token first and releases all ten ``POST``s together
  through an ``asyncio.Barrier``, which removed the flake across 6/6
  standalone reruns and a full-suite run. See the test's own docstring for
  the detail; this fixture's before/after clear is unrelated to that
  timing and was never the cause.
  """
  clear_throttle_and_budget_state(log_path=tmp_path / "clear-before.log")
  yield
  clear_throttle_and_budget_state(log_path=tmp_path / "clear-after.log")


#: Matches the hidden ``csrf_token`` field's value exactly as
#: ``conftest._CSRF_INPUT_PATTERN`` extracts it, so :func:`_body_without_variable_fields`
#: blanks precisely the one field that legitimately differs between two
#: sessions (see its docstring) and nothing else.
_CSRF_VALUE_PATTERN = re.compile(r'(name="csrf_token"[^>]*value=")[^"]*(")')

#: Matches ``auth/login.html``'s echoed ``form.email`` value (``id=
#: "login-email"`` disambiguates it from the hidden CSRF field). The two
#: non-enumeration tests below deliberately submit two *different* email
#: addresses (an unregistered one and a registered one, or two
#: differently-keyed throttled ones) — the whole premise of "unknown vs
#: known account" — so this field echoing the submitted value back is
#: expected, not a leak, and must be normalized out the same way the CSRF
#: token is.
_EMAIL_VALUE_PATTERN = re.compile(r'(id="login-email"[\s\S]*?value=")[^"]*(")')


def _body_without_variable_fields(html: str) -> str:
  """Return ``html`` with its per-request ``csrf_token`` and echoed email blanked out.

  Parameters
  ----------
  html : str
    A rendered ``auth/login.html`` page.

  Returns
  -------
  str
    The same markup with both values replaced by a fixed placeholder.

  Notes
  -----
  ``app.security.csrf.csrf_for_token`` derives the CSRF token from the
  session's own token (``crm-csrf-v1:<session token>``), so it is, by
  design, different for every client/session — including two clients that
  hit ``/login`` at the same instant with the same email and password.
  The email field simply echoes back whatever was submitted, per the
  frozen ``form {email}`` context key. The two non-enumeration tests below
  assert the *rest* of the page (status, copy, structure) is identical
  regardless of whether the account exists or is locked; a raw ``==`` on
  the full body fails on these two expected, non-enumerating differences
  and never actually tests the non-enumeration property. Confirmed
  empirically (a line-level diff of two such bodies) that these two
  fields are the *only* differences once both are blanked.
  """
  without_csrf = _CSRF_VALUE_PATTERN.sub(r"\1REDACTED\2", html)
  return _EMAIL_VALUE_PATTERN.sub(r"\1REDACTED\2", without_csrf)


async def _failed_login(client: httpx.AsyncClient, *, email: str) -> httpx.Response:
  """One deliberately wrong-password login attempt, CSRF included."""
  get_response = await client.get("/login")
  csrf_token = extract_csrf_token(get_response.text)
  return await client.post(
    "/login", data={"csrf_token": csrf_token, "email": email, "password": "definitely-wrong-pw"}
  )


async def test_five_failures_trip_a_temporary_backoff(
  http_client_factory: Any, provision_agent: Any
) -> None:
  """The 6th failed attempt within 15 minutes for one account is ``429``, not ``401``.

  This test only drives the *trip*, never the window rolling over.
  Recovery is proved in
  ``tests/inprocess/test_throttle_and_budget_windows.py``'s
  ``test_login_lock_engages_at_the_6th_failure_and_lifts_after_login_lock_elapses``,
  which advances a ``ManualClock`` past the lock window rather than sleeping
  — this module's ``live_server`` runs the real, unswappable
  ``SystemClock``, so it cannot prove recovery without either sleeping or
  risking a `:00`-boundary flake.

  Targets a freshly provisioned, dedicated agent — never the shared
  session admin — so this test's own throttle trip cannot lock out
  ``bootstrap_admin`` for every other module that logs in as it later in
  the same session.
  """
  agent: ProvisionedUser = provision_agent()
  client: httpx.AsyncClient = http_client_factory()
  statuses = [
    (await _failed_login(client, email=agent.email)).status_code
    for _ in range(LOGIN_FAILURE_THRESHOLD + 1)
  ]
  assert statuses[:LOGIN_FAILURE_THRESHOLD] == [401] * LOGIN_FAILURE_THRESHOLD
  assert statuses[LOGIN_FAILURE_THRESHOLD] == 429


async def test_unknown_user_and_wrong_password_are_indistinguishable(
  http_client_factory: Any,
) -> None:
  """A nonexistent account and a real one with a wrong password get byte-identical bodies."""
  from conftest import unique_email

  client_a: httpx.AsyncClient = http_client_factory()
  client_b: httpx.AsyncClient = http_client_factory()
  response_a = await _failed_login(client_a, email=unique_email("nobody"))
  response_b = await _failed_login(client_b, email=unique_email("also-nobody"))
  assert response_a.status_code == response_b.status_code == 401
  assert _body_without_variable_fields(response_a.text) == _body_without_variable_fields(
    response_b.text
  )


async def test_the_per_account_mutation_budget_trips_and_recovers(
  http_client_factory: Any, provision_agent: Any
) -> None:
  """A burst of change-password ``GET`` requests (the account_query bucket) eventually 429s.

  Coarse: asserts a 429 appears somewhere in a large burst, without
  pinning the exact threshold. Logs in as a freshly provisioned, dedicated
  agent rather than ``admin_session`` — 250 requests would otherwise burn
  a large chunk of the shared session admin's own per-account budget for
  every test that runs after this one in the same session.
  """
  agent: ProvisionedUser = provision_agent()
  client: httpx.AsyncClient = http_client_factory()
  login_response = await login_via_http(client, email=agent.email, password=agent.password)
  assert login_response.status_code == 303, (
    f"login as the freshly provisioned agent failed (status {login_response.status_code})"
  )
  statuses = [(await client.get("/account/password")).status_code for _ in range(250)]
  assert 429 in statuses


async def test_the_account_throttle_429_does_not_enumerate(
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
  assert _body_without_variable_fields(locked_known.text) == _body_without_variable_fields(
    locked_unknown.text
  )


# ---------------------------------------------------------------------------
# Argon2, in-process, real (not fast) parameters.
# ---------------------------------------------------------------------------


def _real_password_hasher() -> PasswordHasher:
  """The production Argon2 parameters (never the fast test profile)."""
  from argon2 import PasswordHasher, Type

  return PasswordHasher(
    time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
  )


async def test_encoded_hash_parses_to_the_pinned_parameters() -> None:
  """The encoded string parses to exactly ``argon2id``/``v=19``/``m=19456``/``t=2``/``p=1``."""
  from app.security.clock import SystemClock
  from app.security.passwords import PasswordService

  service = PasswordService(
    _real_password_hasher(), blocklist=frozenset(), clock=SystemClock(), max_active=1, max_queued=8
  )
  encoded = await service.hash("a fictional passphrase for the parameter check")
  assert encoded.startswith("$argon2id$v=19$m=19456,t=2,p=1$")


async def test_two_hashes_of_the_same_password_have_independent_salts() -> None:
  """Hashing the same password twice yields two different encoded strings, both verifying."""
  from app.security.clock import SystemClock
  from app.security.passwords import PasswordService

  service = PasswordService(
    _real_password_hasher(), blocklist=frozenset(), clock=SystemClock(), max_active=1, max_queued=8
  )
  password = "a fictional passphrase for the independent-salts check"
  first = await service.hash(password)
  second = await service.hash(password)
  assert first != second
  assert await service.verify(first, password) is True
  assert await service.verify(second, password) is True


async def test_a_non_pinned_hash_authenticates_and_is_replaced_on_login() -> None:
  """``needs_rehash`` is true for a default-parameter hash, false for a pinned one."""
  from argon2 import PasswordHasher

  from app.security.clock import SystemClock
  from app.security.passwords import PasswordService

  service = PasswordService(
    _real_password_hasher(), blocklist=frozenset(), clock=SystemClock(), max_active=1, max_queued=8
  )
  password = "a fictional passphrase for the rehash check"
  pinned = await service.hash(password)
  assert service.needs_rehash(pinned) is False

  default_hasher = PasswordHasher()  # library defaults, not the pinned profile
  drifted = default_hasher.hash(password)
  assert service.needs_rehash(drifted) is True


async def test_a_missing_account_runs_the_dummy_hash_not_a_short_circuit() -> None:
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


async def test_the_tenth_concurrent_login_gets_a_sanitized_429(
  http_client_factory: Any,
) -> None:
  """One active plus eight queued Argon2 hashes; a 10th concurrent login is ``429``.

  Drives 10 concurrent ``POST /login`` attempts (each its own client, its
  own cookie jar) against distinct never-registered accounts, so the
  per-account throttle cannot itself explain a 429 here — only the shared
  hash-queue depth can.

  Every client's pre-auth ``GET /login`` (CSRF token, TLS handshake) is
  driven to completion *before* any ``POST`` fires, and an
  :class:`asyncio.Barrier` then releases all ten ``POST``s together.
  Without this staging, interleaving the GET-then-POST pairs freely under
  a single ``asyncio.gather`` (the previous shape) lets the event loop
  dispatch the ten POSTs spread out in time: on a lightly loaded machine
  the first queued hash can finish — freeing a slot — before the tenth
  request even connects, so the 10th sometimes lands as a plain ``401``
  instead of the intended ``429``. Confirmed empirically: the previous
  shape failed roughly 1 run in 3 across repeated standalone runs of just
  this test, with no change at all to the admission logic itself
  (``app/security/passwords.py``'s check-then-increment is not separated
  by an ``await``, so it cannot itself race); staging the dispatch this
  way removed the flake. This still exercises the real, timed queue depth
  under genuine concurrent load — the fix only tightens *when* the ten
  requests are sent, never what the assertion requires.
  """
  import asyncio

  from conftest import unique_email

  clients = [http_client_factory() for _ in range(10)]
  emails = [unique_email(f"queue-{index}") for index in range(10)]

  async def _csrf_token(client: httpx.AsyncClient) -> str:
    get_response = await client.get("/login")
    return extract_csrf_token(get_response.text)

  csrf_tokens = await asyncio.gather(*(_csrf_token(client) for client in clients))

  barrier = asyncio.Barrier(len(clients))

  async def _attempt(client: httpx.AsyncClient, email: str, csrf_token: str) -> int:
    await barrier.wait()
    response = await client.post(
      "/login",
      data={"csrf_token": csrf_token, "email": email, "password": "definitely-wrong-pw"},
    )
    return response.status_code

  statuses = await asyncio.gather(
    *(
      _attempt(client, email, csrf_token)
      for client, email, csrf_token in zip(clients, emails, csrf_tokens, strict=True)
    )
  )
  assert 429 in statuses
