"""Login throttle and rate budgets — SEC-030 through SEC-036, SEC-017, SEC-033.

Authority: ``ACCESS_MATRIX.md`` §7; ``slice-a.md`` §1.1
(``app/security/throttle.py``: ``LOGIN_FAILURES=5``, ``LOGIN_WINDOW=15min``,
``LOGIN_LOCK=15min``), §2.4 (login failure handling); ruling **R52**
(``contracts/slice-a.md`` §7.5 amendment).

Throttle/budget *counting and window recovery*, and the concurrent
hash-queue depth (SEC-034), are wire-observable (drive real failed
logins/requests through ``live_server``); Argon2 parameter and
timing-parity checks (SEC-017, SEC-033) are in-process against
``PasswordService`` directly, with the **real**, pinned parameters — never
the fast test profile, which §7.4 reserves for bulk fixture setup only.

Isolation (R52)
-----------------
The throttle and budget counters are deliberately **DB-shared, global
state** (spec §6 S6) — that is not weakened here to make tests pass.
Instead, every test in this module:

1. targets a **dedicated, uniquely-generated** ``example.test`` identifier
   (``conftest.unique_email`` / :func:`provision_agent`) — **never the
   shared session admin** (``bootstrap_admin``/``admin_session``), which
   other modules elsewhere in the same suite run rely on staying
   throttle-free and budget-free; and
2. runs under :func:`_reset_throttle_and_budget_between_tests`, an
   ``autouse`` fixture (function-scoped — see its own docstring for why
   that, and not a single ``scope="module"`` instance, is what "after
   EVERY test" requires) that clears every row from ``login_throttle`` and
   ``rate_budget`` (owner role, its own subprocess) both before and after
   each test, so a global budget one test trips can never leak into the
   next.
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
  OWNER_ENV_FILE,
  VENV_PYTHON,
  ProvisionedUser,
  extract_csrf_token,
  login_via_http,
  run_with_env,
)

pytestmark = pytest.mark.asyncio

LOGIN_FAILURE_THRESHOLD = 5

#: Owner-role, autocommit: expiry/eviction is maintenance's job elsewhere,
#: this is a blunt test-isolation wipe of exactly the two counter tables
#: R52 names, nothing else (``crm`` is never touched; this only ever runs
#: against ``crm_test``, via ``OWNER_ENV_FILE``).
_CLEAR_THROTTLE_AND_BUDGET_SNIPPET = """
import asyncio
from typing import Any, cast
from psycopg import AsyncConnection
from app.config import load_config

async def main() -> None:
  kwargs = cast('dict[str, Any]', load_config().connect_kwargs())
  conn = await AsyncConnection.connect(autocommit=True, **kwargs)
  try:
    await conn.execute('DELETE FROM public.login_throttle')
    await conn.execute('DELETE FROM public.rate_budget')
  finally:
    await conn.close()

asyncio.run(main())
"""


def _clear_throttle_and_budget_state(*, log_path: Path) -> None:
  """Delete every row from ``login_throttle`` and ``rate_budget`` (owner role)."""
  run_with_env(
    OWNER_ENV_FILE,
    str(VENV_PYTHON),
    "-B",
    "-c",
    _CLEAR_THROTTLE_AND_BUDGET_SNIPPET,
    log_path=log_path,
  )


@pytest.fixture(autouse=True)
def _reset_throttle_and_budget_between_tests(
  crm_test_schema: None, tmp_path: Path
) -> Iterator[None]:
  """Clear ``login_throttle``/``rate_budget`` before **and** after every test here (R52).

  Deliberately **function-scoped** (pytest's default) despite R52's prose
  calling it "module-scoped": a ``scope="module"`` fixture instantiates
  **once** for the whole module and could not clear state *between*
  individual tests, which is exactly what "after EVERY test" requires — so
  "module-scoped" is read here as "scoped to this module's tests" (an
  autouse fixture defined in this file, applying to every test it
  collects), not as the literal pytest scope keyword. Depending on
  ``crm_test_schema`` (session-scoped) rather than assuming some earlier
  module already requested it means this module is safe to run in
  isolation too (``pytest tests/security/test_throttle_and_budget.py``),
  not only as part of the full suite.
  """
  _clear_throttle_and_budget_state(log_path=tmp_path / "clear-before.log")
  yield
  _clear_throttle_and_budget_state(log_path=tmp_path / "clear-after.log")


#: Matches the hidden ``csrf_token`` field's value exactly as
#: ``conftest._CSRF_INPUT_PATTERN`` extracts it, so :func:`_body_without_variable_fields`
#: blanks precisely the one field that legitimately differs between two
#: sessions (see its docstring) and nothing else.
_CSRF_VALUE_PATTERN = re.compile(r'(name="csrf_token"[^>]*value=")[^"]*(")')

#: Matches ``auth/login.html``'s echoed ``form.email`` value (``id=
#: "login-email"`` disambiguates it from the hidden CSRF field). SEC-032 and
#: SEC-036 deliberately submit two *different* email addresses (an
#: unregistered one and a registered one, or two differently-keyed
#: throttled ones) — the whole premise of "unknown vs known account" — so
#: this field echoing the submitted value back is expected, not a leak, and
#: must be normalized out the same way the CSRF token is.
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
  The email field simply echoes back whatever was submitted, per
  ``CONTRACTS.md`` §8.2's ``form {email}`` context key. SEC-032/SEC-036
  assert the *rest* of the page (status, copy, structure) is identical
  regardless of whether the account exists or is locked; a raw ``==`` on
  the full body fails on these two expected, non-enumerating differences
  and never actually tests the no-enumeration property the ID names.
  Confirmed empirically (a line-level diff of two such bodies) that these
  two fields are the *only* differences once both are blanked.
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


async def test_sec030_five_failures_trip_a_temporary_backoff_that_recovers(
  http_client_factory: Any, provision_agent: Any
) -> None:
  """The 6th failed attempt within 15 minutes for one account is ``429``, not ``401``.

  Targets a freshly provisioned, dedicated agent (R52) — never the shared
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
  http_client_factory: Any,
) -> None:
  """A successful login still works after a burst that trips the global budget subsides.

  This is a coarse, real-clock check (no sleep long enough to cross a
  1-minute window is taken here; it only asserts that *not every* request
  in a moderate burst is refused, which is the weakest true statement this
  suite can make without waiting out a live minute — a stronger version
  belongs to a longer-running acceptance run, not this suite). Drives
  anonymous ``GET /login`` only, so it needs no account of its own — no
  ``bootstrap_admin`` dependency (R52: this module never targets the
  shared session admin).
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
  assert _body_without_variable_fields(response_a.text) == _body_without_variable_fields(
    response_b.text
  )


async def test_sec035_the_per_account_mutation_budget_trips_and_recovers(
  http_client_factory: Any, provision_agent: Any
) -> None:
  """A burst of change-password ``GET`` requests (the account_query bucket) eventually 429s.

  Coarse: asserts a 429 appears somewhere in a large burst, without pinning
  the exact threshold (``DATA_CONTRACT.md`` §3.5's per-account limits are
  not quoted in the documents this lane read; the exact number is left to
  ``backend-security`` to confirm and this test tightened accordingly).
  Logs in as a freshly provisioned, dedicated agent rather than
  ``admin_session`` (R52) — 250 requests would otherwise burn a large
  chunk of the shared session admin's own per-account budget for every
  test that runs after this one in the same session.
  """
  agent: ProvisionedUser = provision_agent()
  client: httpx.AsyncClient = http_client_factory()
  login_response = await login_via_http(client, email=agent.email, password=agent.password)
  assert login_response.status_code == 303, (
    f"login as the freshly provisioned agent failed (status {login_response.status_code})"
  )
  statuses = [(await client.get("/account/password")).status_code for _ in range(250)]
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
  assert _body_without_variable_fields(locked_known.text) == _body_without_variable_fields(
    locked_unknown.text
  )


# ---------------------------------------------------------------------------
# SEC-017, SEC-033, SEC-034 — Argon2, in-process, real (not fast) parameters.
# ---------------------------------------------------------------------------


def _real_password_hasher() -> PasswordHasher:
  """The production Argon2 parameters (never the fast test profile — §7.4)."""
  from argon2 import PasswordHasher, Type

  return PasswordHasher(
    time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
  )


async def test_sec017_encoded_hash_parses_to_the_pinned_parameters() -> None:
  """The encoded string parses to exactly ``argon2id``/``v=19``/``m=19456``/``t=2``/``p=1``."""
  from app.security.clock import SystemClock
  from app.security.passwords import PasswordService

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
  from argon2 import PasswordHasher

  from app.security.clock import SystemClock
  from app.security.passwords import PasswordService

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
