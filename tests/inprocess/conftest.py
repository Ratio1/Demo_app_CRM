"""Fixtures for the in-process, whole-app, ``ManualClock``-driven transport (ruling R54).

Authority: ``_agents/projects/CRM/DECISIONS.md`` §9 ruling **R54** (the
``create_app`` injection seam and the exact fixture shape); ``CONTRACTS.md``
§5.1; ``CLAUDE.md``/``AGENTS.md`` (credential discipline — every database
credential reaches a process only through ``scripts/with-env``).

Why this directory exists, and how it differs from ``tests/conftest.py``'s
``live_server``
--------------------------------------------------------------------------
``live_server`` (root ``conftest.py``) runs the real ``app.main:app`` as a
separate uvicorn subprocess over TLS, on the production ``SystemClock`` — the
only way to observe genuinely wire-level behaviour (TLS itself, real cookie
attributes, real header casing), but its clock cannot be swapped, so nothing
driven through it can be clock-tested without sleeping.

``in_process_client`` (this module) instead builds ``app.main.create_app``
**in this same test process**, with an injected
:class:`app.security.clock.ManualClock`, and drives it through
``httpx.ASGITransport`` — no socket, no subprocess, no TLS, but the *entire*
route table, every middleware and every service the lifespan builds, all
reading the *same* clock instance the test holds and can advance by hand.
That is what makes an expiry or a rate-limit window assertion exact and
non-flaky here in a way a real-time test never can be: the test decides
exactly what instant every clock-dependent decision in the whole application
sees, for every request, without waiting on the wall clock at all.

The origin: ``https://crm.test``, not an ephemeral port
--------------------------------------------------------
``live_server`` points ``crm_test``'s one stored ``public_origin`` row at its
own ``https://127.0.0.1:<port>`` the moment it is first constructed, and
never repoints it again for the rest of the session (it is session-scoped,
ruling R46(b)/R57). This module needs its **own**, different, fixed origin
so that (a) it does not depend on ``live_server`` ever having started, and
(b) it does not silently steal ``live_server``'s effect if it ran first —
whichever fixture sets the row last wins for everything that runs
afterward. ``conftest.py``'s ``pytest_collection_modifyitems`` (root
``conftest.py``) orders ``tests/inprocess`` **first** in the session
specifically so this module's own ``manage set-origin --origin
https://crm.test`` call always runs before ``live_server`` is ever
constructed, and ``live_server`` then sets its own origin exactly once,
after — no toggling back and forth is needed either way.

The set-origin fixture below depends on ``bootstrap_admin``, not merely on
``crm_test_schema``: ``manage bootstrap`` — which provisions the one first
administrator every other module's ``live_server``/``admin_session``
relies on — refuses outright once a ``public_origin`` row already exists.
Depending on the weaker fixture would let this module write the origin
*before* ``bootstrap`` ever ran, which would then make every later,
``live_server``-dependent test in the session fail. See
``_set_inprocess_origin``'s own docstring for the detail.

``crm.test`` is a reserved-for-documentation-style fictional hostname
(never resolved, never dialled — ``httpx.ASGITransport`` never opens a
socket), chosen to be visibly distinct from ``live_server``'s
``127.0.0.1:<port>`` shape so a failure naming one or the other origin is
never ambiguous about which transport produced it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Final

import httpx
import pytest
import pytest_asyncio
from conftest import (
  MANAGE,
  OWNER_ENV_FILE,
  VENV_PYTHON,
  ProvisionedUser,
  _default_origin_on_unsafe_methods,
  clear_throttle_and_budget_state,
  run_with_env,
)

if TYPE_CHECKING:
  from fastapi import FastAPI

  from app.security.clock import ManualClock

#: The fixed, fictional origin every in-process request presents (R54).
#: httpx derives the ``Host`` header from ``base_url``'s netloc, so setting
#: this as the client's ``base_url`` is what makes every request carry
#: ``Host: crm.test`` without this module stamping the header by hand.
INPROCESS_ORIGIN: Final[str] = "https://crm.test"


@pytest.fixture(scope="module", autouse=True)
def _set_inprocess_origin(
  bootstrap_admin: ProvisionedUser, tmp_path_factory: pytest.TempPathFactory
) -> None:
  """Point ``crm_test``'s stored ``public_origin`` at ``https://crm.test``, once per module.

  Module-scoped and ``autouse``: every test file under ``tests/inprocess``
  gets a correctly-pointed origin without asking, the same way
  ``live_server`` gives every ``live_server`` test one — mirrored here at
  module rather than session scope only because this fixture is cheap
  (one CLI call) and each test module under this package is independently
  runnable on its own (``pytest tests/inprocess/test_x.py``) without
  depending on collection order pulling in a sibling module's setup.

  Owner role (``manage set-origin``), its own subprocess — never through
  an in-process connection this fixture would have to hold open across
  every test in the module.

  Parameters
  ----------
  bootstrap_admin : ProvisionedUser
    **Not** ``crm_test_schema``: ``scripts/manage bootstrap`` — which
    provisions the one first administrator and writes
    ``provisioning_state = 'complete'`` — refuses outright
    (``AlreadyProvisioned``, exit 3) once a ``public_origin`` row already
    exists (``app/services/accounts.py::bootstrap``). Depending on
    ``bootstrap_admin`` here, exactly like ``live_server`` does, forces
    the ordering bootstrap (placeholder origin) -> **this fixture**
    (``https://crm.test``) -> every ``tests/inprocess`` test -> whichever
    ``live_server`` test runs first repoints it again, once, to its own
    ephemeral port. Depending on the weaker ``crm_test_schema`` instead
    would let ``tests/inprocess`` (collected first, ruling R57) write the
    origin *before* ``bootstrap`` ever runs, which would then make
    ``bootstrap`` itself fail for every later, ``live_server``-dependent
    test in the session — not a hypothetical, this was caught before it
    ever ran.
  tmp_path_factory : pytest.TempPathFactory
    For the one subprocess log, which nothing here prints.
  """
  del bootstrap_admin
  log_path = tmp_path_factory.mktemp("inprocess_set_origin") / "set-origin.log"
  run_with_env(
    OWNER_ENV_FILE,
    str(VENV_PYTHON),
    "-B",
    str(MANAGE),
    "set-origin",
    "--origin",
    INPROCESS_ORIGIN,
    log_path=log_path,
  )


@pytest_asyncio.fixture
async def in_process_app(clock: ManualClock) -> AsyncIterator[FastAPI]:
  """Build ``create_app(clock=clock)`` and run its lifespan for the duration of one test.

  Parameters
  ----------
  clock : ManualClock
    The instance this test will advance; every clock-dependent service the
    lifespan builds (``PasswordService``, ``ThrottleService``,
    ``BudgetService``, the origin/readiness caches,
    ``CorrelationMiddleware``) receives this exact object (**R54**).

  Yields
  ------
  fastapi.FastAPI
    With its lifespan already entered (``app.state.context`` is set) —
    ``in_process_client`` can drive it immediately. Torn down (pool
    closed) when the test finishes, whether it passed or failed.

  Notes
  -----
  ``password_hasher`` is left at its default (the real, pinned production
  profile — R54's own default), deliberately, even though it costs real
  Argon2 time on every hash in these tests: the fast test profile
  (``fast_password_hasher``, §7.4) exists for *fixture setup that seeds
  many users*, not for driving the actual login path a test asserts on,
  and the throttle/budget tests in this package pass hashing time as part
  of what they exercise.

  Reads its configuration through ``app.config.load_config()`` with no
  explicit mapping (the same as every other in-process fixture in this
  suite), which means, per the canonical invocation
  (``tests/README.md``), the test *process itself* must already be running
  under ``scripts/with-env .env.test.local -- ...``.
  """
  from app.main import create_app

  application = create_app(clock=clock)
  async with application.router.lifespan_context(application):
    yield application


@pytest_asyncio.fixture
async def in_process_client(in_process_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
  """One httpx client driving ``in_process_app`` through ``httpx.ASGITransport`` (R54).

  Parameters
  ----------
  in_process_app : fastapi.FastAPI
    The already-lifespan-entered app.

  Yields
  ------
  httpx.AsyncClient
    ``base_url=INPROCESS_ORIGIN`` (so every request carries ``Host:
    crm.test``, matching what ``_set_inprocess_origin`` stored),
    ``follow_redirects=False`` (a test inspects a ``303``'s ``Location``
    itself, exactly like ``live_server``'s clients), and the same
    ``Origin``-stamping request hook ``live_server``'s
    ``http_client_factory`` uses on unsafe methods, reused from
    ``conftest.py`` rather than duplicated (both transports need it for
    the identical reason: httpx never adds ``Origin`` on its own, unlike a
    browser).

  Notes
  -----
  No TLS, no socket, no subprocess: ``ASGITransport`` calls
  ``in_process_app``'s ASGI callable directly in this process. One client
  per test (fresh cookie jar), which is enough for every test in this
  package — none of them needs two independently-authenticated principals
  at once the way some ``live_server`` tests do.
  """
  transport = httpx.ASGITransport(app=in_process_app)
  async with httpx.AsyncClient(
    transport=transport,
    base_url=INPROCESS_ORIGIN,
    follow_redirects=False,
    timeout=10.0,
    event_hooks={"request": [_default_origin_on_unsafe_methods(INPROCESS_ORIGIN)]},
  ) as client:
    yield client


@pytest.fixture(autouse=True)
def _reset_throttle_and_budget_around_inprocess_tests(
  crm_test_schema: None, tmp_path: Path
) -> Iterator[None]:
  """Clear ``login_throttle``/``rate_budget`` before **and** after every test here.

  The same DB-shared, global counters ``test_throttle_and_budget.py``
  clears around its own (``live_server``-driven) tests — reused via
  ``conftest.clear_throttle_and_budget_state`` rather than a second copy
  of the DELETE snippet, since both modules exist to guard the identical
  two tables against cross-test leakage.

  Parameters
  ----------
  crm_test_schema : None
    Documents the real dependency (the two tables must exist); already
    satisfied regardless, since it is session-scoped autouse (R57).
  tmp_path : Path
    For the two owner-role subprocess logs.
  """
  del crm_test_schema
  clear_throttle_and_budget_state(log_path=tmp_path / "clear-before.log")
  yield
  clear_throttle_and_budget_state(log_path=tmp_path / "clear-after.log")
