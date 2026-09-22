"""The ASGI application: construction, lifespan and the four middlewares.

There are no auto-generated API docs: ``/docs``, ``/redoc`` and
``/openapi.json`` are all disabled below.

**Nothing here connects to anything at import time.** ``create_app`` builds
an ASGI application and reads no environment variable; ``load_config`` and
``create_pool`` run inside the lifespan, and the pool is opened with
``wait=False`` at ``min_size=0``, so the first connection is attempted by
the first request that needs one. The test suite asserts that by importing
this module with the five names absent, and again with them pointing at an
unroutable host.

**The injection seam.** ``create_app`` takes an optional ``config``,
``clock`` and ``password_hasher``. Each defaults to the production object,
so the served process behaves exactly as before; passing them is how an
in-process test drives the whole application through
``httpx.ASGITransport`` with a ``ManualClock``, entering the lifespan with
``async with app.router.lifespan_context(app):``. The **same** clock
instance reaches ``CorrelationMiddleware`` and every service the lifespan
builds, so advancing it moves the entire application's notion of time and
no expiry test has to sleep.

Middleware order, outermost first — each wraps everything below it, so a
failure deep in the stack still carries a correlation id and the security
headers:

===  ==============================  ==================================
 #   Middleware                      Responsibility
===  ==============================  ==================================
 1   ``CorrelationMiddleware``       mint the id, time the request, emit
                                     the one JSON log line
 2   ``SecurityHeadersMiddleware``   the one header set on **every**
                                     response, errors and health included
 3   ``BodySizeLimitMiddleware``     64 KiB, refused **before** any
                                     handler reads a byte
 4   ``OriginHostMiddleware``        step 0a: ``Host``/``Origin`` against
                                     the stored origin; ``/health/*``
                                     exempt entirely
===  ==============================  ==================================

``add_middleware`` prepends, so the calls at the bottom of
:func:`create_app` are written in the reverse of that order.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from fastapi import FastAPI
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.staticfiles import StaticFiles

from app.config import load_config
from app.db.pool import close_pool, create_pool, open_pool
from app.db.retry import AmbiguousCommit, RetryExhausted, TransactionRunner
from app.logging import configure_logging, log_request, log_unhandled, new_correlation_id
from app.logging import set_correlation_id as bind_correlation_id
from app.routes import activities as activity_routes
from app.routes import auth as auth_routes
from app.routes import contacts as contact_routes
from app.routes import dashboard as dashboard_routes
from app.routes import deals as deal_routes
from app.routes import health as health_routes
from app.routes.errors import (
  ambiguous_commit_handler,
  budget_handler,
  contact_not_found_handler,
  deal_not_found_handler,
  forbidden,
  forced_reset_handler,
  hash_queue_handler,
  http_exception_handler,
  no_session_handler,
  not_provisioned_handler,
  payload_too_large,
  retry_exhausted_handler,
  role_required_handler,
  step_zero_handler,
  too_large_handler,
  unavailable,
  unhandled_exception_handler,
)
from app.routes.rendering import TEMPLATES
from app.security.clock import SystemClock
from app.security.context import AppContext
from app.security.failures import (
  BudgetExceeded,
  ContactNotFound,
  DealNotFound,
  ForcedResetRequired,
  NoSession,
  NotProvisioned,
  RoleRequired,
  StepZeroDenied,
  TooLarge,
)
from app.security.headers import SecurityHeadersMiddleware
from app.security.origin import STATE_ORIGIN, OriginCache, ReadinessCache, authority_of
from app.security.passwords import (
  DEFAULT_BLOCKLIST,
  HashQueueFull,
  PasswordService,
  production_hasher,
)
from app.security.throttle import BudgetService, ThrottleService

if TYPE_CHECKING:
  from collections.abc import AsyncIterator, Awaitable, Callable

  from argon2 import PasswordHasher
  from starlette.responses import Response
  from starlette.types import ASGIApp, Message, Receive, Scope, Send

  from app.config import Config
  from app.security.clock import Clock

__all__ = [
  "MAX_BODY_BYTES",
  "BodySizeLimitMiddleware",
  "CorrelationMiddleware",
  "OriginHostMiddleware",
  "app",
  "create_app",
  "lifespan",
]

#: 64 KiB. Every form in this application is a handful of short fields; a
#: body above this is a crafted request, not a user.
MAX_BODY_BYTES: Final = 65_536

_STATIC_DIR: Final = Path(__file__).resolve().parent / "static"
_SAFE_METHODS: Final[frozenset[str]] = frozenset({"GET", "HEAD", "OPTIONS"})


class _BodyTooLarge(Exception):
  """Internal signal from the counting receive channel."""


class CorrelationMiddleware(BaseHTTPMiddleware):
  """Mint the correlation id, time the request, emit the one log line."""

  def __init__(self, app: ASGIApp, *, clock: Clock) -> None:
    """Wrap ``app`` with the injected clock.

    Parameters
    ----------
    app : ASGIApp
      The rest of the stack.
    clock : Clock
      The one time source; ``monotonic()`` measures the request, because
      a wall-clock adjustment mid-request must not produce a negative
      duration.
    """
    super().__init__(app)
    self._clock = clock

  async def dispatch(
    self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
  ) -> Response:
    """Bind the id, run the request and log exactly one record.

    Parameters
    ----------
    request : Request
      The inbound request.
    call_next : Callable[[Request], Awaitable[Response]]
      The rest of the stack.

    Returns
    -------
    Response

    Notes
    -----
    The id is bound to a :class:`contextvars.ContextVar` *before* the
    downstream task is created, so the same value is visible to every
    handler, every audit row and — through the outer
    ``ServerErrorMiddleware`` — to the ``500`` page an unhandled exception
    produces. An exception is logged as ``unhandled:<ClassName>`` with no
    message and no traceback, then re-raised for that page to be rendered.
    """
    correlation_id = new_correlation_id()
    bind_correlation_id(correlation_id)
    started = self._clock.monotonic()
    method = request.method
    path = request.url.path
    try:
      response = await call_next(request)
    except Exception as error:
      log_unhandled(
        method=method,
        path=path,
        duration_ms=(self._clock.monotonic() - started) * 1000.0,
        correlation_id=correlation_id,
        exception_class=type(error).__name__,
      )
      raise
    principal = getattr(request.state, "crm_principal", None)
    log_request(
      method=method,
      path=path,
      status=response.status_code,
      duration_ms=(self._clock.monotonic() - started) * 1000.0,
      correlation_id=correlation_id,
      actor_id=None if principal is None else str(principal.id),
    )
    return response


class BodySizeLimitMiddleware:
  """Refuse a body above the cap before any handler can read one byte."""

  def __init__(self, app: ASGIApp, *, max_bytes: int = MAX_BODY_BYTES) -> None:
    """Wrap ``app`` with a byte cap.

    Parameters
    ----------
    app : ASGIApp
      The rest of the stack.
    max_bytes : int, optional
      The cap, in bytes.
    """
    self.app = app
    self.max_bytes = max_bytes

  async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
    """Count the body and fail the request at the cap.

    Parameters
    ----------
    scope : Scope
      The ASGI scope.
    receive : Receive
      The upstream receive channel.
    send : Send
      The upstream send channel.

    Notes
    -----
    Pure ASGI rather than ``BaseHTTPMiddleware`` because the cap has to sit
    on the *receive* channel: a declared ``Content-Length`` is refused
    outright, and a chunked body is counted message by message so a client
    that lies about its length is still stopped. Once the response has
    started there is nothing safe to do but re-raise — the status line is
    already on the wire.
    """
    if scope["type"] != "http":
      await self.app(scope, receive, send)
      return

    request = Request(scope, receive)
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > self.max_bytes:
      response = await payload_too_large(request)
      await response(scope, receive, send)
      return

    counted = 0
    started = False

    async def _receive() -> Message:
      nonlocal counted
      message = await receive()
      if message["type"] == "http.request":
        counted += len(message.get("body", b""))
        if counted > self.max_bytes:
          raise _BodyTooLarge
      return message

    async def _send(message: Message) -> None:
      nonlocal started
      if message["type"] == "http.response.start":
        started = True
      await send(message)

    try:
      await self.app(scope, _receive, _send)
    except _BodyTooLarge:
      if started:
        raise
      response = await payload_too_large(request)
      await response(scope, receive, send)


class OriginHostMiddleware(BaseHTTPMiddleware):
  """Step 0a: ``Host`` and ``Origin`` against the origin stored in the database."""

  async def dispatch(
    self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
  ) -> Response:
    """Compare, then either continue or refuse.

    Parameters
    ----------
    request : Request
      The inbound request.
    call_next : Callable[[Request], Awaitable[Response]]
      The rest of the stack.

    Returns
    -------
    Response
      The downstream response, or ``403`` (``errors/403.html``,
      ``reason="session"``, public shell) or ``503`` when nothing is
      provisioned.

    Notes
    -----
    Runs **before routing**, so a spoofed ``Host`` on an unknown path is
    ``403`` and not ``404``: a wrong-host request must not be able to
    enumerate which paths exist.

    The rules: ``Host`` must equal the stored origin's authority on
    **every** non-health request and method; an
    ``Origin`` header, when present, must equal the stored origin exactly,
    on safe methods too; an **absent** ``Origin`` is refused on an unsafe
    method and served on a safe one, because browsers do not send it on an
    ordinary navigation.

    ``X-Forwarded-Host``/``-Proto``/``-For`` are never consulted, here or
    anywhere else, and uvicorn runs with ``--no-proxy-headers`` so they
    cannot rewrite the scope either. The process always serves plain HTTP;
    the *stored* origin is what says which scheme the browser is on, and
    this is the one place that reads it, so everything scheme-dependent
    further down — the session cookie's name and ``Secure`` flag,
    ``Strict-Transport-Security`` — reads the value recorded here
    (``request.state.crm_origin``) instead of deciding for itself.

    Any failure while reading the origin — the database is down, the pool
    cannot hand out a connection — is answered ``503``. Fail closed: an
    application that cannot tell which origin it is must not accept a
    cross-site request on the strength of not knowing.
    """
    if request.url.path in health_routes.HEALTH_PATHS:
      return await call_next(request)

    context = getattr(request.app.state, "context", None)
    if context is None:
      return await unavailable(request)

    try:
      origin = await context.origin.get()
    # Fail closed on any read failure: an application that cannot tell
    # which origin it is must not accept a cross-site request on the
    # strength of not knowing.
    except Exception:
      return await unavailable(request)
    if not origin:
      return await unavailable(request)

    # Recorded before the two comparisons, so the ``403`` they produce
    # carries the same header set a served response would.
    setattr(request.state, STATE_ORIGIN, origin)

    if request.headers.get("host", "").casefold() != authority_of(origin):
      return await forbidden(request)

    submitted = request.headers.get("origin")
    if submitted is not None:
      if submitted.strip() != origin:
        return await forbidden(request)
    elif request.method not in _SAFE_METHODS:
      return await forbidden(request)

    return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
  """Build the process-wide context, and tear it down again.

  Parameters
  ----------
  app : FastAPI
    The application being started.

  Yields
  ------
  None

  Notes
  -----
  Order: ``load_config()`` →
  ``create_pool(config)`` → the origin cache → the readiness cache; the
  reverse on exit. ``open_pool`` uses ``wait=False`` against
  ``min_size=0``, so it starts the pool's bookkeeping without opening a
  single connection — the first real connection is made by the first
  request that needs one, which is what keeps a database that is down at
  boot from producing a container that never becomes live.

  The clock was resolved by :func:`create_app` and is read back from
  ``app.state`` here, so the one object that timed the request in
  ``CorrelationMiddleware`` is the same one every service in the context
  reads — a test that advances a :class:`app.security.clock.ManualClock`
  moves the whole application, not half of it. The Argon2 hasher is
  resolved *here* rather than in :func:`create_app` because
  :class:`PasswordService`'s constructor computes the dummy hash, ~20 ms of
  work that belongs to starting the application and not to building it.
  """
  configured: Config | None = getattr(app.state, "bootstrap_config", None)
  config = load_config() if configured is None else configured
  pool = create_pool(config)
  await open_pool(pool)
  injected_clock: Clock | None = getattr(app.state, "bootstrap_clock", None)
  clock: Clock = SystemClock() if injected_clock is None else injected_clock
  injected_hasher: PasswordHasher | None = getattr(app.state, "bootstrap_password_hasher", None)
  hasher = production_hasher() if injected_hasher is None else injected_hasher
  passwords = PasswordService(hasher, blocklist=DEFAULT_BLOCKLIST, clock=clock)
  app.state.context = AppContext(
    config=config,
    pool=pool,
    # The one runner, over the one pool, carrying the application clock.
    # Its `sleep` and `jitter` keep their production defaults here;
    # a test builds its own runner with recording hooks.
    runner=TransactionRunner(pool, clock=clock),
    clock=clock,
    passwords=passwords,
    throttle=ThrottleService(pool, clock),
    budget=BudgetService(pool, clock),
    origin=OriginCache(pool, clock),
    readiness=ReadinessCache(pool, clock),
    templates=TEMPLATES,
  )
  try:
    yield
  finally:
    app.state.context = None
    await close_pool(pool)


def create_app(
  *,
  config: Config | None = None,
  clock: Clock | None = None,
  password_hasher: PasswordHasher | None = None,
) -> FastAPI:
  """Build the ASGI application.

  Parameters
  ----------
  config : Config | None, optional
    A pre-built configuration for the lifespan to use instead of reading
    the environment. Used by a harness that wants to point the same code
    at another database; ``None`` — the production path — means
    ``load_config()`` inside the lifespan.
  clock : Clock | None, optional
    The one time source for this application. ``None`` — the
    production path — means :class:`app.security.clock.SystemClock`. The
    instance passed here is the instance ``CorrelationMiddleware`` times
    the request with **and** the instance every service in the lifespan's
    context receives, so an in-process test that advances a
    :class:`app.security.clock.ManualClock` moves every expiry, window and
    TTL in the application at once. Nothing selects it from the
    environment: it is a parameter, which is what keeps the rule "one clock,
    injected" true of the whole tree.
  password_hasher : PasswordHasher | None, optional
    The Argon2 hasher :class:`app.security.passwords.PasswordService` is
    built around. ``None`` means
    :func:`app.security.passwords.production_hasher` — the pinned
    parameters. A test may pass a documented fast profile; no environment
    variable and no branch anywhere can.

  Returns
  -------
  FastAPI
    With ``docs_url``, ``redoc_url`` and ``openapi_url`` all disabled, so
    ``/docs``, ``/redoc`` and ``/openapi.json`` are simply not routes
   . An interactive schema browser is an attack surface and
    a disclosure surface that a tutorial CRM has no use for.

  Notes
  -----
  Reads no environment variable and opens no connection: everything that
  needs either happens in :func:`lifespan`. The three parameters are
  carried on ``application.state`` rather than closed over, so the lifespan
  can read them without this function having to run any of the work they
  describe.
  """
  configure_logging(sys.stdout)
  application = FastAPI(
    title="Demo_App_CRM",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
  )
  resolved_clock: Clock = SystemClock() if clock is None else clock
  application.state.bootstrap_config = config
  application.state.bootstrap_clock = resolved_clock
  application.state.bootstrap_password_hasher = password_hasher
  application.state.context = None

  application.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
  application.include_router(health_routes.router)
  application.include_router(auth_routes.router)
  application.include_router(contact_routes.router)
  # After the contact table, and with `/deals/pipeline` declared before
  # `/deals/{deal_id}` inside it: Starlette matches in registration order,
  # and the other way round the literal path would be read as a
  # non-canonical deal id and answered 404.
  application.include_router(deal_routes.router)
  # After the contact table, because `GET /contacts/{contact_id}/timeline` is
  # a contact-scoped region and its sibling paths are declared there; the two
  # tables hold no overlapping path.
  application.include_router(activity_routes.router)
  application.include_router(dashboard_routes.router)

  handlers: dict[Any, Any] = {
    StarletteHTTPException: http_exception_handler,
    StepZeroDenied: step_zero_handler,
    NotProvisioned: not_provisioned_handler,
    NoSession: no_session_handler,
    ForcedResetRequired: forced_reset_handler,
    RoleRequired: role_required_handler,
    BudgetExceeded: budget_handler,
    HashQueueFull: hash_queue_handler,
    TooLarge: too_large_handler,
    ContactNotFound: contact_not_found_handler,
    DealNotFound: deal_not_found_handler,
    AmbiguousCommit: ambiguous_commit_handler,
    RetryExhausted: retry_exhausted_handler,
    Exception: unhandled_exception_handler,
  }
  for exception_class, handler in handlers.items():
    application.add_exception_handler(exception_class, handler)

  # Reverse of the contracted order: add_middleware prepends, so the last
  # call here is the outermost middleware.
  application.add_middleware(OriginHostMiddleware)
  application.add_middleware(BodySizeLimitMiddleware)
  application.add_middleware(SecurityHeadersMiddleware)
  application.add_middleware(CorrelationMiddleware, clock=resolved_clock)
  return application


app = create_app()
