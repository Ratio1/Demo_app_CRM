"""The ASGI application: construction, lifespan and the four middlewares.

Authority: ``slice-a.md`` §1.1 (the lifespan order and the middleware
table), §2.1 (step 0a, before routing), §2.3 (the 64 KiB body cap), §2.5
(the health exemption), §2.6 (the header set), ``SEC-063`` (no auto-docs).

**Nothing here connects to anything at import time.** ``create_app`` builds
an ASGI application and reads no environment variable; ``load_config`` and
``create_pool`` run inside the lifespan, and the pool is opened with
``wait=False`` at ``min_size=0``, so the first connection is attempted by
the first request that needs one. That is what ``DEP-001``/``DEP-003``
assert by importing this module with the five names absent, and with them
pointing at an unroutable host.

Middleware order, outermost first — each wraps everything below it, so a
failure deep in the stack still carries a correlation id and the security
headers:

===  ==============================  ==================================
 #   Middleware                      Responsibility
===  ==============================  ==================================
 1   ``CorrelationMiddleware``       mint the id, time the request, emit
                                     the one JSON log line
 2   ``SecurityHeadersMiddleware``   the §2.6 header set on **every**
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
from app.logging import configure_logging, log_request, log_unhandled, new_correlation_id
from app.logging import set_correlation_id as bind_correlation_id
from app.routes import auth as auth_routes
from app.routes import health as health_routes
from app.routes.errors import (
  budget_handler,
  forbidden,
  forced_reset_handler,
  hash_queue_handler,
  http_exception_handler,
  no_session_handler,
  not_provisioned_handler,
  payload_too_large,
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
  ForcedResetRequired,
  NoSession,
  NotProvisioned,
  RoleRequired,
  StepZeroDenied,
  TooLarge,
)
from app.security.headers import SecurityHeadersMiddleware
from app.security.origin import OriginCache, ReadinessCache, authority_of
from app.security.passwords import (
  DEFAULT_BLOCKLIST,
  HashQueueFull,
  PasswordService,
  production_hasher,
)
from app.security.throttle import BudgetService, ThrottleService

if TYPE_CHECKING:
  from collections.abc import AsyncIterator, Awaitable, Callable

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
#: body above this is a crafted request, not a user (``SEC-004``).
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
      duration (``ARC-019``).
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
      await payload_too_large(request)(scope, receive, send)
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
      await payload_too_large(request)(scope, receive, send)


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

    The rules, from ``slice-a.md`` §2.1: ``Host`` must equal the stored
    origin's authority on **every** non-health request and method; an
    ``Origin`` header, when present, must equal the stored origin exactly,
    on safe methods too; an **absent** ``Origin`` is refused on an unsafe
    method and served on a safe one, because browsers do not send it on an
    ordinary navigation.

    ``X-Forwarded-Host``/``-Proto``/``-For`` are never consulted, here or
    anywhere else, and uvicorn runs with ``--no-proxy-headers`` so they
    cannot rewrite the scope either (``SEC-041``).

    Any failure while reading the origin — the database is down, the pool
    cannot hand out a connection — is answered ``503``. Fail closed: an
    application that cannot tell which origin it is must not accept a
    cross-site request on the strength of not knowing.
    """
    if request.url.path in health_routes.HEALTH_PATHS:
      return await call_next(request)

    context = getattr(request.app.state, "context", None)
    if context is None:
      return unavailable(request)

    try:
      origin = await context.origin.get()
    # Fail closed on any read failure: an application that cannot tell
    # which origin it is must not accept a cross-site request on the
    # strength of not knowing.
    except Exception:
      return unavailable(request)
    if not origin:
      return unavailable(request)

    if request.headers.get("host", "").casefold() != authority_of(origin):
      return forbidden(request)

    submitted = request.headers.get("origin")
    if submitted is not None:
      if submitted.strip() != origin:
        return forbidden(request)
    elif request.method not in _SAFE_METHODS:
      return forbidden(request)

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
  Order (binding, ``slice-a.md`` §1.1): ``load_config()`` →
  ``create_pool(config)`` → the origin cache → the readiness cache; the
  reverse on exit. ``open_pool`` uses ``wait=False`` against
  ``min_size=0``, so it starts the pool's bookkeeping without opening a
  single connection — the first real connection is made by the first
  request that needs one, which is what keeps a database that is down at
  boot from producing a container that never becomes live.
  """
  configured: Config | None = getattr(app.state, "bootstrap_config", None)
  config = load_config() if configured is None else configured
  pool = create_pool(config)
  await open_pool(pool)
  clock = SystemClock()
  passwords = PasswordService(production_hasher(), blocklist=DEFAULT_BLOCKLIST, clock=clock)
  app.state.context = AppContext(
    config=config,
    pool=pool,
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


def create_app(*, config: Config | None = None) -> FastAPI:
  """Build the ASGI application.

  Parameters
  ----------
  config : Config | None, optional
    A pre-built configuration for the lifespan to use instead of reading
    the environment. Used by a harness that wants to point the same code
    at another database; ``None`` — the production path — means
    ``load_config()`` inside the lifespan.

  Returns
  -------
  FastAPI
    With ``docs_url``, ``redoc_url`` and ``openapi_url`` all disabled, so
    ``/docs``, ``/redoc`` and ``/openapi.json`` are simply not routes
    (``SEC-063``). An interactive schema browser is an attack surface and
    a disclosure surface that a tutorial CRM has no use for.

  Notes
  -----
  Reads no environment variable and opens no connection: everything that
  needs either happens in :func:`lifespan`.
  """
  configure_logging(sys.stdout)
  application = FastAPI(
    title="Demo_App_CRM",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
  )
  application.state.bootstrap_config = config
  application.state.context = None

  application.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
  application.include_router(health_routes.router)
  application.include_router(auth_routes.router)

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
    Exception: unhandled_exception_handler,
  }
  for exception_class, handler in handlers.items():
    application.add_exception_handler(exception_class, handler)

  # Reverse of the contracted order: add_middleware prepends, so the last
  # call here is the outermost middleware.
  application.add_middleware(OriginHostMiddleware)
  application.add_middleware(BodySizeLimitMiddleware)
  application.add_middleware(SecurityHeadersMiddleware)
  application.add_middleware(CorrelationMiddleware, clock=SystemClock())
  return application


app = create_app()
