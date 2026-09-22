"""The per-process objects a request handler is allowed to reach.

One frozen container, built once in the lifespan and stored on
``app.state``. Handlers, middleware and services take it as a parameter
instead of importing a module-level singleton, which is what keeps
``create_app`` free of global state and lets a test build a context of its
own without touching the process.

Nothing in here is read at import time, so ``import app.main`` still
contacts no database (``DEP-001``/``DEP-003``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
  from fastapi.templating import Jinja2Templates
  from starlette.requests import Request

  from app.config import Config
  from app.db.pool import Pool
  from app.security.clock import Clock
  from app.security.origin import OriginCache, ReadinessCache
  from app.security.passwords import PasswordService
  from app.security.throttle import BudgetService, ThrottleService

__all__ = ["AppContext", "context_of"]


@dataclass(frozen=True, slots=True)
class AppContext:
  """Everything a request needs that outlives the request.

  Attributes
  ----------
  config : Config
    The five-name configuration, read once at lifespan start.
  pool : Pool
    The one lazy connection pool. A request holds at most one connection
    from it at a time (``DATA_CONTRACT.md`` §6.1).
  clock : Clock
    The injected time source; the only clock anything reads.
  passwords : PasswordService
    Argon2 at the pinned parameters, behind the bounded hash gate.
  throttle : ThrottleService
    The per-account login throttle.
  budget : BudgetService
    The four ``rate_budget`` buckets.
  origin : OriginCache
    The stored ``public_origin``, cached for five seconds.
  readiness : ReadinessCache
    The ``/health/ready`` verdict, cached for five seconds.
  templates : Jinja2Templates
    The explicit Jinja environment of delta **D11**.
  """

  config: Config
  pool: Pool
  clock: Clock
  passwords: PasswordService
  throttle: ThrottleService
  budget: BudgetService
  origin: OriginCache
  readiness: ReadinessCache
  templates: Jinja2Templates


def context_of(request: Request) -> AppContext:
  """Return the context the lifespan put on this application.

  Parameters
  ----------
  request : Request
    The inbound request.

  Returns
  -------
  AppContext

  Raises
  ------
  RuntimeError
    If the application never started. That is a harness state, not a
    runtime one: uvicorn always runs the lifespan, so the only way here is
    an in-process client used without its context manager. Failing loudly
    beats handing a request a half-built application.
  """
  context = getattr(request.app.state, "context", None)
  if context is None:
    raise RuntimeError("the application lifespan has not run; there is no AppContext")
  return cast("AppContext", context)
