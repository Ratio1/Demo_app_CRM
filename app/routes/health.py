"""``/health/live`` and ``/health/ready`` (``slice-a.md`` §2.5, ``H-09``).

Both are exempt from **all** of step 0 — ``Host``, ``Origin`` and CSRF
alike — because a probe is made by an orchestrator that knows nothing about
the application's stored origin, and an unprovisioned deployment must still
be able to say so. The exemption is implemented once, in
``OriginHostMiddleware``, against these two exact paths.

Both bodies are fixed text. No schema version, no hostname, no reason, no
exception message: a readiness endpoint is the most-reachable surface an
application has, and the ``ReadyReport``'s condition names go to the log
only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from fastapi import APIRouter
from starlette.responses import PlainTextResponse

from app.security.context import context_of

if TYPE_CHECKING:
  from starlette.requests import Request
  from starlette.responses import Response

__all__ = ["HEALTH_PATHS", "router"]

router = APIRouter()

#: The two paths ``OriginHostMiddleware`` lets through untouched. An exact
#: set, not a prefix: ``/health/anything-else`` is an ordinary 404 and gets
#: the ordinary step-0 treatment first.
HEALTH_PATHS: Final[frozenset[str]] = frozenset({"/health/live", "/health/ready"})

_LIVE_BODY: Final = "live"
_READY_BODY: Final = "ready"
_NOT_READY_BODY: Final = "not ready"
_RETRY_AFTER_S: Final = "5"


@router.get("/health/live", name="health_live")
async def health_live() -> Response:
  """Answer that this process is running.

  Returns
  -------
  Response
    Always ``200`` with a fixed body. A process check only: it opens no
    connection, so a database outage never makes a healthy container look
    dead and get restarted into the same outage.
  """
  return PlainTextResponse(_LIVE_BODY)


@router.get("/health/ready", name="health_ready")
async def health_ready(request: Request) -> Response:
  """Answer whether this replica may serve against this database.

  Returns
  -------
  Response
    ``200`` only when every manifest triple is present **and verified**,
    ``provisioning_state`` is ``complete``, a ``public_origin`` row exists
    and at least one active administrator exists. Anything else — an
    unmigrated database, a database migrated by a newer image, an
    unprovisioned one, or one that cannot be reached at all — is ``503``
    with the same fixed body and a ``Retry-After``.

  Notes
  -----
  Any failure is "not ready": a probe that cannot tell must not answer
  yes. That includes the application having no context at all, which is
  what an unstarted process looks like.
  """
  context = getattr(request.app.state, "context", None)
  if context is None:
    return PlainTextResponse(
      _NOT_READY_BODY, status_code=503, headers={"Retry-After": _RETRY_AFTER_S}
    )
  try:
    report = await context_of(request).readiness.get()
    ready = report.ready
  # Every failure is "not ready", by design: a probe that cannot tell
  # must not answer yes.
  except Exception:
    ready = False
  if not ready:
    return PlainTextResponse(
      _NOT_READY_BODY, status_code=503, headers={"Retry-After": _RETRY_AFTER_S}
    )
  return PlainTextResponse(_READY_BODY)
