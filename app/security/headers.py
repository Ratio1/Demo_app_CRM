"""The response header set, applied to every response (``slice-a.md`` §2.6).

One table, one middleware, no per-route exceptions: a header that is only
set on the routes someone remembered is not a control. ``Cache-Control`` is
the single value that varies, and it varies on one visible axis — static
assets are public and cacheable, everything else is ``no-store``.

There is no CORS middleware anywhere in this application and no
``Access-Control-*`` header is ever emitted (``SEC-043``); the browser's
same-origin policy is the boundary, and the ``Origin`` check of §2.1 is what
enforces it server-side.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
  from collections.abc import Awaitable, Callable

  from starlette.requests import Request
  from starlette.responses import Response

__all__ = [
  "CACHE_CONTROL_PRIVATE",
  "CACHE_CONTROL_STATIC",
  "SECURITY_HEADERS",
  "STATIC_PREFIX",
  "SecurityHeadersMiddleware",
  "apply_security_headers",
]

#: ``img-src`` is ``'self'`` with **no** ``data:`` (**R49**): nothing in the
#: design set uses a ``data:`` image, and the source is re-added only with a
#: named consumer. The cross-file ``<use href="/static/img/icons.svg#…">``
#: sprite fetch is not an image-class request and falls to ``default-src``,
#: so dropping ``data:`` does not touch it.
CONTENT_SECURITY_POLICY: Final = (
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
  "connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; "
  "form-action 'self'"
)

PERMISSIONS_POLICY: Final = (
  "accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), "
  "gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), "
  "publickey-credentials-get=(), screen-wake-lock=(), usb=(), xr-spatial-tracking=()"
)

#: Every header that is the same on every response. ``Cache-Control`` is not
#: here because it is the one that varies; ``Retry-After`` and
#: ``Clear-Site-Data`` are per-response and set by their own handlers.
SECURITY_HEADERS: Final[dict[str, str]] = {
  "Content-Security-Policy": CONTENT_SECURITY_POLICY,
  "X-Content-Type-Options": "nosniff",
  # R50: `same-origin`, never `no-referrer`. Per the Fetch standard a browser
  # serializes `Origin: null` on a non-GET/HEAD request whose referrer policy
  # is `no-referrer`, so every real-browser form POST was refused by the
  # exact-`Origin` check of §2.1 step 0a — httpx-driven tests never saw it,
  # because httpx sets `Origin` itself. `same-origin` keeps the full `Origin`
  # on same-origin POSTs and sends nothing cross-origin, so the CSRF control
  # and the privacy goal both hold (SEC-027, T-44).
  "Referrer-Policy": "same-origin",
  "Permissions-Policy": PERMISSIONS_POLICY,
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
}

CACHE_CONTROL_PRIVATE: Final = "no-store"
CACHE_CONTROL_STATIC: Final = "public, max-age=300"
STATIC_PREFIX: Final = "/static/"


def apply_security_headers(response: Response, *, path: str) -> Response:
  """Set the pinned header set on ``response``, in place.

  Parameters
  ----------
  response : Response
    Any response, including one built inside a middleware or an exception
    handler, which never passes back through the middleware stack.
  path : str
    ``request.url.path``, used only to choose the ``Cache-Control`` value.

  Returns
  -------
  Response
    The same object, for convenience at a ``return`` site.

  Notes
  -----
  Assignment, never ``append``: a duplicated ``Content-Security-Policy`` is
  the intersection of both values in every browser, which turns a second
  copy into an accidental tightening or a confusing report. Idempotent, so
  a response that is decorated here *and* passes through the middleware
  ends up with exactly one of each.
  """
  for name, value in SECURITY_HEADERS.items():
    response.headers[name] = value
  response.headers["Cache-Control"] = (
    CACHE_CONTROL_STATIC if path.startswith(STATIC_PREFIX) else CACHE_CONTROL_PRIVATE
  )
  return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
  """Apply :func:`apply_security_headers` to every response.

  Second in the middleware order (``slice-a.md`` §1.1), so everything below
  it — the body-size limit, the ``Host``/``Origin`` check, the router, every
  error page and both health endpoints — is covered.
  """

  async def dispatch(
    self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
  ) -> Response:
    """Add the headers on the way out.

    Parameters
    ----------
    request : Request
      The inbound request; only its path is read.
    call_next : Callable[[Request], Awaitable[Response]]
      The rest of the stack.

    Returns
    -------
    Response
      The downstream response, with the header set applied.
    """
    response = await call_next(request)
    return apply_security_headers(response, path=request.url.path)
