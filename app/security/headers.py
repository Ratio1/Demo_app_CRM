"""The response header set, applied to every response.

One table, one middleware, no per-route exceptions: a header that is only
set on the routes someone remembered is not a control. Two values vary, each
on one visible axis. ``Cache-Control``: static assets are public and
cacheable, everything else is ``no-store``. ``Strict-Transport-Security``:
sent when the stored public origin is an ``https://`` one and omitted
otherwise, because the header is meaningless — and, on a plain-HTTP local
run, a promise nothing can keep — when the browser is not on TLS. Nothing
in the environment can move either one.

There is no CORS middleware anywhere in this application and no
``Access-Control-*`` header is ever emitted; the browser's
same-origin policy is the boundary, and the exact ``Origin`` check on every
unsafe request is what enforces it server-side.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from starlette.middleware.base import BaseHTTPMiddleware

from app.security.origin import is_https_origin, origin_of

if TYPE_CHECKING:
  from collections.abc import Awaitable, Callable

  from starlette.requests import Request
  from starlette.responses import Response

__all__ = [
  "CACHE_CONTROL_PRIVATE",
  "CACHE_CONTROL_STATIC",
  "SECURITY_HEADERS",
  "STATIC_PREFIX",
  "STRICT_TRANSPORT_SECURITY",
  "SecurityHeadersMiddleware",
  "apply_security_headers",
]

#: ``img-src`` is ``'self'`` with **no** ``data:``: nothing in the
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

#: Every header that is the same on every response. ``Cache-Control`` and
#: ``Strict-Transport-Security`` are not here because they are the two that
#: vary; ``Retry-After`` and ``Clear-Site-Data`` are per-response and set by
#: their own handlers.
SECURITY_HEADERS: Final[dict[str, str]] = {
  "Content-Security-Policy": CONTENT_SECURITY_POLICY,
  "X-Content-Type-Options": "nosniff",
  # `same-origin`, never `no-referrer`. Per the Fetch standard a browser
  # serializes `Origin: null` on a non-GET/HEAD request whose referrer policy
  # is `no-referrer`, so with `no-referrer` every real-browser form POST is
  # refused by the exact-`Origin` check — httpx-driven tests never see it,
  # because httpx sets `Origin` itself. `same-origin` keeps the full `Origin`
  # on same-origin POSTs and sends nothing cross-origin, so the CSRF control
  # and the privacy goal both hold.
  "Referrer-Policy": "same-origin",
  "Permissions-Policy": PERMISSIONS_POLICY,
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
}

#: One year, subdomains included, no ``preload``: preloading is a public,
#: hard-to-reverse registration and is the deployer's decision, not this
#: application's.
STRICT_TRANSPORT_SECURITY: Final = "max-age=31536000; includeSubDomains"

CACHE_CONTROL_PRIVATE: Final = "no-store"
CACHE_CONTROL_STATIC: Final = "public, max-age=300"
STATIC_PREFIX: Final = "/static/"


def apply_security_headers(response: Response, *, path: str, origin: str | None = None) -> Response:
  """Set the pinned header set on ``response``, in place.

  Parameters
  ----------
  response : Response
    Any response, including one built inside a middleware or an exception
    handler, which never passes back through the middleware stack.
  path : str
    ``request.url.path``, used only to choose the ``Cache-Control`` value.
  origin : str | None, optional
    The stored public origin for this request
    (:func:`app.security.origin.origin_of`). It decides
    ``Strict-Transport-Security`` and nothing else. The default, ``None``,
    omits that one header — which is what an unprovisioned deployment and
    a request refused before the origin was read both get.

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
  if is_https_origin(origin):
    response.headers["Strict-Transport-Security"] = STRICT_TRANSPORT_SECURITY
  response.headers["Cache-Control"] = (
    CACHE_CONTROL_STATIC if path.startswith(STATIC_PREFIX) else CACHE_CONTROL_PRIVATE
  )
  return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
  """Apply :func:`apply_security_headers` to every response.

  Second in the middleware order, so everything below
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
      The inbound request; its path is read, and — on the way out — the
      origin the ``Host``/``Origin`` check below recorded on it.
    call_next : Callable[[Request], Awaitable[Response]]
      The rest of the stack.

    Returns
    -------
    Response
      The downstream response, with the header set applied.

    Notes
    -----
    The origin is read *after* ``call_next``, because the middleware that
    resolves it sits below this one. A response produced before it ran —
    a health endpoint, an oversized body — carries no
    ``Strict-Transport-Security``.
    """
    response = await call_next(request)
    return apply_security_headers(response, path=request.url.path, origin=origin_of(request))
