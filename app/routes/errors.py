"""One place that turns a refusal into a page.

Authority: ``CONTRACTS.md`` §8.4 (the eight templates and their frozen
contexts), ``slice-a.md`` §3 (the ``HX-Request`` answer — **R26** — and the
always-public shell of ``500``/``503`` — **R32**), §4 (which status each
route may produce), ``R27`` (every step-0 failure is the same body),
``R37``/**R19** (``ambiguous_commit``), ``R38`` (the ``405`` context).

Two rules hold the anti-enumeration properties together:

*One body per status, whatever the cause.* Every step-0 failure — spoofed
``Host``, foreign ``Origin``, missing CSRF, stale CSRF, a mutation with no
session — renders ``errors/403.html`` with ``reason="session"`` and the
public shell. The correlation id is the only byte that differs, and the
tests that compare two bodies normalize it (``ACC-010``, ``SEC-040``).

*A fragment gets a fragment.* A request carrying ``HX-Request: true`` is
answered with ``partials/region_error.html`` and never with a whole
document, so htmx can never swap a full page into a region. The ``401``
and ``403`` auth cases additionally carry ``HX-Redirect``, which htmx acts
on before it looks at the status at all (verified against 2.0.10,
``slice-a.md`` §8.4).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlencode

from starlette.exceptions import HTTPException
from starlette.responses import RedirectResponse, Response

from app.logging import current_correlation_id
from app.routes.rendering import base_context, csrf_token_for_request, render
from app.security.headers import apply_security_headers
from app.security.origin import is_safe_relative
from app.security.sessions import COOKIE_NAME

if TYPE_CHECKING:
  from starlette.requests import Request

  from app.security.principal import Principal

__all__ = [
  "DASHBOARD_URL",
  "LOGIN_URL",
  "PASSWORD_URL",
  "SAFE_METHODS",
  "budget_handler",
  "forbidden",
  "forced_reset_handler",
  "hash_queue_handler",
  "http_exception_handler",
  "is_fragment",
  "no_session_handler",
  "not_provisioned_handler",
  "region_error",
  "role_required_handler",
  "step_zero_handler",
  "too_large_handler",
  "too_many_requests",
  "unavailable",
  "unhandled_exception_handler",
]

#: The methods that never carry a body-changing intent.
SAFE_METHODS: Final[frozenset[str]] = frozenset({"GET", "HEAD", "OPTIONS"})

LOGIN_URL: Final = "/login"
PASSWORD_URL: Final = "/account/password"  # noqa: S105 — a route, not a secret
DASHBOARD_URL: Final = "/dashboard"

#: ``UX_FLOWS.md`` §6.2 / §6.1. The ``405`` page has no ``CP-##`` of its
#: own (``UX_FLOWS.md`` §3.8 fixes only the behaviour), so its heading and
#: body are supplied here as resolved strings, which is how ``R38``'s
#: "``message`` (a copy id)" is read: the value *is* the text, exactly as
#: ``notice.text`` already is elsewhere in this contract.
_CP_405_TITLE: Final = "That is not something you can do here"
_CP_405_MESSAGE: Final = "That request could not be processed. Go back and try again."

_REGION_TEXT: Final[dict[int, str]] = {
  401: "Your session ended. Sign in to continue.",
  403: "Set a new password to continue.",
  429: "Demo_App_CRM is busy with your requests. Wait a moment, then try again.",
  503: "Demo_App_CRM is temporarily unavailable. Nothing you did caused this.",
}


def is_fragment(request: Request) -> bool:
  """Return whether this request came from htmx.

  Parameters
  ----------
  request : Request
    The inbound request.

  Returns
  -------
  bool
    ``True`` when ``HX-Request: true`` is present. The header is
    client-supplied, so it decides only the *shape* of a response, never
    an authorization outcome.
  """
  return request.headers.get("hx-request", "").casefold() == "true"


def _principal_for_shell(request: Request) -> Principal | None:
  """Return the already-resolved principal, without any new database work.

  Parameters
  ----------
  request : Request
    The inbound request.

  Returns
  -------
  Principal | None
    Whatever step 1 resolved earlier in this request, or ``None`` when it
    never ran. An error handler must not open a connection: the failure
    it is rendering may well be that the database is gone.
  """
  principal: Principal | None = getattr(request.state, "crm_principal", None)
  return principal


def _error_page(
  request: Request,
  *,
  status: int,
  template: str,
  extra: dict[str, Any],
  public_shell: bool,
  headers: dict[str, str] | None = None,
) -> Response:
  """Render one full error page with the security headers already on it.

  Parameters
  ----------
  request : Request
    The inbound request.
  status : int
    The HTTP status.
  template : str
    The ``errors/*.html`` template.
  extra : dict[str, Any]
    The template's own frozen context, beyond the base.
  public_shell : bool
    ``True`` forces ``principal=None`` (**R32**): the ``500``, the ``503``
    and the step-0 ``403`` render the public shell whatever the real
    session state is, because a session may not be readable after an
    unhandled exception and a page that tries to read one can fail a
    second time inside the error path.
  headers : dict[str, str] | None, optional
    Extra headers, such as ``Retry-After``.

  Returns
  -------
  Response
  """
  principal = None if public_shell else _principal_for_shell(request)
  context = base_context(
    page_title=str(status),
    principal=principal,
    csrf_token="" if principal is None else csrf_token_for_request(request),
    private=True,
  )
  context.update(extra)
  response = render(request, template, context, status_code=status, headers=headers)
  return apply_security_headers(response, path=request.url.path)


def region_error(
  request: Request,
  *,
  status: int,
  redirect: str | None = None,
  retry_after: int | None = None,
) -> Response:
  """Render the compact fragment an htmx request gets instead of a page.

  Parameters
  ----------
  request : Request
    The inbound request.
  status : int
    The status to answer with — ``401`` for a dead session, ``403`` for a
    forced reset, ``429`` or ``503``.
  redirect : str | None, optional
    Value for ``HX-Redirect``. htmx acts on it before it consults the
    status, so a ``401`` redirects exactly as a ``200`` would while still
    being the honest status; if a proxy strips the header the body is
    swapped into the region and the user sees a real recovery link
    instead of nothing (**R26**).
  retry_after : int | None, optional
    Whole seconds, rendered in the fragment and sent as ``Retry-After``.

  Returns
  -------
  Response
  """
  headers: dict[str, str] = {}
  if redirect is not None:
    headers["HX-Redirect"] = redirect
  if retry_after is not None:
    headers["Retry-After"] = str(retry_after)
  context = {
    "status": status,
    "text": _REGION_TEXT.get(status, _REGION_TEXT[503]),
    "retry_after": retry_after,
  }
  response = render(
    request,
    "partials/region_error.html",
    context,
    status_code=status,
    headers=headers or None,
  )
  return apply_security_headers(response, path=request.url.path)


def forbidden(request: Request, *, reason: str = "session") -> Response:
  """Render the ``403`` of ``slice-a.md`` §2.1.

  Parameters
  ----------
  request : Request
    The inbound request.
  reason : str, optional
    ``session`` (step 0 — the default and the only one Slice A reaches
    from a route), ``role`` or ``forced_reset``.

  Returns
  -------
  Response
    ``reason="session"`` renders the public shell unconditionally, so the
    body cannot report whether the caller had a session.
  """
  if is_fragment(request) and reason == "forced_reset":
    return region_error(request, status=403, redirect=PASSWORD_URL)
  return _error_page(
    request,
    status=403,
    template="errors/403.html",
    extra={"reason": reason, "correlation_id": current_correlation_id()},
    public_shell=reason == "session",
  )


def unavailable(request: Request, *, context: str = "unavailable") -> Response:
  """Render the ``503`` page, always in the public shell (**R32**).

  Parameters
  ----------
  request : Request
    The inbound request.
  context : str, optional
    ``unavailable`` (the database is down, or the deployment is not
    provisioned — one body for both, so an outsider cannot tell a fresh
    deployment from a broken one) or ``ambiguous_commit`` (**R19**,
    **R37**).

  Returns
  -------
  Response
    Carries ``Retry-After``, because a ``503`` here is always a busy or
    not-yet-ready state rather than a permanent one.
  """
  if is_fragment(request):
    return region_error(request, status=503, retry_after=5)
  return _error_page(
    request,
    status=503,
    template="errors/503.html",
    extra={
      "context": context,
      "record_url": None,
      "correlation_id": current_correlation_id(),
    },
    public_shell=True,
    headers={"Retry-After": "5"},
  )


def too_many_requests(request: Request, *, retry_after_s: int) -> Response:
  """Render the non-login ``429`` page.

  Parameters
  ----------
  request : Request
    The inbound request.
  retry_after_s : int
    Whole seconds until the window rolls; never a fixed long value, so the
    advertised recovery matches the real one (``SEC-031``(c)).

  Returns
  -------
  Response
  """
  if is_fragment(request):
    return region_error(request, status=429, retry_after=retry_after_s)
  return _error_page(
    request,
    status=429,
    template="errors/429.html",
    extra={
      "retry_after_seconds": retry_after_s,
      "correlation_id": current_correlation_id(),
    },
    public_shell=False,
    headers={"Retry-After": str(retry_after_s)},
  )


def not_found(request: Request) -> Response:
  """Render the ``404`` page — identical for a missing and a foreign object."""
  return _error_page(
    request,
    status=404,
    template="errors/404.html",
    extra={"back_url": DASHBOARD_URL, "correlation_id": current_correlation_id()},
    public_shell=False,
  )


def bad_request(request: Request) -> Response:
  """Render the generic ``400`` page for a crafted request."""
  return _error_page(
    request,
    status=400,
    template="errors/400.html",
    extra={"back_url": DASHBOARD_URL, "correlation_id": current_correlation_id()},
    public_shell=False,
  )


def method_not_allowed(request: Request) -> Response:
  """Render the ``405`` page with the 400-family context (**R38**)."""
  return _error_page(
    request,
    status=405,
    template="errors/405.html",
    extra={
      "status": 405,
      "title": _CP_405_TITLE,
      "message": _CP_405_MESSAGE,
      "correlation_id": current_correlation_id(),
    },
    public_shell=False,
  )


def payload_too_large(request: Request) -> Response:
  """Render the ``413`` page for a body above the 64 KiB cap."""
  return _error_page(
    request,
    status=413,
    template="errors/413.html",
    extra={"back_url": DASHBOARD_URL, "correlation_id": current_correlation_id()},
    public_shell=False,
  )


def internal_error(request: Request) -> Response:
  """Render the ``500`` page: public shell always, correlation id only."""
  return _error_page(
    request,
    status=500,
    template="errors/500.html",
    extra={"correlation_id": current_correlation_id()},
    public_shell=True,
  )


_STATUS_PAGES: Final[dict[int, Any]] = {
  400: bad_request,
  404: not_found,
  405: method_not_allowed,
  413: payload_too_large,
}


async def http_exception_handler(request: Request, exc: Exception) -> Response:
  """Render any :class:`HTTPException` the router or a handler raised.

  Parameters
  ----------
  request : Request
    The inbound request.
  exc : Exception
    The exception; a :class:`starlette.exceptions.HTTPException` in
    practice. Its ``detail`` is **never** rendered: Starlette's own
    defaults name the method and the path, and a handler's detail would
    be the one place a value could slip into a page.

  Returns
  -------
  Response
    The frozen page for that status, or the ``500`` page for a status
    Slice A does not register — a status with no page is a bug in this
    application, not something to improvise a body for.
  """
  status = exc.status_code if isinstance(exc, HTTPException) else 500
  if status == 403:
    return forbidden(request)
  if status == 429:
    return too_many_requests(request, retry_after_s=5)
  if status == 503:
    return unavailable(request)
  page = _STATUS_PAGES.get(status)
  if page is None:
    return internal_error(request)
  response: Response = page(request)
  return response


async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
  """Render the ``500`` page for anything that escaped a route.

  Parameters
  ----------
  request : Request
    The inbound request.
  exc : Exception
    The exception. Neither its message nor its traceback reaches the
    response or the log: the log line carries the **class name** only
    (``SEC-062``), and the page carries the correlation id that joins the
    two.

  Returns
  -------
  Response
  """
  del exc
  return internal_error(request)


async def step_zero_handler(request: Request, exc: Exception) -> Response:
  """Answer any step-0 refusal with the one shared ``403`` body."""
  del exc
  return forbidden(request)


async def not_provisioned_handler(request: Request, exc: Exception) -> Response:
  """Answer an unprovisioned deployment with the ``503`` page."""
  del exc
  return unavailable(request)


async def no_session_handler(request: Request, exc: Exception) -> Response:
  """Answer step 1's failure in the shape the request asked for.

  Parameters
  ----------
  request : Request
    The inbound request.
  exc : Exception
    The :class:`app.security.failures.NoSession` decision; carries nothing.

  Returns
  -------
  Response
    A fragment request gets ``401`` plus ``HX-Redirect`` (**R26**); a
    private ``GET`` gets ``303`` to the login page, carrying a validated
    ``next`` and — only when a cookie was actually presented — the
    ``session_ended`` notice, so a first-time visitor never reads "Your
    session ended"; an unsafe method gets the step-0 ``403``.
  """
  del exc
  if is_fragment(request):
    return region_error(request, status=401, redirect=f"{LOGIN_URL}?notice=session_ended")
  if request.method not in SAFE_METHODS:
    return forbidden(request)

  parameters: list[tuple[str, str]] = []
  target = request.url.path
  if is_safe_relative(target) and target != LOGIN_URL:
    parameters.append(("next", target))
  if request.cookies.get(COOKIE_NAME):
    parameters.append(("notice", "session_ended"))
  location = f"{LOGIN_URL}?{urlencode(parameters)}" if parameters else LOGIN_URL
  return apply_security_headers(RedirectResponse(location, status_code=303), path=request.url.path)


async def forced_reset_handler(request: Request, exc: Exception) -> Response:
  """Answer step 2's failure: ``403``, or ``HX-Redirect`` to the password page."""
  del exc
  return forbidden(request, reason="forced_reset")


async def role_required_handler(request: Request, exc: Exception) -> Response:
  """Answer step 3's failure with the role ``403``."""
  del exc
  return forbidden(request, reason="role")


async def budget_handler(request: Request, exc: Exception) -> Response:
  """Answer a budget or throttle refusal with a sanitized ``429``."""
  retry_after = getattr(exc, "retry_after_s", 5)
  return too_many_requests(request, retry_after_s=int(retry_after))


async def hash_queue_handler(request: Request, exc: Exception) -> Response:
  """Answer a full Argon2 gate with a sanitized ``429``.

  Parameters
  ----------
  request : Request
    The inbound request.
  exc : Exception
    The :class:`app.security.passwords.HashQueueFull` refusal.

  Returns
  -------
  Response
    ``Retry-After: 1`` — the gate drains in the time one hash takes
    (~20 ms), so anything longer would advertise a delay that is not real.
  """
  del exc
  return too_many_requests(request, retry_after_s=1)


async def too_large_handler(request: Request, exc: Exception) -> Response:
  """Answer an over-cap body with the ``413`` page."""
  del exc
  return payload_too_large(request)
