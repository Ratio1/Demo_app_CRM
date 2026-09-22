"""One place that turns a refusal into a page.

Eight templates, one handler each, and no route renders a status page of
its own.

Three rules hold the anti-enumeration properties together:

*One body per status, whatever the cause.* Every step-0 failure — spoofed
``Host``, foreign ``Origin``, missing CSRF, stale CSRF, a mutation with no
session — renders ``errors/403.html`` with ``reason="session"`` and the
public shell. The correlation id is the only byte that differs, and the
tests that compare two bodies normalize it.

*A fragment gets a fragment.* A request carrying ``HX-Request: true`` is
answered with ``partials/region_error.html`` and never with a whole
document, so htmx can never swap a full page into a region. The ``401``
and ``403`` auth cases additionally carry ``HX-Redirect``, which htmx acts
on before it looks at the status at all (verified against htmx 2.0.10).

*A `4xx` shell follows the session; a `5xx` shell never asks*.
The ``400``/``403(role|forced_reset)``/``404``/``405``/``413``/``429``
pages resolve the principal once — from ``request.state`` when step 1
already ran, otherwise with one bounded read — so an authenticated user's
``404`` on an unrouted path is the **same body** as their ``404`` on a
foreign object, which is what "identical 404 **for one principal**"
 means. The ``500``, the ``503`` and the step-0
``403`` never read a session at all: after an unhandled
exception, or with the database gone, a page that tries to would fail a
second time inside the error path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlencode

from starlette.exceptions import HTTPException
from starlette.responses import RedirectResponse, Response

from app.logging import current_correlation_id
from app.routes.rendering import base_context, csrf_token_for_request, render
from app.security.audit import ACTION_ACCESS_DENIED, OBJECT_CONTACT, OBJECT_DEAL, record_denial
from app.security.headers import apply_security_headers
from app.security.origin import is_safe_relative
from app.security.principal import resolve_principal
from app.security.sessions import COOKIE_NAME

if TYPE_CHECKING:
  from starlette.requests import Request

  from app.security.principal import Principal

__all__ = [
  "CONTACTS_URL",
  "DASHBOARD_URL",
  "LOGIN_URL",
  "PASSWORD_URL",
  "SAFE_METHODS",
  "ambiguous_commit_handler",
  "bad_request",
  "budget_handler",
  "conflict",
  "contact_not_found_handler",
  "deal_not_found_handler",
  "forbidden",
  "forced_reset_handler",
  "hash_queue_handler",
  "http_exception_handler",
  "is_fragment",
  "no_session_handler",
  "not_found",
  "not_provisioned_handler",
  "redirect",
  "region_error",
  "retry_exhausted_handler",
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
CONTACTS_URL: Final = "/contacts"

#: The ``405`` page's heading and body, as resolved strings: the value *is*
#: the text, exactly as a notice's ``text`` already is.
_METHOD_NOT_ALLOWED_TITLE: Final = "That is not something you can do here"
_METHOD_NOT_ALLOWED_MESSAGE: Final = "That request could not be processed. Go back and try again."

_REGION_TEXT: Final[dict[int, str]] = {
  401: "Your session ended. Sign in to continue.",
  403: "Set a new password to continue.",
  429: "Demo_App_CRM is busy with your requests. Wait a moment, then try again.",
  503: "Demo_App_CRM is temporarily unavailable. Nothing you did caused this.",
}

#: The ``401`` fragment body is a **pair**, selected by whether a session
#: cookie was presented — the same evidence the ``?notice=session_ended``
#: suffix uses. With a cookie the region keeps the two sentences above;
#: **without one**, "Your session ended" is
#: a claim about a client that never had a session, so the region says only
#: this. One rule, both shapes: a first-time visitor is never told a session
#: ended, whether they asked for a page or for a fragment.
_REGION_TEXT_401_COOKIELESS: Final = "Sign in to continue."


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


async def _principal_for_shell(request: Request) -> Principal | None:
  """Return the principal whose shell this 4xx page renders in.

  Parameters
  ----------
  request : Request
    The inbound request.

  Returns
  -------
  Principal | None
    Whatever step 1 resolved earlier in this request; failing that, the
    result of resolving it **once**, here. ``None`` — the public shell —
    when there is no session or the resolution fails for any reason at
    all.

  Notes
  -----
  Only the ``4xx`` family reaches this function: :func:`_error_page`'s
  ``public_shell`` flag short-circuits it for the ``500``, the ``503`` and
  the step-0 ``403``, which must never read a session.

  The read is why this function exists. A ``404`` on an unrouted path never
  ran step 1, so without it an authenticated user's ``404`` would render
  the *public* shell while their ``404`` on a foreign object rendered the
  authenticated one — two distinguishable bodies where one is required.
  Resolution is
  memoized on ``request.state`` by
  :func:`app.security.principal.resolve_session`, so this costs at most one
  bounded read per request and nothing at all when step 1 already ran.

  Every failure is swallowed into the public shell: an error page that
  raises while choosing its own shell would turn a ``404`` into a ``500``,
  and the most likely reason the read fails is the very outage the page is
  about to describe.
  """
  principal: Principal | None = getattr(request.state, "crm_principal", None)
  if principal is not None:
    return principal
  try:
    return await resolve_principal(request)
  # Any failure at all — no application context, no connection, a database
  # that has gone away mid-request — renders the public shell rather than
  # escalating the status the user asked about.
  except Exception:
    return None


async def _error_page(
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
    ``True`` forces ``principal=None``: the ``500``, the ``503``
    and the step-0 ``403`` render the public shell whatever the real
    session state is, because a session may not be readable after an
    unhandled exception and a page that tries to read one can fail a
    second time inside the error path. ``False`` — every other ``4xx`` —
    lets :func:`_principal_for_shell` resolve the session once.
  headers : dict[str, str] | None, optional
    Extra headers, such as ``Retry-After``.

  Returns
  -------
  Response
  """
  principal = None if public_shell else await _principal_for_shell(request)
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
  presented_cookie: bool = True,
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
    instead of nothing.
  retry_after : int | None, optional
    Whole seconds, rendered in the fragment and sent as ``Retry-After``.
  presented_cookie : bool, optional
    Whether this request carried a session cookie. It selects the
    ``401`` body only and is ignored on every other status; the default is
    ``True`` so the three other callers keep the two-sentence body. The
    cookie's *value* is never parsed — it is evidence that this client once
    had a session and nothing more.

  Returns
  -------
  Response
  """
  headers: dict[str, str] = {}
  if redirect is not None:
    headers["HX-Redirect"] = redirect
  if retry_after is not None:
    headers["Retry-After"] = str(retry_after)
  text = _REGION_TEXT.get(status, _REGION_TEXT[503])
  if status == 401 and not presented_cookie:
    text = _REGION_TEXT_401_COOKIELESS
  context = {
    "status": status,
    "text": text,
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


async def forbidden(request: Request, *, reason: str = "session") -> Response:
  """Render the ``403`` page.

  Parameters
  ----------
  request : Request
    The inbound request.
  reason : str, optional
    ``session`` (step 0, the default), ``role`` or ``forced_reset``.

  Returns
  -------
  Response
    ``reason="session"`` renders the public shell unconditionally, so the
    body cannot report whether the caller had a session.
  """
  if is_fragment(request) and reason == "forced_reset":
    return region_error(request, status=403, redirect=PASSWORD_URL)
  return await _error_page(
    request,
    status=403,
    template="errors/403.html",
    extra={"reason": reason, "correlation_id": current_correlation_id()},
    public_shell=reason == "session",
  )


async def unavailable(request: Request, *, context: str = "unavailable") -> Response:
  """Render the ``503`` page, always in the public shell.

  Parameters
  ----------
  request : Request
    The inbound request.
  context : str, optional
    ``unavailable`` (the database is down, or the deployment is not
    provisioned — one body for both, so an outsider cannot tell a fresh
    deployment from a broken one) or ``ambiguous_commit``.

  Returns
  -------
  Response
    Carries ``Retry-After``, because a ``503`` here is always a busy or
    not-yet-ready state rather than a permanent one.
  """
  if is_fragment(request):
    return region_error(request, status=503, retry_after=5)
  return await _error_page(
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


async def too_many_requests(request: Request, *, retry_after_s: int) -> Response:
  """Render the non-login ``429`` page.

  Parameters
  ----------
  request : Request
    The inbound request.
  retry_after_s : int
    Whole seconds until the window rolls; never a fixed long value, so the
    advertised recovery matches the real one.

  Returns
  -------
  Response
  """
  if is_fragment(request):
    return region_error(request, status=429, retry_after=retry_after_s)
  return await _error_page(
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


async def not_found(request: Request) -> Response:
  """Render the ``404`` page — identical for a missing and a foreign object."""
  return await _error_page(
    request,
    status=404,
    template="errors/404.html",
    extra={"back_url": DASHBOARD_URL, "correlation_id": current_correlation_id()},
    public_shell=False,
  )


async def bad_request(request: Request) -> Response:
  """Render the generic ``400`` page for a crafted request."""
  return await _error_page(
    request,
    status=400,
    template="errors/400.html",
    extra={"back_url": DASHBOARD_URL, "correlation_id": current_correlation_id()},
    public_shell=False,
  )


async def method_not_allowed(request: Request) -> Response:
  """Render the ``405`` page with the 400-family context."""
  return await _error_page(
    request,
    status=405,
    template="errors/405.html",
    extra={
      "status": 405,
      "title": _METHOD_NOT_ALLOWED_TITLE,
      "message": _METHOD_NOT_ALLOWED_MESSAGE,
      "correlation_id": current_correlation_id(),
    },
    public_shell=False,
  )


async def payload_too_large(request: Request) -> Response:
  """Render the ``413`` page for a body above the 64 KiB cap."""
  return await _error_page(
    request,
    status=413,
    template="errors/413.html",
    extra={"back_url": DASHBOARD_URL, "correlation_id": current_correlation_id()},
    public_shell=False,
  )


async def conflict(request: Request, *, context: str, extra: dict[str, Any]) -> Response:
  """Render ``errors/409.html`` in one of its four contexts.

  Parameters
  ----------
  request : Request
    The inbound request.
  context : str
    ``stale``, ``archived_parent``, ``duplicate`` or ``stage_terminal``.
    The context is the **only** thing that distinguishes the three (soon
    four) conflicts: a distinct status code would tell an attacker which
    condition held.
  extra : dict[str, Any]
    That context's own payload, and nothing beyond it.

  Returns
  -------
  Response
    Always a **full page** in the authenticated shell, never
    ``partials/region_error.html``. No mutation is ever issued by htmx, so
    no legitimate ``HX-Request`` can produce a 409; a crafted one gets the
    page, because the region partial's ``{status, text}`` shape has no 409
    text and would render the 503 line. This is the one deliberate
    narrowing of "every ``HX-Request`` response is a fragment".

  Notes
  -----
  ``_STATUS_PAGES`` is deliberately **not** extended with ``409``: the
  status carries a context payload only its own route holds, so no code
  path may raise a context-less ``HTTPException(409)``.
  """
  return await _error_page(
    request,
    status=409,
    template="errors/409.html",
    extra={"context": context, "correlation_id": current_correlation_id(), **extra},
    public_shell=False,
  )


async def internal_error(request: Request) -> Response:
  """Render the ``500`` page: public shell always, correlation id only."""
  return await _error_page(
    request,
    status=500,
    template="errors/500.html",
    extra={"correlation_id": current_correlation_id()},
    public_shell=True,
  )


def redirect(location: str, request: Request, *, headers: dict[str, str] | None = None) -> Response:
  """Return a ``303`` to ``location`` with the security headers already applied.

  Parameters
  ----------
  location : str
    A **relative** path, built by the caller from a route name and, where
    there is one, an allowlisted ``?notice=`` code. No free text ever travels in a URL.
  request : Request
    The inbound request, whose path selects the cache directives.
  headers : dict[str, str] | None, optional
    Extra headers, such as ``Clear-Site-Data``.

  Returns
  -------
  Response
    ``303 See Other`` — the Post/Redirect/Get of every mutation in this
    application.
  """
  response = RedirectResponse(location, status_code=303, headers=headers)
  return apply_security_headers(response, path=request.url.path)


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
    this application does not register — a status with no page is a bug
    here, not something to improvise a body for.
  """
  status = exc.status_code if isinstance(exc, HTTPException) else 500
  if status == 403:
    return await forbidden(request)
  if status == 429:
    return await too_many_requests(request, retry_after_s=5)
  if status == 503:
    return await unavailable(request)
  page = _STATUS_PAGES.get(status)
  if page is None:
    return await internal_error(request)
  response: Response = await page(request)
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
   , and the page carries the correlation id that joins the
    two.

  Returns
  -------
  Response
  """
  del exc
  return await internal_error(request)


async def step_zero_handler(request: Request, exc: Exception) -> Response:
  """Answer any step-0 refusal with the one shared ``403`` body."""
  del exc
  return await forbidden(request)


async def not_provisioned_handler(request: Request, exc: Exception) -> Response:
  """Answer an unprovisioned deployment with the ``503`` page."""
  del exc
  return await unavailable(request)


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
    A fragment request gets ``401`` plus ``HX-Redirect``; a
    private ``GET`` gets ``303`` to the login page, carrying a validated
    ``next``; an unsafe method gets the step-0 ``403``.

  Notes
  -----
  The ``?notice=session_ended`` suffix is gated on a **presented cookie**
  on *both* branches, not only on the ``303`` — a first-time visitor is
  never told a session ended, whichever shape they asked for. The cookie is
  evidence that this client once had a session and no more: its value is never parsed here, so a
  fabricated one only buys the sentence a genuine expiry would have
  earned.

  The same flag goes one step further: it also selects the fragment's
  **body**, so a cookieless htmx ``401`` reads *"Sign in to
  continue."* rather than announcing an ending that never happened. The
  header and the body now say the same thing.
  """
  del exc
  presented_cookie = bool(request.cookies.get(COOKIE_NAME))
  if is_fragment(request):
    login_target = f"{LOGIN_URL}?notice=session_ended" if presented_cookie else LOGIN_URL
    return region_error(
      request, status=401, redirect=login_target, presented_cookie=presented_cookie
    )
  if request.method not in SAFE_METHODS:
    return await forbidden(request)

  parameters: list[tuple[str, str]] = []
  target = request.url.path
  if is_safe_relative(target) and target != LOGIN_URL:
    parameters.append(("next", target))
  if presented_cookie:
    parameters.append(("notice", "session_ended"))
  location = f"{LOGIN_URL}?{urlencode(parameters)}" if parameters else LOGIN_URL
  return apply_security_headers(RedirectResponse(location, status_code=303), path=request.url.path)


async def forced_reset_handler(request: Request, exc: Exception) -> Response:
  """Answer step 2's failure: ``403``, or ``HX-Redirect`` to the password page."""
  del exc
  return await forbidden(request, reason="forced_reset")


async def role_required_handler(request: Request, exc: Exception) -> Response:
  """Answer step 3's failure with the role ``403``."""
  del exc
  return await forbidden(request, reason="role")


async def budget_handler(request: Request, exc: Exception) -> Response:
  """Answer a budget or throttle refusal with a sanitized ``429``."""
  retry_after = getattr(exc, "retry_after_s", 5)
  return await too_many_requests(request, retry_after_s=int(retry_after))


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
  return await too_many_requests(request, retry_after_s=1)


async def too_large_handler(request: Request, exc: Exception) -> Response:
  """Answer an over-cap body with the ``413`` page."""
  del exc
  return await payload_too_large(request)


async def contact_not_found_handler(request: Request, exc: Exception) -> Response:
  """Answer step 4's contact denial: one deny row, then the one ``404`` body.

  Parameters
  ----------
  request : Request
    The inbound request. Step 1 has already run on every route that can
    raise this, so the principal is memoized on ``request.state``.
  exc : Exception
    The :class:`app.security.failures.ContactNotFound` decision; carries
    the requested id **iff** it was canonical.

  Returns
  -------
  Response
    ``404`` with ``errors/404.html`` — identical for a foreign contact, a
    missing one and a non-canonical path segment, for the same principal
    modulo the correlation id.

  Notes
  -----
  This is the single emission point of the
  ``(contact, access_denied, denied)`` row, so six routes cannot
  write six different rows. The write is best-effort and in its own short
  transaction, opened only **after** the denying transaction unwound and
  released its connection; :func:`app.security.audit.record_denial`
  swallows its own failures, so a database hiccup can never turn a ``404``
  into a ``503``.

  A denial with no resolved principal writes nothing: pre-session denials
  reach the log stream only, so an anonymous flood cannot drive unbounded
  inserts.
  """
  object_id = getattr(exc, "object_id", None)
  principal: Principal | None = getattr(request.state, "crm_principal", None)
  context = getattr(request.app.state, "context", None)
  if principal is not None and context is not None:
    await record_denial(
      context.pool,
      actor_id=principal.id,
      object_type=OBJECT_CONTACT,
      object_id=object_id,
      action=ACTION_ACCESS_DENIED,
      correlation_id=current_correlation_id(),
      at=context.clock.now(),
    )
  return await not_found(request)


async def deal_not_found_handler(request: Request, exc: Exception) -> Response:
  """Answer step 4's deal denial: one deny row, then the one ``404`` body.

  Parameters
  ----------
  request : Request
    The inbound request. Step 1 has already run on every route that can
    raise this, so the principal is memoized on ``request.state``.
  exc : Exception
    The :class:`app.security.failures.DealNotFound` decision; carries the
    requested id **iff** it was canonical.

  Returns
  -------
  Response
    ``404`` with ``errors/404.html`` — the **same** body
    :func:`contact_not_found_handler` renders, from the same
    :func:`not_found`, so a foreign deal, a missing deal, a non-canonical
    deal id and a foreign *contact* are one answer for one principal
    modulo the correlation id.

  Notes
  -----
  The single emission point of the ``(deal, access_denied, denied)`` row,
  so five deal surfaces cannot write five different rows. It differs from
  the contact row in exactly one field —
  ``object_type`` — and that is the whole reason the two handlers exist
  separately rather than one guessing the surface.

  A **parent** miss never reaches here: ``POST /contacts/{id}/deals`` and
  ``GET /contacts/{id}/deals/new`` raise ``ContactNotFound`` instead, so
  the deny row names the contact the caller was actually refused. The
  write is best-effort, in its own short transaction opened after the
  denying one unwound, and a denial with no resolved principal
  writes nothing at all.
  """
  object_id = getattr(exc, "object_id", None)
  principal: Principal | None = getattr(request.state, "crm_principal", None)
  context = getattr(request.app.state, "context", None)
  if principal is not None and context is not None:
    await record_denial(
      context.pool,
      actor_id=principal.id,
      object_type=OBJECT_DEAL,
      object_id=object_id,
      action=ACTION_ACCESS_DENIED,
      correlation_id=current_correlation_id(),
      at=context.clock.now(),
    )
  return await not_found(request)


async def retry_exhausted_handler(request: Request, exc: Exception) -> Response:
  """Answer a spent retry budget with the ``unavailable`` ``503``.

  Parameters
  ----------
  request : Request
    The inbound request.
  exc : Exception
    The :class:`app.db.retry.RetryExhausted` signal. Its message names the
    operation and the attempt counts only — no SQL, no parameters, no
    record values — and is not rendered.

  Returns
  -------
  Response
    ``503`` with ``context="unavailable"`` and ``record_url=None``.

  Notes
  -----
  This is the **opposite** of :func:`ambiguous_commit_handler` and takes
  the other of ``errors/503.html``'s two frozen contexts on purpose. A
  serialization failure that spent its budget is a *confirmed* abort:
  every attempt rolled back, nothing was written, and the honest copy is
  the ``unavailable`` page's *"temporarily unavailable. Nothing you did
  caused this."* — the user may simply try again. *"Do not resubmit; open
  the record and check"* must stay reserved for the commit
  whose outcome is genuinely unknown, or the one sentence that matters
  there stops meaning anything.

  Registering it is what keeps an exhausted budget off the ``500`` page:
  a 500 reads as a defect in the application rather than as the momentary
  contention it is.
  """
  del exc
  return await unavailable(request)


async def ambiguous_commit_handler(request: Request, exc: Exception) -> Response:
  """Answer a commit whose outcome is unknown with the second ``503``.

  Parameters
  ----------
  request : Request
    The inbound request.
  exc : Exception
    The :class:`app.db.retry.AmbiguousCommit` signal. Its message names the
    operation and the attempt only — never SQL, parameters or values — and
    is not rendered.

  Returns
  -------
  Response
    ``503`` with ``context="ambiguous_commit"``, whose copy says *do not
    resubmit; open the record and check*. The true outcome is
    resolved by reading the receipt, which is the whole reason the receipt
    is written in the same transaction as the business row.

  Notes
  -----
  Registered so this never falls through to the ``500`` page: a 500 would
  invite exactly the resubmission that can turn one submission into two
  rows. ``record_url`` stays ``None`` here because this handler has no
  object id; giving it one is a per-route refinement, recorded as open.
  """
  del exc
  return await unavailable(request, context="ambiguous_commit")
