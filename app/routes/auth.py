"""The Slice A route table: root, login, change password, logout.

Authority: ``slice-a.md`` §4 (the table itself — method, path, name, auth,
CSRF, template, context, success and error statuses), §2.4 (the ordered
stages of each mutation), §2.7 (the ``?notice=`` enum), ``R15`` (every
mutation is a plain form ``POST`` answered with ``303``), ``R28`` (no
``autofocus`` on a failed ``POST``).

Every handler follows the same shape, in the same order: resolve the
session, check CSRF on an unsafe method, charge the budget, apply the
forced-reset gate, then do the work. A refusal is **raised**, never
rendered here — :mod:`app.routes.errors` owns every status page, so two
routes cannot answer the same denial differently.

``ARC-003``: the three ``GET`` handlers call nothing from
``app.services``. The pre-auth row ``GET /login`` creates is a session-layer
write (``DATA_CONTRACT.md`` §6.8 row 26), reached through
:mod:`app.security.session_store` and admitted only after the
``preauth_global`` budget (``ARC-017``(c)).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from app.logging import current_correlation_id
from app.routes.errors import DASHBOARD_URL, LOGIN_URL, PASSWORD_URL, bad_request
from app.routes.rendering import base_context, csrf_token_for_request, notice_for, render
from app.security.authz import (
  charge_account_budget,
  form_content_type_ok,
  read_form,
  require_csrf,
  require_session,
)
from app.security.context import context_of
from app.security.failures import BudgetExceeded, ForcedResetRequired
from app.security.headers import apply_security_headers
from app.security.origin import is_safe_relative
from app.security.principal import resolve_session
from app.security.session_store import ensure_preauth
from app.security.sessions import COOKIE_NAME, expire_cookie, set_cookie
from app.security.throttle import (
  BUCKET_LOGIN_GLOBAL,
  BUCKET_PREAUTH_GLOBAL,
  GLOBAL_SUBJECT_KEY,
)
from app.services.auth import (
  OUTCOME_LOCKED,
  OUTCOME_OK,
  change_password,
  login,
  logout,
)

if TYPE_CHECKING:
  from starlette.datastructures import FormData

  from app.security.principal import Principal

__all__ = ["MAX_PASSWORD_LENGTH", "MIN_PASSWORD_LENGTH", "router"]

router = APIRouter()

#: ``UX_FLOWS.md`` §6.1 ``CP-01`` — one message for every login failure, so
#: nothing distinguishes a missing account from a wrong password or a
#: disabled one (``SEC-032``).
CP_01_LOGIN_FAILED: Final = (
  "We could not sign you in. Check the email address and password, then try again."
)

MIN_PASSWORD_LENGTH: Final = 15
MAX_PASSWORD_LENGTH: Final = 128

_PASSWORD_CHANGED_URL: Final = f"{DASHBOARD_URL}?notice=password_changed"
_SIGNED_OUT_URL: Final = f"{LOGIN_URL}?notice=signed_out"


def _validated_next(raw: str | None) -> str | None:
  """Return ``raw`` when it is a safe same-origin path, else ``None``.

  Parameters
  ----------
  raw : str | None
    A submitted ``next`` value, from the query string or the form.

  Returns
  -------
  str | None
    The path, or ``None`` — which the caller turns into the default
    destination rather than into an error, because a hostile ``next`` is
    not worth telling an attacker about (``SEC-042``).
  """
  if raw is None or not is_safe_relative(raw) or raw == LOGIN_URL:
    return None
  return raw


def _login_context(
  request: Request,
  *,
  csrf_token: str,
  email: str = "",
  errors: dict[str, list[str]] | None = None,
  next_path: str | None = None,
  retry_after_seconds: int | None = None,
) -> dict[str, Any]:
  """Build ``auth/login.html``'s full context (``slice-a.md`` §4).

  Parameters
  ----------
  request : Request
    The inbound request, for the ``?notice=`` booleans.
  csrf_token : str
    The pre-auth session's token.
  email : str, optional
    Echoed back so a mistyped password does not cost the address too.
  errors : dict[str, list[str]] | None, optional
    Non-empty renders the single ``CP-01`` message; the template never
    enumerates which field was wrong.
  next_path : str | None, optional
    An already-validated path.
  retry_after_seconds : int | None, optional
    Set only on a throttled attempt (``CP-02``).

  Returns
  -------
  dict[str, Any]
  """
  notice = notice_for(request)
  code = "" if notice is None else request.query_params.get("notice", "")
  context = base_context(page_title="Sign in", csrf_token=csrf_token, private=True)
  context.update(
    form={"email": email},
    errors=errors or {},
    next=next_path,
    signed_out=code == "signed_out",
    session_ended=code == "session_ended",
    retry_after_seconds=retry_after_seconds,
  )
  return context


def _password_context(
  request: Request,
  principal: Principal,
  *,
  csrf_token: str,
  errors: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
  """Build ``auth/change_password.html``'s full context.

  Parameters
  ----------
  request : Request
    The inbound request, for the ``?notice=`` banner.
  principal : Principal
    The signed-in user; ``must_change_password`` drives the forced banner
    and the reduced navigation.
  csrf_token : str
    The session's token.
  errors : dict[str, list[str]] | None, optional
    Field errors from the service.

  Returns
  -------
  dict[str, Any]
  """
  context = base_context(
    page_title="Change password",
    principal=principal,
    csrf_token=csrf_token,
    private=True,
    nav_active="account",
    notice=notice_for(request),
  )
  context.update(
    forced=principal.must_change_password,
    errors=errors or {},
    min_length=MIN_PASSWORD_LENGTH,
    max_length=MAX_PASSWORD_LENGTH,
  )
  return context


def _redirect(
  location: str, request: Request, *, headers: dict[str, str] | None = None
) -> Response:
  """Return a ``303`` to ``location`` with the security headers applied."""
  response = RedirectResponse(location, status_code=303, headers=headers)
  return apply_security_headers(response, path=request.url.path)


def _field(form: FormData, name: str) -> str | None:
  """Return one form field as text, or ``None`` when it is absent.

  Parameters
  ----------
  form : object
    The parsed ``FormData``.
  name : str
    The field name.

  Returns
  -------
  str | None
    The value; an uploaded file would arrive as something other than a
    string, and this application accepts no files, so anything non-textual
    reads as absent.
  """
  value = form.get(name)
  return value if isinstance(value, str) else None


@router.get("/", name="root")
async def root(request: Request) -> Response:
  """Send a signed-in user to the dashboard, and anyone else to the login page.

  Returns
  -------
  Response
    ``303 /dashboard``. Step 1 turns an absent session into ``303 /login``
    and step 2 turns a forced reset into ``403`` — both from
    :mod:`app.routes.errors`, so this handler states only the happy path.
  """
  principal = await require_session(request)
  await charge_account_budget(request, principal, safe=True)
  if principal.must_change_password:
    raise ForcedResetRequired
  return _redirect(DASHBOARD_URL, request)


@router.get("/login", name="login")
async def login_page(request: Request) -> Response:
  """Render the sign-in form against a pre-auth session.

  Returns
  -------
  Response
    ``200`` with ``auth/login.html``. The ``preauth_global`` budget is
    charged **before** the pre-auth row is created, so an over-budget
    request inserts nothing (``ARC-017``(c), ``SEC-031``(e)).
  """
  context = context_of(request)
  now = context.clock.now()
  decision = await context.budget.charge(BUCKET_PREAUTH_GLOBAL, GLOBAL_SUBJECT_KEY, now=now)
  if not decision.allowed:
    raise BudgetExceeded(decision.retry_after_s)

  preauth = await ensure_preauth(context.pool, token=request.cookies.get(COOKIE_NAME), now=now)
  page = _login_context(
    request,
    csrf_token=preauth.csrf_token,
    next_path=_validated_next(request.query_params.get("next")),
  )
  response = render(request, "auth/login.html", page)
  if preauth.issued_token is not None:
    set_cookie(response, preauth.issued_token)
  return response


@router.post("/login", name="login_submit")
async def login_submit(request: Request) -> Response:
  """Authenticate a submission and rotate the session on success.

  Returns
  -------
  Response
    ``303`` to the validated ``next``, to ``/account/password`` when the
    account must change its password, or to ``/dashboard``. ``401`` with
    ``CP-01`` on any authentication failure, ``429`` with ``CP-02`` when
    the account is throttled.

  Notes
  -----
  The ``401`` carries **no** ``WWW-Authenticate``: the only scheme a
  browser would act on is ``Basic``, whose credential dialog would break
  this form flow. A deliberate deviation from RFC 9110 §15.5.2, recorded
  in ``slice-a.md`` §2.4 for the review council.
  """
  context = context_of(request)
  form = await read_form(request)
  await require_csrf(request, _field(form, "csrf_token"))
  if not form_content_type_ok(request):
    return bad_request(request)
  row = await resolve_session(request)

  now = context.clock.now()
  decision = await context.budget.charge(BUCKET_LOGIN_GLOBAL, GLOBAL_SUBJECT_KEY, now=now)
  if not decision.allowed:
    raise BudgetExceeded(decision.retry_after_s)

  email = _field(form, "email") or ""
  password = _field(form, "password") or ""
  next_path = _validated_next(_field(form, "next"))
  csrf_token = csrf_token_for_request(request)

  result = await login(
    pool=context.pool,
    clock=context.clock,
    passwords=context.passwords,
    throttle=context.throttle,
    email=email,
    password=password,
    preauth_id=row.id if row is not None else None,
    correlation_id=current_correlation_id(),
  )

  if result.outcome == OUTCOME_LOCKED:
    retry_after = result.retry_after_s or 1
    page = _login_context(
      request,
      csrf_token=csrf_token,
      email=email,
      next_path=next_path,
      retry_after_seconds=retry_after,
    )
    return render(
      request,
      "auth/login.html",
      page,
      status_code=429,
      headers={"Retry-After": str(retry_after)},
    )

  if result.outcome != OUTCOME_OK or result.token is None:
    page = _login_context(
      request,
      csrf_token=csrf_token,
      email=email,
      errors={"credentials": [CP_01_LOGIN_FAILED]},
      next_path=next_path,
    )
    return render(request, "auth/login.html", page, status_code=401)

  destination = next_path or (PASSWORD_URL if result.must_change_password else DASHBOARD_URL)
  response = _redirect(destination, request)
  set_cookie(response, result.token)
  return response


@router.get("/account/password", name="password")
async def password_page(request: Request) -> Response:
  """Render the change-password form; reachable on the forced path too.

  Returns
  -------
  Response
    ``200`` with ``auth/change_password.html``.
  """
  principal = await require_session(request)
  await charge_account_budget(request, principal, safe=True)
  page = _password_context(request, principal, csrf_token=csrf_token_for_request(request))
  return render(request, "auth/change_password.html", page)


@router.post("/account/password", name="password_submit")
async def password_submit(request: Request) -> Response:
  """Change the password, revoke every sibling session and rotate this one.

  Returns
  -------
  Response
    ``303 /dashboard?notice=password_changed`` on success, with the new
    cookie already set; ``400`` re-rendering the form with field errors
    otherwise.
  """
  context = context_of(request)
  principal = await require_session(request)
  form = await read_form(request)
  await require_csrf(request, _field(form, "csrf_token"))
  if not form_content_type_ok(request):
    return bad_request(request)
  await charge_account_budget(request, principal, safe=False)

  result = await change_password(
    pool=context.pool,
    clock=context.clock,
    passwords=context.passwords,
    principal=principal,
    current_password=_field(form, "current_password") or "",
    new_password=_field(form, "new_password") or "",
    confirm_password=_field(form, "confirm_password") or "",
    correlation_id=current_correlation_id(),
  )

  if result.errors or result.token is None:
    page = _password_context(
      request, principal, csrf_token=csrf_token_for_request(request), errors=result.errors
    )
    return render(request, "auth/change_password.html", page, status_code=400)

  response = _redirect(_PASSWORD_CHANGED_URL, request)
  set_cookie(response, result.token)
  return response


@router.post("/logout", name="logout")
async def logout_submit(request: Request) -> Response:
  """End the session, clear the browser's copy of it and go to the login page.

  Returns
  -------
  Response
    ``303 /login?notice=signed_out`` carrying ``Clear-Site-Data`` and the
    expired cookie (``SEC-029``). Allowed on the forced-reset path: a user
    who cannot use the application must still be able to leave it.

  Notes
  -----
  This is the one mutation that does **not** charge the
  ``account_mutation`` budget, and the deviation from ``slice-a.md`` §2.1
  is deliberate rather than an omission. Logout is self-limiting: the
  session row is gone once it succeeds, so a repeat is refused at step 1
  before it reaches any write. Charging it would buy no bound and would
  create a real failure mode — a user whose budget is exhausted being
  unable to sign out, which is precisely when they most want to. Recorded
  for the review council.
  """
  context = context_of(request)
  principal = await require_session(request)
  form = await read_form(request)
  await require_csrf(request, _field(form, "csrf_token"))
  if not form_content_type_ok(request):
    return bad_request(request)

  await logout(
    pool=context.pool,
    clock=context.clock,
    principal=principal,
    correlation_id=current_correlation_id(),
  )
  response = _redirect(_SIGNED_OUT_URL, request, headers={"Clear-Site-Data": '"cache", "storage"'})
  expire_cookie(response)
  return response
