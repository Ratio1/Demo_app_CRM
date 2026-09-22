"""Steps 0b, 2 and 3 of the pipeline, as awaited guards.

Authority: ``slice-a.md`` §2.1 (the ordered steps and their exact
statuses), §2.3 (content type and the body's shape), ``ACCESS_MATRIX.md``
§1.1.

Each guard raises one of :mod:`app.security.failures`' decisions and
renders nothing: the mapping from a decision to a page, a status and a
shell lives in :mod:`app.routes.errors`, in one place, so two routes cannot
answer the same denial differently.

The order is fixed and every route follows it: **CSRF before the budget,
the budget before the work, the forced-reset gate before the role, the role
before anything is read**. Charging a budget before validating CSRF would
let an unauthenticated cross-site request burn an authenticated user's
budget; checking a role before the forced-reset gate would leak that the
route exists to an account that may not use it at all.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from app.logging import current_correlation_id
from app.security.audit import ACTION_BUDGET_DENIED, OBJECT_USER, record_denial
from app.security.context import context_of
from app.security.csrf import verify_csrf
from app.security.failures import (
  BudgetExceeded,
  ForcedResetRequired,
  NoSession,
  RoleRequired,
  StepZeroDenied,
)
from app.security.principal import resolve_principal, resolve_session
from app.security.throttle import (
  BUCKET_ACCOUNT_MUTATION,
  BUCKET_ACCOUNT_QUERY,
)

if TYPE_CHECKING:
  from starlette.datastructures import FormData
  from starlette.requests import Request

  from app.security.principal import Principal

__all__ = [
  "FORM_CONTENT_TYPE",
  "MAX_FORM_FIELDS",
  "MAX_FORM_PART_BYTES",
  "charge_account_budget",
  "form_content_type_ok",
  "read_form",
  "require_active_session",
  "require_admin",
  "require_csrf",
  "require_session",
]

FORM_CONTENT_TYPE: Final = "application/x-www-form-urlencoded"

#: Passed explicitly to ``Request.form``: Starlette's defaults are 1000
#: fields and a 1 MiB part, both far above anything this application's
#: forms need, and a bound that is never reached is not a bound.
MAX_FORM_FIELDS: Final = 64
MAX_FORM_PART_BYTES: Final = 65_536


async def require_session(request: Request) -> Principal:
  """Step 1: demand a live full session.

  Parameters
  ----------
  request : Request
    The inbound request.

  Returns
  -------
  Principal

  Raises
  ------
  NoSession
    When there is no live full session. The caller decides the shape of
    the answer — ``303`` for a private ``GET``, ``403`` for an unsafe
    method, ``401`` + ``HX-Redirect`` for a fragment (**R26**) — because
    only the caller knows which it is.
  """
  principal = await resolve_principal(request)
  if principal is None:
    raise NoSession
  return principal


async def require_active_session(request: Request) -> Principal:
  """Demand a live session that is not barred by a forced reset (steps 1, 2).

  Parameters
  ----------
  request : Request
    The inbound request.

  Returns
  -------
  Principal

  Raises
  ------
  NoSession
    As :func:`require_session`.
  ForcedResetRequired
    When the account must change its password. Only ``GET``/``POST
    /account/password`` and ``POST /logout`` proceed; every other route is
    refused, so a forced account can neither read nor write anything else.
  """
  principal = await require_session(request)
  if principal.must_change_password:
    raise ForcedResetRequired
  return principal


def require_admin(principal: Principal) -> None:
  """Step 3: demand the ``admin`` role.

  Parameters
  ----------
  principal : Principal
    The already-resolved principal, whose role was re-read from ``users``
    on this request.

  Raises
  ------
  RoleRequired
    When the principal is not an administrator.

  Notes
  -----
  Slice A registers no admin-only route; the guard exists so that Slice B's
  first one cannot be written without it. Hiding a control in the UI is
  never a substitute for this check.
  """
  if not principal.is_admin:
    raise RoleRequired


def form_content_type_ok(request: Request) -> bool:
  """Return whether an unsafe request declared the one accepted content type.

  Parameters
  ----------
  request : Request
    A request whose method is unsafe.

  Returns
  -------
  bool
    ``True`` for ``application/x-www-form-urlencoded``, with or without an
    explicit ``charset`` parameter.

  Notes
  -----
  Checked **after** CSRF, never before: a cross-site post that carries no
  token at all must meet the same ``403`` as one carrying a stale token,
  and answering ``400`` first would both leak that ordering and let a
  cross-site request skip the CSRF check by sending the wrong type.

  There is **no multipart path in this application**, so
  ``python-multipart``'s own limits never govern anything; refusing every
  other type is what keeps it that way.
  """
  media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
  return media_type == FORM_CONTENT_TYPE


async def read_form(request: Request) -> FormData:
  """Parse an unsafe request's body under explicit bounds.

  Parameters
  ----------
  request : Request
    A request whose method is unsafe.

  Returns
  -------
  FormData
    The parsed body, or an **empty** form when the content type is not one
    Starlette parses. Empty rather than an exception, so the CSRF check
    runs first and answers ``403`` (see :func:`form_content_type_ok`).

  Notes
  -----
  ``max_fields`` and ``max_part_size`` are passed explicitly
  (``slice-a.md`` §2.3): Starlette's defaults are 1000 fields and a 1 MiB
  part, and a bound that is never reached is not a bound.
  """
  return await request.form(max_fields=MAX_FORM_FIELDS, max_part_size=MAX_FORM_PART_BYTES)


async def require_csrf(request: Request, submitted: str | None) -> None:
  """Step 0b: compare the submitted token with the session row's digest.

  Parameters
  ----------
  request : Request
    The inbound request; its session row has already been resolved by an
    earlier step and is reused rather than re-read.
  submitted : str | None
    The ``csrf_token`` form field, or ``None`` when it was absent.

  Raises
  ------
  StepZeroDenied
    When there is no session row at all, when the field is missing, or
    when the token does not match. One outcome, one body: a mutation
    carrying no session and a mutation carrying a stale token are
    indistinguishable in the response (``R27``).

  Notes
  -----
  The digest compared against belongs to the row **this request
  authenticated with** — the pre-auth row for ``POST /login``, the full
  row otherwise — which is what makes this a synchronizer token rather
  than a bare double-submit cookie.
  """
  row = await resolve_session(request)
  stored = row.csrf_sha256 if row is not None else None
  if not verify_csrf(submitted, stored):
    raise StepZeroDenied


async def charge_account_budget(request: Request, principal: Principal, *, safe: bool) -> None:
  """Charge this request against the actor's per-account budget.

  Parameters
  ----------
  request : Request
    The inbound request, for the application context.
  principal : Principal
    The resolved actor; the budget is keyed on their user id, never on an
    address or a header (``ARC-016``).
  safe : bool
    ``True`` for ``GET``/``HEAD`` (the ``account_query`` bucket), ``False``
    for a mutation (``account_mutation``).

  Raises
  ------
  BudgetExceeded
    When the bucket is over its limit for this minute. The refusal is a
    sanitized ``429`` with a ``Retry-After`` no longer than the remaining
    window.

  Notes
  -----
  The request that *crosses* the limit also writes one ``budget_denied``
  audit row, inside the counter's own transaction, and no later refusal in
  the same window writes another — which is what keeps the deny trail
  bounded by the very budget it records (``DATA_CONTRACT.md`` §3.6).
  """
  context = context_of(request)
  now = context.clock.now()
  bucket = BUCKET_ACCOUNT_QUERY if safe else BUCKET_ACCOUNT_MUTATION
  decision = await context.budget.charge(bucket, str(principal.id), now=now)
  if decision.allowed:
    return
  if decision.transitioned:
    await record_denial(
      context.pool,
      actor_id=principal.id,
      object_type=OBJECT_USER,
      object_id=principal.id,
      action=ACTION_BUDGET_DENIED,
      correlation_id=current_correlation_id(),
      at=now,
    )
  raise BudgetExceeded(decision.retry_after_s)
