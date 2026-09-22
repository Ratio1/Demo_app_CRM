"""The ordered request pipeline every business route runs, in one place.

Authority: ``ACCESS_MATRIX.md`` §1.1 (the check order), §1.2 (the status
policy and the H-08 unknown-parameter rule), §4.5 rows 4, 6 and 7 (the
deny-audit triples these helpers write), §5.1 (the writable-field
allowlists a body is read against), ``contracts/slice-b.md`` §2(c)/§2(f)
and ``contracts/slice-c.md`` §2(c) (the handler order, restated unchanged
for the deal routes), **R69** (the zero-difference 409-stale body).

Everything here shipped inside ``app/routes/contacts.py`` in Slice B and is
**unchanged in behaviour**; Slice C moves it because the deal routes must
run the *same* order rather than a copy of it (§2(c): *"the handler order
is the shipped ``_start_mutation`` / ``_start_read`` order, unchanged"*),
and because two copies of an authorization order are two orders.

The order is fixed and shared so eighteen routes cannot drift: session,
body, CSRF, content type, budget, forced-reset gate, role, body allowlist.
CSRF is checked **before** the content type, so a cross-site post carrying
no token at all meets the same ``403`` as one carrying a stale token; the
budget is charged **after** CSRF, so an unauthenticated cross-site request
cannot burn an authenticated user's budget.

The one thing that varies between the contact surfaces and the deal
surfaces is the **object type** of the deny row an allowlist rejection
writes — §4.5 row 6 for a contact surface, row 7 for a deal one — so it is
a parameter, and the default is the contact surface the Slice B routes
already pass by omission.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Final

from app.logging import current_correlation_id
from app.routes.errors import bad_request
from app.security.audit import (
  ACTION_INPUT_REJECTED,
  ACTION_ROLE_DENIED,
  OBJECT_CONTACT,
  record_denial,
)
from app.security.authz import (
  charge_account_budget,
  deny_forced_reset,
  form_content_type_ok,
  read_form,
  require_admin,
  require_csrf,
  require_session,
)
from app.security.context import context_of
from app.security.failures import RoleRequired
from app.security.idempotency import parse_canonical

if TYPE_CHECKING:
  from collections.abc import Mapping, Sequence

  from starlette.datastructures import FormData
  from starlette.requests import Request
  from starlette.responses import Response

  from app.security.principal import Principal

__all__ = [
  "CP_OWED_ZERO_FIELD_STALE",
  "field",
  "is_fragment_request",
  "positive_int",
  "query_value",
  "read_body",
  "reject_input",
  "require_admin_audited",
  "stale_body",
  "start_mutation",
  "start_read",
]

_DIGITS: Final = re.compile(r"\A[0-9]+\Z")

#: **R63**/**R69** — the body of a 409-stale panel in which **no rendered
#: field differs**. ``UX_FLOWS.md`` §3.9's own orientation sentence promises
#: two panels ("Your version is on the left, the saved version on the
#: right"), which an archive or a restore cannot fill: their form carries a
#: version and nothing else (``ACCESS_MATRIX.md`` §5.1). That screen keeps
#: the ``CP-85`` heading — the heading of the screen ``CP-12`` sits on,
#: which is how R63's *"CP-12's heading"* reads, ``CP-12`` itself being
#: 409-stale **secondary** copy rather than a heading — and carries this
#: sentence as its body instead. The ruling supplies the text verbatim and
#: records the **CP id as owed** to the copy authority; this constant is its
#: only spelling in the code, so the id lands in one place when it is
#: issued.
CP_OWED_ZERO_FIELD_STALE: Final = (
  "This record changed since you opened it. Review it and try again."
)


def stale_body(fields: Sequence[Mapping[str, Any]]) -> str | None:
  """Return the 409-stale panel's body for this comparison (**R69**).

  Parameters
  ----------
  fields : Sequence[Mapping[str, Any]]
    The rendered comparison rows, each carrying ``differs``.

  Returns
  -------
  str | None
    ``None`` when at least one field differs — the screen then keeps
    ``UX_FLOWS.md`` §3.9's own orientation sentence — and
    :data:`CP_OWED_ZERO_FIELD_STALE` when **none** does.

  Notes
  -----
  **R69** fixes the predicate as *"no rendered field differs"* rather than
  *"there are no fields"*: it covers an archive or a restore, whose form
  has no data field at all, **and** a reassign to the current owner or a
  stage move someone else already made — one row, rendered, identical on
  both sides. Promising two panels and then showing two identical ones
  explains nothing, which is the defect the ruling closes.
  """
  if any(field_row["differs"] for field_row in fields):
    return None
  return CP_OWED_ZERO_FIELD_STALE


def field(form: FormData, name: str) -> str | None:
  """Return one form field as text, or ``None`` when it is absent."""
  value = form.get(name)
  return value if isinstance(value, str) else None


def is_fragment_request(request: Request) -> bool:
  """Return whether this ``GET`` must answer with the partial (**PIN 5**).

  Parameters
  ----------
  request : Request
    The inbound request.

  Returns
  -------
  bool
    ``True`` only for a genuine htmx fragment request. A Back-button
    history restore carries ``HX-Request: true`` **and**
    ``HX-History-Restore-Request: true`` — htmx 2.0.10 defaults
    ``historyRestoreAsHxRequest`` to ``true``, and with the pinned
    ``historyCacheSize: 0`` every restore is a cache miss, so this is the
    normal path rather than an edge case. htmx swaps that response into
    the history element with ``innerHTML``, so answering it with a
    fragment would put a fragment on screen as the whole document.
  """
  if request.headers.get("hx-request", "").casefold() != "true":
    return False
  return request.headers.get("hx-history-restore-request", "").casefold() != "true"


def query_value(request: Request, key: str) -> tuple[bool, str | None]:
  """Return ``(ok, value)`` for one allowlisted query key.

  Parameters
  ----------
  request : Request
    The inbound request.
  key : str
    An allowlisted key.

  Returns
  -------
  tuple[bool, str | None]
    ``ok`` is ``False`` when the key was supplied more than once
    (``SEC-076``), which is a ``400``; the rule applies to allowlisted keys
    only, because an unknown key is already gone by the time duplicates are
    counted (H-08). ``value`` is ``None`` when the key was absent **or
    empty**: a ``<select>`` always submits something, so an empty value is
    the absence of a choice.
  """
  values = request.query_params.getlist(key)
  if len(values) > 1:
    return False, None
  if not values or not values[0]:
    return True, None
  return True, values[0]


def positive_int(value: str | None, *, default: int) -> int | None:
  """Return ``value`` as a positive integer, ``default`` when absent, else ``None``.

  Notes
  -----
  Matched against ``[0-9]+`` rather than parsed with :meth:`str.isdigit`,
  which is ``True`` for non-ASCII digits :func:`int` also accepts — one
  more spelling of the same number is one more thing a test cannot
  enumerate.
  """
  if value is None:
    return default
  if _DIGITS.match(value) is None:
    return None
  parsed = int(value)
  return parsed if parsed >= 1 else None


def read_body(form: FormData, allowed: frozenset[str]) -> dict[str, str] | None:
  """Return the submitted body when it is exactly within ``allowed``.

  Parameters
  ----------
  form : FormData
    The parsed body.
  allowed : frozenset[str]
    That form's exact accepted set.

  Returns
  -------
  dict[str, str] | None
    Every allowed name, with ``""`` for one the body omitted — which is
    how an unselected radio group reaches ``CP-66`` rather than a crafted
    400. ``None`` means the body carried a name outside the set, a
    **repeated** name, or a non-textual part: all three are crafted
    requests, rejected and never ignored, because silence makes mass
    assignment untestable (``ACCESS_MATRIX.md`` §5.1).
  """
  counts: dict[str, int] = {}
  for key, value in form.multi_items():
    if key not in allowed or not isinstance(value, str):
      return None
    counts[key] = counts.get(key, 0) + 1
  if any(count != 1 for count in counts.values()):
    return None
  body: dict[str, str] = {}
  for key in allowed:
    submitted = form.get(key)
    body[key] = submitted if isinstance(submitted, str) else ""
  return body


async def reject_input(
  request: Request, principal: Principal, *, object_type: str = OBJECT_CONTACT
) -> Response:
  """Answer a crafted query or body with ``400`` and §4.5 row 6 or row 7.

  Parameters
  ----------
  request : Request
    The inbound request.
  principal : Principal
    The resolved actor the row names.
  object_type : str, optional
    The surface the request targeted: ``contact`` (row 6, the default and
    what every Slice B route passes by omission) or ``deal`` (row 7). The
    two rows differ in this field alone, which is why it is a parameter
    and not a second function.

  Notes
  -----
  ``object_id`` is ``NULL``: the row records *that* an allowlist refused
  this actor's request, never which value it refused, so no submitted free
  text reaches a 90-day table the runtime role can read (§4.5 rule 1).
  The generic ``errors/400.html`` names no field and echoes no value
  (``CP-80``/``CP-15``), which is what keeps it a different screen from the
  inline field errors of ``UX_FLOWS.md`` §3.13.
  """
  context = context_of(request)
  await record_denial(
    context.pool,
    actor_id=principal.id,
    object_type=object_type,
    object_id=None,
    action=ACTION_INPUT_REJECTED,
    correlation_id=current_correlation_id(),
    at=context.clock.now(),
  )
  return await bad_request(request)


async def require_admin_audited(
  request: Request, principal: Principal, raw_id: str, *, object_type: str = OBJECT_CONTACT
) -> None:
  """Step 3: the role check, with §4.5 **row 4** written on refusal.

  Notes
  -----
  Runs **before** the path id is parsed, so an agent posting to
  ``/contacts/<garbage>/reassign`` meets ``403`` and not ``404``: the role
  check is constant over objects and leaks nothing about the target
  (``ACC-033``). ``object_id`` is the path id **iff** it is canonical,
  ``NULL`` otherwise.
  """
  try:
    require_admin(principal)
  except RoleRequired:
    context = context_of(request)
    await record_denial(
      context.pool,
      actor_id=principal.id,
      object_type=object_type,
      object_id=parse_canonical(raw_id),
      action=ACTION_ROLE_DENIED,
      correlation_id=current_correlation_id(),
      at=context.clock.now(),
    )
    raise


async def start_mutation(
  request: Request,
  form_fields: frozenset[str],
  *,
  admin_for: str | None = None,
  object_type: str = OBJECT_CONTACT,
) -> tuple[Principal, dict[str, str]] | Response:
  """Run the unsafe-method pipeline up to the body allowlist.

  Parameters
  ----------
  request : Request
    The inbound request.
  form_fields : frozenset[str]
    That form's exact accepted set.
  admin_for : str | None, optional
    The raw path id, on an admin-only route. Passing it runs step 3
    **before** the body allowlist, which is the contracted order: the role
    check is constant over objects, so it must not sit behind a check that
    a crafted body could answer first.
  object_type : str, optional
    Which §4.5 row an allowlist rejection writes; see :func:`reject_input`.

  Returns
  -------
  tuple[Principal, dict[str, str]] | Response
    The principal and the validated body, or the response that refuses the
    request.
  """
  principal = await require_session(request)
  form = await read_form(request)
  await require_csrf(request, field(form, "csrf_token"))
  if not form_content_type_ok(request):
    return await bad_request(request)
  await charge_account_budget(request, principal, safe=False)
  if principal.must_change_password:
    await deny_forced_reset(request, principal)
  if admin_for is not None:
    await require_admin_audited(request, principal, admin_for, object_type=object_type)
  body = read_body(form, form_fields)
  if body is None:
    return await reject_input(request, principal, object_type=object_type)
  return principal, body


async def start_read(request: Request) -> Principal:
  """Run the safe-method pipeline: session, budget, forced-reset gate.

  Notes
  -----
  The gate refuses through :func:`~app.security.authz.deny_forced_reset`,
  so the block writes ``ACCESS_MATRIX.md`` §4.5 row 5 (**R67**) — and it
  does so for every route that starts here, contacts and deals alike,
  rather than at four sites that could drift apart.
  """
  principal = await require_session(request)
  await charge_account_budget(request, principal, safe=True)
  if principal.must_change_password:
    await deny_forced_reset(request, principal)
  return principal
