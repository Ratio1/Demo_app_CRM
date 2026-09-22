"""Step 1 of the pipeline: cookie to principal, or to nothing.

Authority: ``slice-a.md`` §2.1 step 1 — "session cookie → ``sha256`` →
``sessions`` row joined to ``users``; live, within idle 30 min and absolute
8 h, ``users.is_active = TRUE``, **role re-read now**".

The last clause is the one that matters most: the role, the active flag and
the forced-reset flag are read from ``users`` on **every** request through
the join, never carried in the cookie and never cached in the process. A
disabled account therefore stops working on its next request rather than
when its session happens to expire, and nothing a client holds can claim a
role.

Resolution happens at most once per request: the row and the principal are
memoized on ``request.state`` so the pipeline's later steps, the template
context and the audit row all read one consistent answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.security.context import context_of
from app.security.session_store import KIND_FULL, read_live, touch_if_stale
from app.security.sessions import COOKIE_NAME

if TYPE_CHECKING:
  from uuid import UUID

  from starlette.requests import Request

  from app.db.repositories.sessions import SessionRow

__all__ = [
  "Principal",
  "Scope",
  "principal_of",
  "resolve_principal",
  "resolve_session",
  "scope_of",
]

_STATE_ROW = "crm_session_row"
_STATE_PRINCIPAL = "crm_principal"
_STATE_RESOLVED = "crm_session_resolved"


@dataclass(frozen=True, slots=True)
class Principal:
  """The authenticated identity of one request.

  Attributes
  ----------
  id : UUID
    ``users.id``.
  display_name : str
    For the navigation's identity line; never used in a decision.
  role : str
    ``admin`` or ``agent``, re-read from ``users`` on this request.
  is_admin : bool
    ``role == "admin"``, computed once so no template re-derives it.
  must_change_password : bool
    Whether step 2 bars everything but the two forced-path routes.
  session_id : UUID
    The row this request authenticated against.
  """

  id: UUID
  display_name: str
  role: str
  is_admin: bool
  must_change_password: bool
  session_id: UUID


@dataclass(frozen=True, slots=True)
class Scope:
  """The authorization scope a business query is filtered by.

  Attributes
  ----------
  actor_id : UUID
    Whose records the predicate admits.
  is_admin : bool
    Whether the predicate widens to every record.

  Notes
  -----
  Defined here because the identity that produces it is defined here.
  Slice B's business repositories take it as a mandatory argument — the
  first *business* one, after the connection (``ARC-001``,
  ``contracts/slice-b.md`` §1(b) B1).
  """

  actor_id: UUID
  is_admin: bool


def scope_of(principal: Principal) -> Scope:
  """Return the authorization scope this principal's reads and writes carry.

  Parameters
  ----------
  principal : Principal
    The resolved identity of the request, whose role was re-read from
    ``users`` on this request by :func:`resolve_session`.

  Returns
  -------
  Scope
    ``actor_id`` is the session's user id — never a submitted value — and
    ``is_admin`` is the re-read role. Building the scope here, from the
    principal alone, is what makes it impossible for a route to widen its
    own authorization: there is no parameter through which a request could
    reach either field.
  """
  return Scope(actor_id=principal.id, is_admin=principal.is_admin)


def principal_of(row: SessionRow | None) -> Principal | None:
  """Build a :class:`Principal` from a live session row.

  Parameters
  ----------
  row : SessionRow | None
    A row from ``read_live_session``, or ``None``.

  Returns
  -------
  Principal | None
    ``None`` for no row and for a pre-auth row: a pre-auth session carries
    no identity at all, which ``ck_sessions_kind_user`` enforces
    structurally (``user_id IS NULL``).
  """
  if row is None or row.kind != KIND_FULL or row.user_id is None:
    return None
  role = row.role or "agent"
  return Principal(
    id=row.user_id,
    display_name=row.display_name or "",
    role=role,
    is_admin=role == "admin",
    must_change_password=bool(row.must_change_password),
    session_id=row.id,
  )


async def resolve_session(request: Request) -> SessionRow | None:
  """Return the live session row for this request, resolving it once.

  Parameters
  ----------
  request : Request
    The inbound request. Its cookie is the only input; no header is
    consulted.

  Returns
  -------
  SessionRow | None
    The live row — pre-auth or full — or ``None``.

  Notes
  -----
  A full session is touched here, at most once a minute
  (``DATA_CONTRACT.md`` §6.8 row 14). The touch is the only write this
  step performs and it happens before the handler runs, so a handler that
  fails still leaves the idle window extended — which is correct: the user
  *was* active.
  """
  if getattr(request.state, _STATE_RESOLVED, False):
    row: SessionRow | None = getattr(request.state, _STATE_ROW, None)
    return row

  context = context_of(request)
  now = context.clock.now()
  token = request.cookies.get(COOKIE_NAME)
  resolved = await read_live(context.pool, token=token, now=now)
  if resolved is not None:
    await touch_if_stale(context.pool, resolved, now=now)

  setattr(request.state, _STATE_ROW, resolved)
  setattr(request.state, _STATE_PRINCIPAL, principal_of(resolved))
  setattr(request.state, _STATE_RESOLVED, True)
  return resolved


async def resolve_principal(request: Request) -> Principal | None:
  """Return the authenticated principal, or ``None``.

  Parameters
  ----------
  request : Request
    The inbound request.

  Returns
  -------
  Principal | None
    ``None`` when the cookie is absent, the row is dead or revoked, the
    account is disabled, or the row is a pre-auth one.
  """
  await resolve_session(request)
  principal: Principal | None = getattr(request.state, _STATE_PRINCIPAL, None)
  return principal
