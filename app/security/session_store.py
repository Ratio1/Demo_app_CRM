"""The database-facing half of the session layer.

Split from :mod:`app.security.sessions` so that the parameters and the
primitives stay importable with no database in sight; everything here
reaches ``app.db.repositories.sessions`` through the short
``READ COMMITTED`` wrapper the contract assigns each function
(``slice-a.md`` §10(b)).

``app/routes/**`` may not import a repository (``ARC-008``), so this module
is how a route reads or creates a session row. The two *mutations* that
belong to a business transaction — promoting a pre-auth row at login and
revoking siblings at a password change — are not here: they run inside the
service's ``run_serializable`` block, where they belong.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.db.repositories.sessions import (
  create_preauth_session,
  delete_session,
  read_live_session,
  touch_session,
)
from app.db.retry import run_read_committed
from app.security.csrf import csrf_for_token
from app.security.sessions import (
  IDLE_TTL,
  PREAUTH_TTL,
  TOUCH_INTERVAL,
  mint_token,
  sha256_hex,
)

if TYPE_CHECKING:
  from datetime import datetime
  from uuid import UUID

  from app.db.pool import Pool, PoolConnection
  from app.db.repositories.sessions import SessionRow

__all__ = [
  "KIND_FULL",
  "KIND_PRE_AUTH",
  "PreauthSession",
  "end_session",
  "ensure_preauth",
  "read_live",
  "touch_if_stale",
]

KIND_PRE_AUTH = "pre_auth"
KIND_FULL = "full"


@dataclass(frozen=True, slots=True)
class PreauthSession:
  """The pre-auth row ``GET /login`` renders its form against.

  Attributes
  ----------
  session_id : UUID
    The row's id.
  csrf_token : str
    The token to render into the hidden field, derived from the session
    token (:mod:`app.security.csrf`).
  issued_token : str | None
    The raw token when a **new** row was created and the cookie must be
    set, ``None`` when a still-valid row was reused and the browser
    already holds its cookie (``ARC-017``(b) forbids a second INSERT).
  """

  session_id: UUID
  csrf_token: str
  issued_token: str | None


async def read_live(pool: Pool, *, token: str | None, now: datetime) -> SessionRow | None:
  """Read the live session row a cookie names, if any.

  Parameters
  ----------
  pool : Pool
    The process pool.
  token : str | None
    The raw cookie value, or ``None`` when no cookie was presented.
  now : datetime
    The instant expiry is judged against.

  Returns
  -------
  SessionRow | None
    ``None`` when there is no cookie, no row, or the row is expired,
    revoked or belongs to a disabled account. The repository filters all
    of that in SQL, so no caller can mistake a dead row for a live one.
  """
  if not token:
    return None

  digest = sha256_hex(token)

  async def _read(conn: PoolConnection) -> SessionRow | None:
    return await read_live_session(conn, token_sha256=digest, now=now)

  return await run_read_committed(pool, _read, op="read-live-session")


async def ensure_preauth(pool: Pool, *, token: str | None, now: datetime) -> PreauthSession:
  """Return the pre-auth session ``GET /login`` will render against.

  Parameters
  ----------
  pool : Pool
    The process pool.
  token : str | None
    The raw cookie value presented with the request, if any.
  now : datetime
    The instant the row is created or judged against.

  Returns
  -------
  PreauthSession
    Reusing a still-valid pre-auth row when the cookie presents one, and
    inserting exactly one row otherwise.

  Notes
  -----
  A **full** session that lands on ``GET /login`` is left completely
  alone: its row is not reused as a pre-auth row (the kinds are
  structurally different — ``ck_sessions_kind_user``) and it is not
  deleted either, because a ``GET`` must not end a session. A new pre-auth
  row is inserted and its cookie replaces the full session's cookie for
  this browser, which is the same thing that happens to a visitor who
  simply navigates to ``/login`` while signed in.

  This is ``DATA_CONTRACT.md`` §6.8 row 26 — the one write an anonymous
  ``GET`` can cause — and the caller has already charged the
  ``preauth_global`` budget before reaching it (``ARC-017``(c)).
  """
  existing = await read_live(pool, token=token, now=now)
  if existing is not None and existing.kind == KIND_PRE_AUTH and token is not None:
    csrf_token, _digest = csrf_for_token(token)
    return PreauthSession(session_id=existing.id, csrf_token=csrf_token, issued_token=None)

  new_token, token_digest = mint_token()
  csrf_token, csrf_digest = csrf_for_token(new_token)
  session_id = uuid.uuid4()
  expires_at = now + PREAUTH_TTL

  async def _create(conn: PoolConnection) -> None:
    await create_preauth_session(
      conn,
      session_id=session_id,
      token_sha256=token_digest,
      csrf_sha256=csrf_digest,
      now=now,
      expires_at=expires_at,
    )

  await run_read_committed(pool, _create, op="create-preauth-session")
  return PreauthSession(session_id=session_id, csrf_token=csrf_token, issued_token=new_token)


async def touch_if_stale(pool: Pool, row: SessionRow, *, now: datetime) -> None:
  """Extend a full session's idle window, at most once a minute.

  Parameters
  ----------
  pool : Pool
    The process pool.
  row : SessionRow
    The live row this request authenticated against.
  now : datetime
    The instant of the request.

  Notes
  -----
  ``DATA_CONTRACT.md`` §6.8 row 14, and the reason the rule is "only when
  the clock moved more than 60 s": without it every authenticated request
  would write a row, turning a read-mostly workload into a write-mostly
  one. The threshold is computed here and bound as ``stale_before``,
  because interval arithmetic in SQL is banned (§9.1).

  A pre-auth row is never touched: its ten minutes are absolute, so a
  login form left open cannot be kept alive by polling.
  """
  if row.kind != KIND_FULL:
    return

  stale_before = now - TOUCH_INTERVAL
  if row.last_seen_at >= stale_before:
    return

  async def _touch(conn: PoolConnection) -> bool:
    return await touch_session(
      conn,
      session_id=row.id,
      now=now,
      idle_expires_at=now + IDLE_TTL,
      stale_before=stale_before,
    )

  await run_read_committed(pool, _touch, op="touch-session")


async def end_session(pool: Pool, *, session_id: UUID) -> None:
  """Delete one session row (logout).

  Parameters
  ----------
  pool : Pool
    The process pool.
  session_id : UUID
    The row to remove.

  Notes
  -----
  Sessions are hard-deleted, never flagged (``DATA_CONTRACT.md`` §3.3), so
  "revoked" and "unknown token" are one code path and no dead token hash
  is left behind.
  """

  async def _delete(conn: PoolConnection) -> None:
    await delete_session(conn, session_id=session_id)

  await run_read_committed(pool, _delete, op="delete-session")
