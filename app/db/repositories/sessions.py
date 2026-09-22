"""``sessions`` — pre-auth and full rows, read and written by hash alone.

The raw cookie value never reaches this module: the caller hashes it and
binds the digest. Nothing here mints a token, sets a cookie or decides
whether a principal may proceed — those belong to ``app/security/**``.

The one design decision worth restating is :func:`read_live_session`'s
**LEFT JOIN** (amendment **A4**). An INNER JOIN cannot see a pre-auth row,
whose ``user_id`` is ``NULL`` by construction, and ``POST /login`` has to
read exactly that row for its CSRF digest. Expiry and account state are
filtered **in SQL**, so no service bug can treat a dead row as live.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, LiteralString
from uuid import UUID

if TYPE_CHECKING:
  from datetime import datetime

  from app.db.pool import PoolConnection

__all__ = [
  "SessionRow",
  "create_preauth_session",
  "delete_session",
  "promote_session",
  "read_live_session",
  "revoke_sessions",
  "touch_session",
]

_READ_LIVE_SESSION_SQL: Final[LiteralString] = """
SELECT s.id, s.kind, s.user_id, s.csrf_sha256, s.created_at, s.last_seen_at,
       s.idle_expires_at, s.absolute_expires_at,
       u.role, u.is_active, u.must_change_password, u.display_name
  FROM public.sessions s
  LEFT JOIN public.users u ON u.id = s.user_id
 WHERE s.token_sha256 = %(token_sha256)s
   AND s.idle_expires_at > %(now)s
   AND s.absolute_expires_at > %(now)s
   AND (s.kind = 'pre_auth' OR u.is_active)
"""

_CREATE_PREAUTH_SESSION_SQL: Final[LiteralString] = """
INSERT INTO public.sessions
  (id, token_sha256, csrf_sha256, kind, user_id,
   created_at, last_seen_at, idle_expires_at, absolute_expires_at)
VALUES
  (%(id)s, %(token_sha256)s, %(csrf_sha256)s, 'pre_auth', NULL,
   %(now)s, %(now)s, %(expires_at)s, %(expires_at)s)
"""

_INSERT_FULL_SESSION_SQL: Final[LiteralString] = """
INSERT INTO public.sessions
  (id, token_sha256, csrf_sha256, kind, user_id,
   created_at, last_seen_at, idle_expires_at, absolute_expires_at)
VALUES
  (%(id)s, %(token_sha256)s, %(csrf_sha256)s, 'full', %(user_id)s,
   %(now)s, %(now)s, %(idle_expires_at)s, %(absolute_expires_at)s)
"""

_TOUCH_SESSION_SQL: Final[LiteralString] = """
UPDATE public.sessions
   SET last_seen_at = %(now)s, idle_expires_at = %(idle_expires_at)s
 WHERE id = %(id)s
   AND last_seen_at < %(stale_before)s
   AND absolute_expires_at > %(now)s
"""

_DELETE_SESSION_SQL: Final[LiteralString] = """
DELETE FROM public.sessions WHERE id = %(id)s
"""

_REVOKE_ALL_SESSIONS_SQL: Final[LiteralString] = """
DELETE FROM public.sessions WHERE user_id = %(user_id)s
"""

_REVOKE_OTHER_SESSIONS_SQL: Final[LiteralString] = """
DELETE FROM public.sessions WHERE user_id = %(user_id)s AND id <> %(keep_id)s
"""


@dataclass(frozen=True, slots=True)
class SessionRow:
  """One live session, joined to its account where it has one.

  Attributes
  ----------
  id : UUID
    The row's id.
  kind : str
    ``pre_auth`` or ``full``. ``ck_sessions_kind_user`` ties it to
    ``user_id``, so the four trailing account fields are ``None`` if and only
    if this is a pre-auth row.
  user_id : UUID | None
    ``None`` on a pre-auth row — structurally, not by convention.
  csrf_sha256 : str
    The digest ``verify_csrf`` compares a submitted token against.
  created_at : datetime
    When the row was inserted.
  last_seen_at : datetime
    When it was last touched; the >60 s rule reads it.
  idle_expires_at : datetime
    The rolling 30-minute bound (10 minutes, fixed, on a pre-auth row).
  absolute_expires_at : datetime
    The 8-hour bound a touch can never push out.
  role : str | None
    ``admin`` or ``agent``, re-read on every request — ``None`` on a pre-auth
    row.
  is_active : bool | None
    ``None`` on a pre-auth row. On a full row it is always ``True``, because
    the SQL filters on it.
  must_change_password : bool | None
    ``None`` on a pre-auth row.
  display_name : str | None
    ``None`` on a pre-auth row.
  """

  id: UUID
  kind: str
  user_id: UUID | None
  csrf_sha256: str
  created_at: datetime
  last_seen_at: datetime
  idle_expires_at: datetime
  absolute_expires_at: datetime
  role: str | None
  is_active: bool | None
  must_change_password: bool | None
  display_name: str | None


async def read_live_session(
  conn: PoolConnection, *, token_sha256: str, now: datetime
) -> SessionRow | None:
  """Read the session a token digest names, if it is live.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's short ``READ COMMITTED`` transaction.
  token_sha256 : str
    The SHA-256 of the cookie value, 64 lowercase hex characters.
  now : datetime
    The instant expiry is judged against, supplied by the caller's clock —
    which is what lets a test move time instead of sleeping (§7.3).

  Returns
  -------
  SessionRow | None
    ``None`` when there is no such row, when either expiry has passed, or
    when the account behind a full session has been disabled. The three are
    one answer on purpose: "revoked", "expired" and "unknown token" must not
    be distinguishable.

  Notes
  -----
  The last conjunct reads ``(s.kind = 'pre_auth' OR u.is_active)``. For a
  full session the foreign key guarantees ``u.*`` is non-``NULL``, so that
  disjunct is two-valued and behaves as a plain boolean; for a pre-auth row
  the first disjunct short-circuits it, which is what keeps the ``NULL``
  from the LEFT JOIN out of the predicate's result.
  """
  cursor = await conn.execute(_READ_LIVE_SESSION_SQL, {"token_sha256": token_sha256, "now": now})
  row = await cursor.fetchone()
  if row is None:
    return None
  user_id = row[2]
  return SessionRow(
    id=UUID(str(row[0])),
    kind=str(row[1]),
    user_id=None if user_id is None else UUID(str(user_id)),
    csrf_sha256=str(row[3]),
    created_at=row[4],
    last_seen_at=row[5],
    idle_expires_at=row[6],
    absolute_expires_at=row[7],
    role=None if row[8] is None else str(row[8]),
    is_active=None if row[9] is None else bool(row[9]),
    must_change_password=None if row[10] is None else bool(row[10]),
    display_name=None if row[11] is None else str(row[11]),
  )


async def create_preauth_session(
  conn: PoolConnection,
  *,
  session_id: UUID,
  token_sha256: str,
  csrf_sha256: str,
  now: datetime,
  expires_at: datetime,
) -> None:
  """Insert the ten-minute row ``GET /login`` renders its form against.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's short ``READ COMMITTED`` transaction.
  session_id : UUID
    The application-generated id (``A3``).
  token_sha256 : str
    The digest of the cookie value being set.
  csrf_sha256 : str
    The digest of the CSRF token being rendered into the form.
  now : datetime
    Written to ``created_at`` and ``last_seen_at``.
  expires_at : datetime
    Written to **both** expiry columns: a pre-auth row's ten minutes are
    absolute, so a login form left open cannot be kept alive by polling.

  Notes
  -----
  ``kind`` is the literal ``'pre_auth'`` and ``user_id`` the literal ``NULL``
  in the statement, not parameters. A pre-auth row that could be handed a
  ``user_id`` would defeat ``ck_sessions_kind_user``, whose whole purpose is
  to make this row structurally identity-free (§3.3).

  This is ``DATA_CONTRACT.md`` §6.8 row 26 — the one write an anonymous
  ``GET`` can cause — and the caller has already charged the
  ``preauth_global`` budget before reaching it (``ARC-017``(c)).
  """
  await conn.execute(
    _CREATE_PREAUTH_SESSION_SQL,
    {
      "id": str(session_id),
      "token_sha256": token_sha256,
      "csrf_sha256": csrf_sha256,
      "now": now,
      "expires_at": expires_at,
    },
  )


async def promote_session(
  conn: PoolConnection,
  *,
  preauth_id: UUID | None,
  session_id: UUID,
  user_id: UUID,
  token_sha256: str,
  csrf_sha256: str,
  now: datetime,
  idle_expires_at: datetime,
  absolute_expires_at: datetime,
) -> None:
  """Rotate to a fresh full session, inside the caller's transaction.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction — the same
    one that writes the audit row, which is what makes the two atomic.
  preauth_id : UUID | None
    The pre-auth row to delete. ``None`` when there is none to delete: a
    password change rotates a session that was already full, and its
    siblings were removed by :func:`revoke_sessions` a statement earlier.
  session_id : UUID
    The new row's application-generated id.
  user_id : UUID
    The account this session now carries.
  token_sha256 : str
    The digest of the **new** cookie value. The cookie's *name* never
    changes; what rotates is the value (``SEC-011``, ``SEC-012``).
  csrf_sha256 : str
    The digest of the new CSRF token.
  now : datetime
    Written to ``created_at`` and ``last_seen_at``.
  idle_expires_at : datetime
    ``now + 30 min``, computed by the caller.
  absolute_expires_at : datetime
    ``now + 8 h``, computed by the caller.

  Notes
  -----
  Delete-then-insert, never an UPDATE of the pre-auth row in place: the two
  kinds differ in ``user_id``, in both expiries and in the token digest, and
  a row that changed kind would leave a live token hash from the anonymous
  phase attached to an identified session.

  When ``preauth_id`` is ``None`` the DELETE is **not executed at all**,
  rather than issued with a ``NULL`` parameter. Binding ``NULL`` into
  ``WHERE id = %(id)s`` would match nothing and cost a round trip; worse, the
  obvious "``%(id)s IS NULL OR id = %(id)s``" form cannot be typed by the
  server at all (``42P18``). Choosing the statement in Python is the portable
  answer, and it is used again in :func:`revoke_sessions`.
  """
  if preauth_id is not None:
    await conn.execute(_DELETE_SESSION_SQL, {"id": str(preauth_id)})
  await conn.execute(
    _INSERT_FULL_SESSION_SQL,
    {
      "id": str(session_id),
      "token_sha256": token_sha256,
      "csrf_sha256": csrf_sha256,
      "user_id": str(user_id),
      "now": now,
      "idle_expires_at": idle_expires_at,
      "absolute_expires_at": absolute_expires_at,
    },
  )


async def touch_session(
  conn: PoolConnection,
  *,
  session_id: UUID,
  now: datetime,
  idle_expires_at: datetime,
  stale_before: datetime,
) -> bool:
  """Extend one full session's idle window, at most once a minute.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's short ``READ COMMITTED`` transaction,
    deliberately outside every business transaction (§6.8 row 14).
  session_id : UUID
    The row to touch.
  now : datetime
    Written to ``last_seen_at``.
  idle_expires_at : datetime
    ``now + 30 min``.
  stale_before : datetime
    ``now - 60 s``, computed in Python (amendment **A5**): the ">60 s" rule
    cannot be ``now() - interval`` in SQL, because interval arithmetic and
    server clocks are both banned (§9.1).

  Returns
  -------
  bool
    ``True`` when the row was actually extended. ``False`` means the row was
    touched within the last minute, is past its absolute expiry, or is gone —
    none of which is an error, and none of which the caller acts on.

  Notes
  -----
  ``absolute_expires_at > %(now)s`` is in the ``WHERE`` clause so that a
  touch can never resurrect a session past its eight-hour bound. Without it
  the idle window would be pushed out on a row the next read would reject
  anyway, which is a contradiction waiting to be discovered by a test.
  """
  cursor = await conn.execute(
    _TOUCH_SESSION_SQL,
    {
      "id": str(session_id),
      "now": now,
      "idle_expires_at": idle_expires_at,
      "stale_before": stale_before,
    },
  )
  return cursor.rowcount == 1


async def delete_session(conn: PoolConnection, *, session_id: UUID) -> None:
  """Remove one session row (logout).

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's transaction. ``slice-a.md`` §10(b)
    tables this under ``run_read_committed`` for the bare delete; logout
    runs it inside ``run_serializable`` instead, because its audit row must
    ride the transaction of the mutation it describes.
  session_id : UUID
    The row to delete.

  Notes
  -----
  Sessions are hard-deleted, never flagged (§3.3): no ``revoked_at`` column
  exists, so a deleted row leaves no token hash behind and "revoked" and
  "unknown token" are one code path. Deleting a row that is already gone is
  not an error and is not reported — there is nothing a caller could do
  differently.
  """
  await conn.execute(_DELETE_SESSION_SQL, {"id": str(session_id)})


async def revoke_sessions(
  conn: PoolConnection, *, user_id: UUID, keep_session_id: UUID | None
) -> int:
  """Delete every session of one account, optionally sparing one.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  user_id : UUID
    Whose sessions.
  keep_session_id : UUID | None
    The one row to spare, or ``None`` to remove them all. ``reset-password``
    and ``disable-user`` pass ``None``; a self-service password change passes
    ``None`` too and then inserts a fresh row, which is the same outcome
    reached in the order that leaves no window where the old token still
    works.

  Returns
  -------
  int
    How many rows were deleted.

  Notes
  -----
  Two statements, chosen in Python, for the reason spelled out in
  :func:`promote_session`: a single statement with a nullable ``keep``
  parameter would need ``(%(keep)s IS NULL OR id <> %(keep)s)``, which
  PostgreSQL refuses with ``42P18`` because it cannot infer the parameter's
  type from a comparison against ``NULL``. Two literal statements also keep
  the index usage obvious — both drive ``ix_sessions_user_id``.
  """
  if keep_session_id is None:
    cursor = await conn.execute(_REVOKE_ALL_SESSIONS_SQL, {"user_id": str(user_id)})
  else:
    cursor = await conn.execute(
      _REVOKE_OTHER_SESSIONS_SQL,
      {"user_id": str(user_id), "keep_id": str(keep_session_id)},
    )
  return cursor.rowcount
