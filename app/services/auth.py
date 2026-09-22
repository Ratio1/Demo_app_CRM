"""Login, password change and logout (``DATA_CONTRACT.md`` §6.8 rows 2-5).

Authority: ``slice-a.md`` §2.4 (the ordered stages of each), §10(b) (the
repository surface and the wrapper each function runs under),
``DATA_CONTRACT.md`` §6.8 note 1 (the rehash's version guard),
``THREAT_MODEL.md`` T-01/T-03.

Four properties the ordering here exists to hold:

*Argon2 never runs inside a transaction.* Verifying, and the rehash a
parameter drift triggers, both happen **before** the ``SERIALIZABLE`` block
opens, with no connection held (``DATA_CONTRACT.md`` §6.1). A 20 ms hash
inside a transaction would hold one of four connections for the whole of
it, and would be repeated by every retry.

*Missing, disabled and wrong-password are one outcome.* There is a single
``invalid`` result; a caller cannot tell the three apart and neither can a
client (``SEC-032``).

*The failure counter outlives the failure.* ``register_failure`` and the
``login_failed`` audit row commit together in their own ``READ COMMITTED``
transaction, so the authentication path rolling back cannot erase the
record of what it rejected (``SQL-027``).

*Every success writes its audit row in the same transaction as the rows it
describes* — the same connection, inside the same ``run_serializable``
block (``S7``, ``SQL-016``).

``ARC-018``(b), as **R51** (2026-09-22) rewords it, holds here by
construction. The rule is now: no file but ``app/db/repositories/users.py``
holds an ``UPDATE`` of ``users``, and the functions that write ``role`` or
``is_active`` are referenced only from ``app/services/accounts.py``; reads
of that module are unrestricted, because authentication cannot be written
without them. This module imports exactly ``find_user_for_auth``,
``read_user``, ``set_password`` and ``update_password_hash`` — two reads
and the two password writes. It imports neither ``set_active`` nor
``insert_user`` (the only writers of ``is_active`` and ``role``) nor
``count_active_admins``, and it holds no SQL of its own.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from app.db.repositories.sessions import delete_session, promote_session, revoke_sessions
from app.db.repositories.throttle import register_failure
from app.db.repositories.users import (
  find_user_for_auth,
  read_user,
  set_password,
  update_password_hash,
)
from app.db.retry import run_read_committed, run_serializable
from app.security.audit import (
  ACTION_LOGIN_FAILED,
  ACTION_LOGIN_SUCCEEDED,
  ACTION_LOGOUT,
  ACTION_PASSWORD_CHANGED,
  ACTION_THROTTLE_LOCKED,
  OBJECT_SESSION,
  OBJECT_USER,
  OUTCOME_DENIED,
  OUTCOME_FAILURE,
  OUTCOME_SUCCESS,
  record,
)
from app.security.csrf import csrf_for_token
from app.security.passwords import CP_74_MISMATCH
from app.security.sessions import ABSOLUTE_TTL, IDLE_TTL, mint_token
from app.security.throttle import account_key

if TYPE_CHECKING:
  from datetime import datetime
  from uuid import UUID

  from app.db.pool import Pool, PoolConnection
  from app.db.repositories.users import UserAuthRow
  from app.security.clock import Clock
  from app.security.passwords import PasswordService
  from app.security.principal import Principal
  from app.security.throttle import ThrottleService

__all__ = [
  "CP_70_WRONG_CURRENT",
  "OUTCOME_INVALID",
  "OUTCOME_LOCKED",
  "OUTCOME_OK",
  "ChangePasswordResult",
  "LoginResult",
  "change_password",
  "login",
  "logout",
]

#: ``UX_FLOWS.md`` §6.1 ``CP-70``.
CP_70_WRONG_CURRENT: Final = "That is not your current password."

OUTCOME_OK: Final = "ok"
OUTCOME_INVALID: Final = "invalid"
OUTCOME_LOCKED: Final = "locked"


@dataclass(frozen=True, slots=True)
class LoginResult:
  """What ``POST /login`` learned, with no HTTP in it.

  Attributes
  ----------
  outcome : str
    :data:`OUTCOME_OK`, :data:`OUTCOME_INVALID` (missing account, disabled
    account or wrong password — one value on purpose) or
    :data:`OUTCOME_LOCKED`.
  token : str | None
    The new session token for the cookie, on success only.
  must_change_password : bool
    Whether the caller must be sent to the forced-reset screen.
  retry_after_s : int | None
    Seconds until the throttle lifts, when locked.
  """

  outcome: str
  token: str | None = None
  must_change_password: bool = False
  retry_after_s: int | None = None


@dataclass(frozen=True, slots=True)
class ChangePasswordResult:
  """What ``POST /account/password`` learned.

  Attributes
  ----------
  errors : dict[str, list[str]]
    Field name to rendered messages, empty on success. The names are the
    template's: ``current_password``, ``new_password``,
    ``confirm_password``.
  token : str | None
    The rotated session's new cookie value, on success only.
  """

  errors: dict[str, list[str]]
  token: str | None = None


async def _count_failure(
  pool: Pool,
  throttle: ThrottleService,
  *,
  key: str,
  user_id: UUID | None,
  correlation_id: str,
  now: datetime,
) -> None:
  """Record one failed attempt and its audit rows in one transaction.

  Parameters
  ----------
  pool : Pool
    The process pool; this opens its own ``READ COMMITTED`` transaction.
  throttle : ThrottleService
    For its configured threshold, window and lock length.
  key : str
    The ``account_key`` — written for an unknown account too, so that the
    existence of a throttle row is not an account oracle.
  user_id : UUID | None
    The account's id when it exists, else ``None`` (**R13**): the
    submitted identifier never enters the audit trail in any form.
  correlation_id : str
    This request's id.
  now : datetime
    The instant of the failure.

  Notes
  -----
  ``DATA_CONTRACT.md`` §6.8 row 2: the counter and the ``login_failed``
  row commit **together**, and ``throttle_locked`` is written once, by the
  increment that set ``locked_until`` — never on each later refusal, or
  the deny trail would grow without the bound it exists to record.
  """
  window_cutoff = now - throttle.window
  locked_until = now + throttle.lock_for

  async def _work(conn: PoolConnection) -> None:
    outcome = await register_failure(
      conn,
      account_key=key,
      now=now,
      window_cutoff=window_cutoff,
      threshold=throttle.failures,
      locked_until=locked_until,
    )
    await record(
      conn,
      actor_id=user_id,
      object_type=OBJECT_USER,
      object_id=user_id,
      action=ACTION_LOGIN_FAILED,
      outcome=OUTCOME_FAILURE,
      correlation_id=correlation_id,
      at=now,
    )
    if outcome.transitioned:
      await record(
        conn,
        actor_id=user_id,
        object_type=OBJECT_USER,
        object_id=user_id,
        action=ACTION_THROTTLE_LOCKED,
        outcome=OUTCOME_DENIED,
        correlation_id=correlation_id,
        at=now,
      )

  await run_read_committed(pool, _work, op="login-failure")


async def login(
  *,
  pool: Pool,
  clock: Clock,
  passwords: PasswordService,
  throttle: ThrottleService,
  email: str,
  password: str,
  preauth_id: UUID | None,
  correlation_id: str,
) -> LoginResult:
  """Authenticate one submission and, on success, rotate the session.

  Parameters
  ----------
  pool : Pool
    The process pool.
  clock : Clock
    Injected time source. Read **once**, so every row this operation
    writes carries the same instant.
  passwords : PasswordService
    Argon2 behind the bounded gate.
  throttle : ThrottleService
    The per-account counter.
  email : str
    Exactly what was submitted.
  password : str
    Exactly what was submitted; never logged, never truncated.
  preauth_id : UUID | None
    The pre-auth row this request's CSRF token was checked against. It is
    deleted as part of the rotation, so the old cookie value dies the
    moment the new one is issued (``SEC-012``).
  correlation_id : str
    This request's id, written into every audit row below.

  Returns
  -------
  LoginResult

  Raises
  ------
  app.security.passwords.HashQueueFull
    When the bounded hash gate is full; the caller answers ``429``.

  Notes
  -----
  The version read before Argon2 is the guard the transaction re-checks.
  If a concurrent password change committed in between, the cleartext was
  verified against a hash that is no longer current, so the login **fails
  generically**: no session, and above all no rehash written under the old
  guard, which would overwrite the new password with a rehash of the old
  one (``DATA_CONTRACT.md`` §6.8 note 1).
  """
  now = clock.now()
  key = account_key(email)
  email_norm = email.strip().lower()

  state = await throttle.state(key, now=now)
  if state.locked:
    return LoginResult(outcome=OUTCOME_LOCKED, retry_after_s=state.retry_after_s)

  async def _find(conn: PoolConnection) -> UserAuthRow | None:
    return await find_user_for_auth(conn, email_norm=email_norm)

  user = await run_read_committed(pool, _find, op="find-user-for-auth")

  # A disabled account verifies against the dummy hash exactly as a
  # missing one does, so "disabled" costs the same and says the same.
  # Written as an explicit ``user is None`` branch rather than a ``usable``
  # flag because a flag carries no type information: ``mypy --strict``
  # cannot narrow ``UserAuthRow | None`` through it, and every attribute
  # read below was an error. The dummy hash still runs in the same gate
  # slot, with the same parameters, for a missing and for a disabled
  # account alike (``T-03``/``SEC-033``), and all three outcomes are still
  # the single :data:`OUTCOME_INVALID` (``SEC-032``).
  if user is None or not user.is_active:
    await passwords.verify(None, password)
    await _count_failure(
      pool,
      throttle,
      key=key,
      user_id=None if user is None else user.id,
      correlation_id=correlation_id,
      now=now,
    )
    return LoginResult(outcome=OUTCOME_INVALID)

  if not await passwords.verify(user.password_hash, password):
    await _count_failure(
      pool,
      throttle,
      key=key,
      user_id=user.id,
      correlation_id=correlation_id,
      now=now,
    )
    return LoginResult(outcome=OUTCOME_INVALID)

  user_id: UUID = user.id
  expected_version: int = user.version
  must_change_password: bool = user.must_change_password
  rehashed = await passwords.hash(password) if passwords.needs_rehash(user.password_hash) else None

  token, token_digest = mint_token()
  _csrf_token, csrf_digest = csrf_for_token(token)
  session_id = uuid.uuid4()

  async def _rotate(conn: PoolConnection) -> bool:
    current = await read_user(conn, user_id=user_id)
    if current is None or not current.is_active or current.version != expected_version:
      return False
    if rehashed is not None and not await update_password_hash(
      conn,
      user_id=user_id,
      password_hash=rehashed,
      expected_version=expected_version,
      now=now,
    ):
      return False
    await promote_session(
      conn,
      preauth_id=preauth_id,
      session_id=session_id,
      user_id=user_id,
      token_sha256=token_digest,
      csrf_sha256=csrf_digest,
      now=now,
      idle_expires_at=now + IDLE_TTL,
      absolute_expires_at=now + ABSOLUTE_TTL,
    )
    await record(
      conn,
      actor_id=user_id,
      object_type=OBJECT_USER,
      object_id=user_id,
      action=ACTION_LOGIN_SUCCEEDED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return True

  if not await run_serializable(pool, _rotate, op="login"):
    await _count_failure(
      pool,
      throttle,
      key=key,
      user_id=user_id,
      correlation_id=correlation_id,
      now=now,
    )
    return LoginResult(outcome=OUTCOME_INVALID)

  # Only after the rotation committed: a login that failed to rotate must
  # not clear the counter that recorded why. An UPDATE, never a DELETE —
  # the runtime role holds no DELETE on login_throttle (§5.2).
  await throttle.clear(key, now=now)
  return LoginResult(
    outcome=OUTCOME_OK,
    token=token,
    must_change_password=must_change_password,
  )


async def change_password(
  *,
  pool: Pool,
  clock: Clock,
  passwords: PasswordService,
  principal: Principal,
  current_password: str,
  new_password: str,
  confirm_password: str,
  correlation_id: str,
) -> ChangePasswordResult:
  """Change the signed-in user's password and rotate every session.

  Parameters
  ----------
  pool : Pool
    The process pool.
  clock : Clock
    Injected time source.
  passwords : PasswordService
    Argon2 and the policy.
  principal : Principal
    The signed-in user, forced-reset or not.
  current_password : str
    Required even on the forced path (``SEC-016``): without it, whoever
    reaches an unattended signed-in browser could take the account over
    permanently instead of merely using it until the session expires.
  new_password : str
    The candidate.
  confirm_password : str
    The repeat.
  correlation_id : str
    This request's id.

  Returns
  -------
  ChangePasswordResult
    On success ``errors`` is empty and ``token`` carries the rotated
    session's new cookie value; every other session of that user was
    deleted in the same transaction (``CP-06``).

  Raises
  ------
  app.security.passwords.HashQueueFull
    When the bounded hash gate is full; the caller answers ``429``.
  """
  now = clock.now()

  async def _read(conn: PoolConnection) -> UserAuthRow | None:
    return await read_user(conn, user_id=principal.id)

  user = await run_read_committed(pool, _read, op="read-user-for-password-change")
  if user is None:
    return ChangePasswordResult(errors={"current_password": [CP_70_WRONG_CURRENT]})

  expected_version: int = user.version
  errors: dict[str, list[str]] = {}
  if not await passwords.verify(user.password_hash, current_password):
    errors["current_password"] = [CP_70_WRONG_CURRENT]

  # Context words: the user's own display name and the local part of their
  # address, so "AdaAdmin2026" is refused for Ada Admin and nobody else.
  context = (user.display_name, user.email_norm.split("@", 1)[0])
  policy_errors = passwords.validate(new_password, context=context)
  if policy_errors:
    errors["new_password"] = policy_errors
  if new_password != confirm_password:
    errors["confirm_password"] = [CP_74_MISMATCH]
  if errors:
    return ChangePasswordResult(errors=errors)

  new_hash = await passwords.hash(new_password)
  token, token_digest = mint_token()
  _csrf_token, csrf_digest = csrf_for_token(token)
  session_id = uuid.uuid4()

  async def _apply(conn: PoolConnection) -> bool:
    current = await read_user(conn, user_id=principal.id)
    if current is None or not current.is_active or current.version != expected_version:
      return False
    if not await set_password(
      conn,
      user_id=principal.id,
      password_hash=new_hash,
      must_change_password=False,
      password_changed_at=now,
      expected_version=expected_version,
      now=now,
    ):
      return False
    await revoke_sessions(conn, user_id=principal.id, keep_session_id=None)
    await promote_session(
      conn,
      preauth_id=None,
      session_id=session_id,
      user_id=principal.id,
      token_sha256=token_digest,
      csrf_sha256=csrf_digest,
      now=now,
      idle_expires_at=now + IDLE_TTL,
      absolute_expires_at=now + ABSOLUTE_TTL,
    )
    await record(
      conn,
      actor_id=principal.id,
      object_type=OBJECT_USER,
      object_id=principal.id,
      action=ACTION_PASSWORD_CHANGED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return True

  if not await run_serializable(pool, _apply, op="change-password"):
    # A concurrent change committed first. Nothing was written, and the
    # user is told their current password did not match — true of the row
    # as it now stands, and it discloses nothing about the race.
    return ChangePasswordResult(errors={"current_password": [CP_70_WRONG_CURRENT]})
  return ChangePasswordResult(errors={}, token=token)


async def logout(
  *,
  pool: Pool,
  clock: Clock,
  principal: Principal,
  correlation_id: str,
) -> None:
  """End one session and record it, atomically.

  Parameters
  ----------
  pool : Pool
    The process pool.
  clock : Clock
    Injected time source.
  principal : Principal
    The signed-in user; only their own session is deleted.
  correlation_id : str
    This request's id.

  Notes
  -----
  ``DATA_CONTRACT.md`` §6.8 row 4 runs this at ``SERIALIZABLE``, which is
  also what keeps the ``logout`` audit row in the same transaction as the
  ``DELETE`` (``S7``). ``slice-a.md`` §10(b)'s table lists
  ``delete_session`` under ``run_read_committed``; that placement is for
  the bare delete, and it is overridden here because an audit row must
  ride the transaction of the mutation it describes. The row is
  hard-deleted, so no token hash is left behind.
  """
  now = clock.now()

  async def _end(conn: PoolConnection) -> None:
    await delete_session(conn, session_id=principal.session_id)
    await record(
      conn,
      actor_id=principal.id,
      object_type=OBJECT_SESSION,
      object_id=principal.session_id,
      action=ACTION_LOGOUT,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )

  await run_serializable(pool, _end, op="logout")
