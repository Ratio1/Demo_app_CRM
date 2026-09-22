"""The maintenance use cases behind ``scripts/manage``.

Authority: ``slice-a.md`` §1.2 (the subcommands and their exit codes),
``DATA_CONTRACT.md`` §6.8 rows 15-19, §6.9 (the last-active-admin rule),
``ACCESS_MATRIX.md`` ``ACC-605``/``ACC-609``/``ACC-611``, ``H-07``
(``role`` is set here and nowhere else).

Everything in this module runs as the **maintenance role**, from a CLI, in
its own process. There is no web route to any of it (spec §2), which is
what keeps account administration off the attack surface entirely: an
attacker with a session cannot create, disable or re-role anybody, because
the code that could is not reachable over HTTP.

``ARC-018``(b), in **R51**'s (2026-09-22) wording: this is the one module
that references the functions writing ``role`` or ``is_active`` —
``insert_user`` and ``set_active`` — together with
``count_active_admins``. The ``UPDATE`` behind ``set_active`` is the only
place ``is_active`` is ever written, and it lives in
``app/db/repositories/users.py`` like every other statement in this
application.

**``role`` is written once, at INSERT, and never updated** — ``ARC-018``(a).
A role change in this MVP is ``create-user`` plus ``disable-user``: two
audited operations rather than one silent one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from app.db.repositories.sessions import revoke_sessions
from app.db.repositories.settings import read_setting, upsert_setting
from app.db.repositories.users import (
  count_active_admins,
  find_user_for_auth,
  insert_user,
  set_active,
  set_password,
)
from app.db.retry import run_serializable
from app.security.audit import (
  ACTION_ORIGIN_SET,
  ACTION_PASSWORD_RESET,
  ACTION_PROVISIONED,
  ACTION_USER_CREATED,
  ACTION_USER_DISABLED,
  OBJECT_SETTINGS,
  OBJECT_SYSTEM,
  OBJECT_USER,
  OUTCOME_SUCCESS,
  record,
)

if TYPE_CHECKING:
  from uuid import UUID

  from app.db.pool import Pool, PoolConnection
  from app.security.clock import Clock
  from app.security.passwords import PasswordService

__all__ = [
  "ORIGIN_KEY",
  "PROVISIONING_COMPLETE",
  "PROVISIONING_KEY",
  "AlreadyProvisioned",
  "DomainRefusal",
  "DuplicateEmail",
  "LastAdminProtected",
  "UnknownUser",
  "bootstrap",
  "create_user",
  "disable_user",
  "reset_password",
  "set_origin",
]

ORIGIN_KEY: Final = "public_origin"
PROVISIONING_KEY: Final = "provisioning_state"
PROVISIONING_COMPLETE: Final = "complete"

ROLE_ADMIN: Final = "admin"
ROLE_AGENT: Final = "agent"


class DomainRefusal(Exception):
  """A refusal the operator can act on; ``scripts/manage`` exits ``3``.

  Never a bug and never a database fault: the command was well-formed and
  the domain said no.
  """


class AlreadyProvisioned(DomainRefusal):
  """``bootstrap`` ran against a database that already has an admin or an origin."""


class DuplicateEmail(DomainRefusal):
  """``create-user`` was given an address that already exists."""


class UnknownUser(DomainRefusal):
  """No user with that address exists."""


class LastAdminProtected(DomainRefusal):
  """Disabling this account would leave the application with no administrator."""


@dataclass(frozen=True, slots=True)
class CreatedUser:
  """The identity a create returned.

  Attributes
  ----------
  user_id : UUID
    The new row's id.
  email_norm : str
    The normalized address it is unique on.
  """

  user_id: UUID
  email_norm: str


def normalize_email(email: str) -> str:
  """Return ``users.email_norm`` for a submitted address.

  Parameters
  ----------
  email : str
    The address as typed.

  Returns
  -------
  str
    ``email.strip().lower()`` — byte for byte ``DATA_CONTRACT.md`` §3.2's
    rule, and byte for byte what ``account_key`` normalizes before
    hashing, so one account is always one throttle row and one unique key.
  """
  return email.strip().lower()


async def bootstrap(
  *,
  pool: Pool,
  clock: Clock,
  passwords: PasswordService,
  email: str,
  display_name: str,
  origin: str,
  password: str,
  correlation_id: str,
) -> CreatedUser:
  """Create the first administrator, the origin and the provisioning state.

  Parameters
  ----------
  pool : Pool
    The process pool, under the maintenance role.
  clock : Clock
    Injected time source.
  passwords : PasswordService
    For the Argon2 hash, computed before the transaction opens.
  email : str
    The administrator's address.
  display_name : str
    Their display name.
  origin : str
    The exact public HTTPS origin, such as ``https://127.0.0.1:3002``.
  password : str
    Their initial password.
  correlation_id : str
    This command's id, written into both audit rows.

  Returns
  -------
  CreatedUser

  Raises
  ------
  AlreadyProvisioned
    If an active administrator or an origin row already exists. All or
    nothing: this is a one-shot operation and a second run must not
    quietly add a second administrator.

  Notes
  -----
  One ``SERIALIZABLE`` transaction writes all five rows — the user, the
  two settings and the two audit rows (``user_created`` **and**
  ``provisioned``) — so ``provisioning_state = 'complete'`` is true if and
  only if the administrator exists. ``/health/ready`` reads exactly that.

  The first administrator is **not** forced to change their password: they
  chose it themselves at this prompt, and there is no second party to hand
  it over from. ``create-user`` is the opposite case and does force it.
  """
  now = clock.now()
  password_hash = await passwords.hash(password)
  user_id = uuid.uuid4()
  email_norm = normalize_email(email)

  async def _work(conn: PoolConnection) -> None:
    if await count_active_admins(conn) > 0:
      raise AlreadyProvisioned("an active administrator already exists")
    if await read_setting(conn, key=ORIGIN_KEY) is not None:
      raise AlreadyProvisioned("a public origin is already set")
    await insert_user(
      conn,
      user_id=user_id,
      email=email.strip(),
      email_norm=email_norm,
      display_name=display_name,
      role=ROLE_ADMIN,
      password_hash=password_hash,
      must_change_password=False,
      now=now,
    )
    await upsert_setting(conn, key=ORIGIN_KEY, value=origin, now=now, updated_by_user_id=user_id)
    await upsert_setting(
      conn,
      key=PROVISIONING_KEY,
      value=PROVISIONING_COMPLETE,
      now=now,
      updated_by_user_id=user_id,
    )
    await record(
      conn,
      actor_id=user_id,
      object_type=OBJECT_USER,
      object_id=user_id,
      action=ACTION_USER_CREATED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    await record(
      conn,
      actor_id=user_id,
      object_type=OBJECT_SYSTEM,
      object_id=None,
      action=ACTION_PROVISIONED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )

  await run_serializable(pool, _work, op="bootstrap")
  return CreatedUser(user_id=user_id, email_norm=email_norm)


async def create_user(
  *,
  pool: Pool,
  clock: Clock,
  passwords: PasswordService,
  email: str,
  display_name: str,
  role: str,
  password: str,
  correlation_id: str,
) -> CreatedUser:
  """Create one account with the role it will keep for its whole life.

  Parameters
  ----------
  pool : Pool
    The process pool, under the maintenance role.
  clock : Clock
    Injected time source.
  passwords : PasswordService
    For the Argon2 hash, computed before the transaction opens.
  email : str
    The new account's address.
  display_name : str
    Their display name.
  role : str
    ``admin`` or ``agent`` — set **here and nowhere else** (``H-07``).
  password : str
    The initial password the operator hands over.
  correlation_id : str
    This command's id.

  Returns
  -------
  CreatedUser

  Raises
  ------
  DuplicateEmail
    If the normalized address already exists. Checked by reading first and
    caught again by ``uq_users_email_norm`` if two runs race; either way
    it is a refusal, never a retry.

  Notes
  -----
  ``must_change_password`` is **true**: somebody other than the account
  holder knows this password, so it is a hand-over credential and the
  first login must replace it (``S1``).
  """
  now = clock.now()
  password_hash = await passwords.hash(password)
  user_id = uuid.uuid4()
  email_norm = normalize_email(email)

  async def _work(conn: PoolConnection) -> None:
    if await find_user_for_auth(conn, email_norm=email_norm) is not None:
      raise DuplicateEmail("an account with that address already exists")
    await insert_user(
      conn,
      user_id=user_id,
      email=email.strip(),
      email_norm=email_norm,
      display_name=display_name,
      role=role,
      password_hash=password_hash,
      must_change_password=True,
      now=now,
    )
    await record(
      conn,
      actor_id=None,
      object_type=OBJECT_USER,
      object_id=user_id,
      action=ACTION_USER_CREATED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )

  await run_serializable(pool, _work, op="create-user")
  return CreatedUser(user_id=user_id, email_norm=email_norm)


async def reset_password(
  *,
  pool: Pool,
  clock: Clock,
  passwords: PasswordService,
  email: str,
  password: str,
  correlation_id: str,
) -> UUID:
  """Set a new password, force a change, and end every session that account has.

  Parameters
  ----------
  pool : Pool
    The process pool, under the maintenance role.
  clock : Clock
    Injected time source.
  passwords : PasswordService
    For the Argon2 hash, computed before the transaction opens.
  email : str
    Whose password to reset.
  password : str
    The new hand-over credential.
  correlation_id : str
    This command's id.

  Returns
  -------
  UUID
    The affected user's id.

  Raises
  ------
  UnknownUser
    If no account has that address.

  Notes
  -----
  Operator-only recovery (``S1``). Every session of that user is deleted
  in the same transaction as the new hash, so a reset always ends whatever
  access the old password was supporting — including an attacker's.
  """
  now = clock.now()
  password_hash = await passwords.hash(password)
  email_norm = normalize_email(email)

  async def _work(conn: PoolConnection) -> UUID:
    user = await find_user_for_auth(conn, email_norm=email_norm)
    if user is None:
      raise UnknownUser("no account with that address")
    updated = await set_password(
      conn,
      user_id=user.id,
      password_hash=password_hash,
      must_change_password=True,
      password_changed_at=now,
      expected_version=user.version,
      now=now,
    )
    if not updated:
      raise UnknownUser("the account changed while the reset was running")
    await revoke_sessions(conn, user_id=user.id, keep_session_id=None)
    await record(
      conn,
      actor_id=None,
      object_type=OBJECT_USER,
      object_id=user.id,
      action=ACTION_PASSWORD_RESET,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return user.id

  return await run_serializable(pool, _work, op="reset-password")


async def disable_user(
  *,
  pool: Pool,
  clock: Clock,
  email: str,
  correlation_id: str,
) -> UUID:
  """Deactivate one account, refusing to remove the last active administrator.

  Parameters
  ----------
  pool : Pool
    The process pool, under the maintenance role.
  clock : Clock
    Injected time source.
  email : str
    Whose account to disable.
  correlation_id : str
    This command's id.

  Returns
  -------
  UUID
    The disabled user's id.

  Raises
  ------
  UnknownUser
    If no account has that address.
  LastAdminProtected
    If the update would leave zero active administrators.

  Notes
  -----
  ``DATA_CONTRACT.md`` §6.9, and the reason this is the one command that
  genuinely needs ``SERIALIZABLE``: the ``UPDATE`` runs **first** and the
  ``count(*)`` is a predicate read taken **after** this transaction's own
  write. Two concurrent invocations, each disabling the other's
  administrator, each see ``1`` locally; PostgreSQL's SSI detects the
  read-write conflict and aborts one with ``40001``. The retry wrapper
  re-runs it, the re-read now sees ``0``, and it fails with this domain
  error — which is never retried. At ``READ COMMITTED`` both would commit
  and the deployment would be left with no administrator (``SQL-014``).

  The account's sessions are deleted in the same transaction, so disabling
  takes effect immediately rather than at the next expiry.
  """
  now = clock.now()
  email_norm = normalize_email(email)

  async def _work(conn: PoolConnection) -> UUID:
    user = await find_user_for_auth(conn, email_norm=email_norm)
    if user is None:
      raise UnknownUser("no account with that address")
    updated = await set_active(
      conn,
      user_id=user.id,
      is_active=False,
      expected_version=user.version,
      now=now,
    )
    if not updated:
      raise UnknownUser("the account changed while the command was running")
    if await count_active_admins(conn) == 0:
      raise LastAdminProtected("that is the last active administrator")
    await revoke_sessions(conn, user_id=user.id, keep_session_id=None)
    await record(
      conn,
      actor_id=None,
      object_type=OBJECT_USER,
      object_id=user.id,
      action=ACTION_USER_DISABLED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return user.id

  return await run_serializable(pool, _work, op="disable-user")


async def set_origin(
  *,
  pool: Pool,
  clock: Clock,
  origin: str,
  correlation_id: str,
) -> None:
  """Write the public HTTPS origin every request is compared against.

  Parameters
  ----------
  pool : Pool
    The process pool, under the maintenance role.
  clock : Clock
    Injected time source.
  origin : str
    The exact origin, such as ``https://127.0.0.1:3002``.
  correlation_id : str
    This command's id.

  Notes
  -----
  CLI-only, by design: the runtime role holds ``SELECT`` on
  ``app_settings`` and nothing more (``DATA_CONTRACT.md`` §5.2), so no web
  path — and no compromised session — can repoint the origin the
  ``Host``/``Origin`` check depends on.
  """
  now = clock.now()

  async def _work(conn: PoolConnection) -> None:
    await upsert_setting(conn, key=ORIGIN_KEY, value=origin, now=now, updated_by_user_id=None)
    await record(
      conn,
      actor_id=None,
      object_type=OBJECT_SETTINGS,
      object_id=None,
      action=ACTION_ORIGIN_SET,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )

  await run_serializable(pool, _work, op="set-origin")
