"""``users`` — the account row, and the one file allowed to deactivate one.

``ARC-018``, in the form the Slice A contract step settled (``slice-a.md``
§10(b), ruling **R39**):

* **(a)** no ``UPDATE users`` statement anywhere under ``app/`` or
  ``scripts/`` names ``role`` in its ``SET`` list. ``users.role`` is written
  by :func:`insert_user` and by nothing else, ever (``H-07``). A role change
  in this MVP is ``create-user`` plus ``disable-user``, two audited
  operations.
* **(b)** exactly one file may name ``is_active`` in an ``UPDATE users``
  ``SET`` list, and it is **this one** (:func:`set_active`). ``app/routes/**``
  and ``app/services/**`` except ``app/services/accounts.py`` may not import
  this module. The by-name exemption is the honest form: the statement has to
  live in the Data lane like every other statement, so the gate confines
  *who may reach it* rather than pretending no repository holds it.

Every editable write carries ``WHERE id = %(id)s AND version = %(version)s``
and sets ``version = version + 1`` in the same statement (§4.1). Zero rows
updated is a **stale edit**, reported as ``False``, and never a retry: the
caller re-reads and decides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, LiteralString
from uuid import UUID

if TYPE_CHECKING:
  from datetime import datetime

  from app.db.pool import PoolConnection

__all__ = [
  "UserAuthRow",
  "UserOptionRow",
  "count_active_admins",
  "find_user_for_auth",
  "insert_user",
  "is_active_user",
  "list_active_users",
  "read_user",
  "set_active",
  "set_password",
  "update_password_hash",
]

#: The two reads select the same eight columns, in the same order, and
#: :func:`_row_to_user` unpacks both. The list is written out in each
#: statement rather than composed from a shared fragment: every SELECT names
#: its columns (``ARC-011``), and an f-string assembling SQL is exactly the
#: shape a reviewer — and ``ruff`` ``S608`` — must not have to think about.
#: ``email`` is deliberately absent from both: nothing in the auth path
#: displays the address as typed, and the normalized form is the key.
_FIND_USER_FOR_AUTH_SQL: Final[LiteralString] = """
SELECT id, email_norm, display_name, role, is_active, must_change_password,
       password_hash, version
  FROM public.users
 WHERE email_norm = %(email_norm)s
"""

_READ_USER_SQL: Final[LiteralString] = """
SELECT id, email_norm, display_name, role, is_active, must_change_password,
       password_hash, version
  FROM public.users
 WHERE id = %(id)s
"""

_UPDATE_CREDENTIALS_SQL: Final[LiteralString] = """
UPDATE public.users
   SET password_hash = %(password_hash)s,
       password_changed_at = %(password_changed_at)s,
       must_change_password = %(must_change_password)s,
       version = version + 1,
       updated_at = %(now)s
 WHERE id = %(id)s AND version = %(version)s
"""

_REHASH_SQL: Final[LiteralString] = """
UPDATE public.users
   SET password_hash = %(password_hash)s,
       version = version + 1,
       updated_at = %(now)s
 WHERE id = %(id)s AND version = %(version)s
"""

_INSERT_USER_SQL: Final[LiteralString] = """
INSERT INTO public.users
  (id, email, email_norm, display_name, role, password_hash, password_changed_at,
   must_change_password, is_active, version, created_at, updated_at)
VALUES
  (%(id)s, %(email)s, %(email_norm)s, %(display_name)s, %(role)s, %(password_hash)s,
   %(now)s, %(must_change_password)s, true, 1, %(now)s, %(now)s)
"""

_SET_ACTIVE_SQL: Final[LiteralString] = """
UPDATE public.users
   SET is_active = %(is_active)s,
       version = version + 1,
       updated_at = %(now)s
 WHERE id = %(id)s AND version = %(version)s
"""

_COUNT_ACTIVE_ADMINS_SQL: Final[LiteralString] = """
SELECT count(*) FROM public.users WHERE role = 'admin' AND is_active = true
"""

#: Slice B, ``PIN 9``. Deliberately not :func:`read_user`, which would answer
#: the same question while pulling ``password_hash`` into memory to decide a
#: reassignment — a widening for no gain.
_IS_ACTIVE_USER_SQL: Final[LiteralString] = """
SELECT count(*) FROM public.users WHERE id = %(id)s AND is_active = true
"""

#: Slice B, amendment **A-10**. The source of ``contacts/detail.html``'s frozen
#: ``reassign.assignable_users``. Ordered by the displayed column with an ``id``
#: tiebreaker, so two people sharing a display name still order deterministically.
_LIST_ACTIVE_USERS_SQL: Final[LiteralString] = """
SELECT id, display_name
  FROM public.users
 WHERE is_active = true
 ORDER BY display_name, id
"""


@dataclass(frozen=True, slots=True)
class UserAuthRow:
  """One account, as every authentication and maintenance path reads it.

  Attributes
  ----------
  id : UUID
    The account's application-generated id.
  email_norm : str
    ``email.strip().lower()`` — the login lookup key.
  display_name : str
    The name shown in the shell, and one of the two context words the
    password policy refuses.
  role : str
    ``admin`` or ``agent``. Re-read on every request rather than carried in
    the cookie, so a change takes effect immediately.
  is_active : bool
    ``False`` disables sign-in; a disabled account verifies against the dummy
    hash exactly as a missing one does.
  must_change_password : bool
    ``True`` confines the session to the change-password page and logout.
  password_hash : str
    The encoded Argon2id hash. Never logged, never rendered, never compared
    outside :class:`app.security.passwords.PasswordService`.
  version : int
    The row's optimistic-concurrency guard.
  """

  id: UUID
  email_norm: str
  display_name: str
  role: str
  is_active: bool
  must_change_password: bool
  password_hash: str
  version: int


@dataclass(frozen=True, slots=True)
class UserOptionRow:
  """One selectable account, for the admin reassignment control.

  Attributes
  ----------
  id : UUID
    ``users.id``, the value the ``owner_id`` field posts back.
  display_name : str
    What the option reads. ``CONTRACTS.md`` §8 rule 4 pins person names to
    ``users.display_name``; no address is exposed by this read, because an
    admin choosing an owner never needs one.
  """

  id: UUID
  display_name: str


def _row_to_user(row: tuple[object, ...]) -> UserAuthRow:
  """Build a :class:`UserAuthRow` from one row of either account SELECT.

  Parameters
  ----------
  row : tuple[object, ...]
    The tuple as psycopg returned it, in the order of the SELECT list.

  Returns
  -------
  UserAuthRow
    The row with its ``TEXT`` id converted back to :class:`uuid.UUID`. This
    is the module's single conversion point in that direction
    (``DATA_CONTRACT.md`` §2.2).
  """
  return UserAuthRow(
    id=UUID(str(row[0])),
    email_norm=str(row[1]),
    display_name=str(row[2]),
    role=str(row[3]),
    is_active=bool(row[4]),
    must_change_password=bool(row[5]),
    password_hash=str(row[6]),
    version=int(str(row[7])),
  )


async def find_user_for_auth(conn: PoolConnection, *, email_norm: str) -> UserAuthRow | None:
  """Look an account up by its normalized address.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's transaction.
  email_norm : str
    ``submitted.strip().lower()``, computed in Python — the identical
    normalization ``users.email_norm`` is written with (§3.2), so a known
    account is always found.

  Returns
  -------
  UserAuthRow | None
    ``None`` when no account has that address. The caller must treat that
    exactly as it treats a wrong password: it still runs the dummy hash, in
    the same semaphore slot (``SEC-032``, ``SEC-033``).

  Notes
  -----
  This read runs **before** Argon2 and outside every business transaction,
  with no connection held during the hash (§6.1). The value it returns is a
  snapshot; the ``SERIALIZABLE`` transaction that follows re-reads the row by
  id under its ``version`` (:func:`read_user`).
  """
  cursor = await conn.execute(_FIND_USER_FOR_AUTH_SQL, {"email_norm": email_norm})
  row = await cursor.fetchone()
  return None if row is None else _row_to_user(row)


async def read_user(conn: PoolConnection, *, user_id: UUID) -> UserAuthRow | None:
  """Re-read one account by id, inside the transaction that will write it.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  user_id : UUID
    The account to re-read.

  Returns
  -------
  UserAuthRow | None
    ``None`` when the row is gone.

  Notes
  -----
  Added beyond ``slice-a.md`` §5's list because :func:`find_user_for_auth`
  keys on ``email_norm`` and runs before Argon2: the re-read §6.8 rows 3 and
  5 require *inside* the transaction is by id and must see the row's current
  ``version``, ``is_active`` and ``role``. A version other than the one read
  before Argon2 fails the login generically — it can mean a concurrent
  password change committed, and writing a rehash under the stale guard would
  overwrite the new password with a rehash of the old one (§6.8 note 1).
  """
  cursor = await conn.execute(_READ_USER_SQL, {"id": str(user_id)})
  row = await cursor.fetchone()
  return None if row is None else _row_to_user(row)


async def set_password(
  conn: PoolConnection,
  *,
  user_id: UUID,
  password_hash: str,
  must_change_password: bool,
  password_changed_at: datetime,
  expected_version: int,
  now: datetime,
) -> bool:
  """Write a new password — a real credential change (§6.8 rows 5 and 17).

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  user_id : UUID
    Whose password.
  password_hash : str
    The encoded Argon2id hash, computed before the transaction opened.
  must_change_password : bool
    ``False`` for a self-service change, ``True`` for an operator reset.
  password_changed_at : datetime
    When the credential changed — the caller's instant, not the server's.
  expected_version : int
    The version read before the hash was computed.
  now : datetime
    The caller's instant, written to ``updated_at``.

  Returns
  -------
  bool
    ``False`` when no row matched, which means a stale edit: something else
    changed this account between the read and this write. It is never a
    retry — the caller answers as if the current password had not matched,
    which is true of the row as it now stands and discloses nothing about the
    race.

  Notes
  -----
  Split from :func:`update_password_hash` (amendment **A2**) precisely so
  that the login-time rehash cannot reach ``password_changed_at`` or
  ``must_change_password``. One function with a ``must_change_password``
  argument would silently clear a forced reset the first time a rehash fired.
  """
  cursor = await conn.execute(
    _UPDATE_CREDENTIALS_SQL,
    {
      "id": str(user_id),
      "password_hash": password_hash,
      "password_changed_at": password_changed_at,
      "must_change_password": must_change_password,
      "now": now,
      "version": expected_version,
    },
  )
  return cursor.rowcount == 1


async def update_password_hash(
  conn: PoolConnection,
  *,
  user_id: UUID,
  password_hash: str,
  expected_version: int,
  now: datetime,
) -> bool:
  """Re-encode an existing password at the pinned Argon2 parameters.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  user_id : UUID
    Whose hash.
  password_hash : str
    The new encoding of the **same** password, computed on the bounded
    executor before the transaction opened and reused across every retry
    (§6.8 note 1).
  expected_version : int
    The version read before Argon2 ran.
  now : datetime
    The caller's instant, written to ``updated_at``.

  Returns
  -------
  bool
    ``False`` on a stale edit, which fails the login.

  Notes
  -----
  A parameter migration, not a password change: ``password_changed_at`` and
  ``must_change_password`` are untouched, so this must not revoke sessions
  and cannot clear a forced reset. ``version`` **is** bumped, because the row
  changed and §4.1 admits no unversioned write to an editable row.
  """
  cursor = await conn.execute(
    _REHASH_SQL,
    {
      "id": str(user_id),
      "password_hash": password_hash,
      "now": now,
      "version": expected_version,
    },
  )
  return cursor.rowcount == 1


async def insert_user(
  conn: PoolConnection,
  *,
  user_id: UUID,
  email: str,
  email_norm: str,
  display_name: str,
  role: str,
  password_hash: str,
  must_change_password: bool,
  now: datetime,
) -> None:
  """Create one account — maintenance role only (§6.8 rows 15 and 16).

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  user_id : UUID
    The application-generated id (``A3``).
  email : str
    The address as the operator typed it, 3..254 characters and containing
    an ``@`` with something on either side (``ck_users_email``).
  email_norm : str
    ``email.strip().lower()``, computed in Python.
  display_name : str
    1..160 characters.
  role : str
    ``admin`` or ``agent``. **This statement is the only place ``role`` is
    ever written** (``H-07``, ``ARC-018``(a)).
  password_hash : str
    The encoded Argon2id hash.
  must_change_password : bool
    ``False`` for ``bootstrap``'s first admin, ``True`` for ``create-user``.
  now : datetime
    The caller's instant, written to ``password_changed_at``, ``created_at``
    and ``updated_at`` alike.

  Notes
  -----
  ``is_active`` is literal ``true`` and ``version`` literal ``1`` in the
  statement, not parameters: a new account is active at version one, and
  there is no caller that could legitimately ask for anything else. The
  schema carries no DEFAULT clauses (§2.3 rule 1), so both are written here.

  A duplicate address raises ``23505`` on ``uq_users_email_norm``. It is not
  caught: ``create-user`` classifies it as "already exists" (exit 3), which
  is a domain refusal and not a retry (§6.8 row 16).
  """
  await conn.execute(
    _INSERT_USER_SQL,
    {
      "id": str(user_id),
      "email": email,
      "email_norm": email_norm,
      "display_name": display_name,
      "role": role,
      "password_hash": password_hash,
      "must_change_password": must_change_password,
      "now": now,
    },
  )


async def set_active(
  conn: PoolConnection,
  *,
  user_id: UUID,
  is_active: bool,
  expected_version: int,
  now: datetime,
) -> bool:
  """Enable or disable one account — the ``ARC-018``(b) statement.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  user_id : UUID
    Whose account.
  is_active : bool
    ``False`` disables it; Slice A has no path that passes ``True``.
  expected_version : int
    The version read in the same transaction.
  now : datetime
    The caller's instant, written to ``updated_at``.

  Returns
  -------
  bool
    ``False`` on a stale edit.

  Notes
  -----
  This is the **one** ``UPDATE users`` in the tree whose ``SET`` list names
  ``is_active``, and the reason ``ARC-018``(b) exempts this file by name
  rather than claiming no repository holds the statement.

  It is composed **before** :func:`count_active_admins`, in one
  ``run_serializable``, by ``app/services/accounts.py``: the UPDATE first,
  then the predicate read. That order is what makes PostgreSQL's SSI abort
  the losing run when two ``disable-user`` commands race for the last
  administrator (§6.9, ``SQL-014``) — the read is what creates the conflict,
  so it has to come after the write it must see.
  """
  cursor = await conn.execute(
    _SET_ACTIVE_SQL,
    {
      "id": str(user_id),
      "is_active": is_active,
      "now": now,
      "version": expected_version,
    },
  )
  return cursor.rowcount == 1


async def count_active_admins(conn: PoolConnection) -> int:
  """Count the accounts that can still administer this installation.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.

  Returns
  -------
  int
    How many rows have ``role = 'admin'`` and ``is_active``.

  Notes
  -----
  Served by ``ix_users_role_active``. Two callers: ``bootstrap`` refuses to
  run when this is above zero, and ``disable-user`` refuses to commit when
  its own UPDATE brought it to zero (§6.9).
  """
  cursor = await conn.execute(_COUNT_ACTIVE_ADMINS_SQL)
  row = await cursor.fetchone()
  return 0 if row is None else int(str(row[0]))


async def is_active_user(conn: PoolConnection, *, user_id: UUID) -> bool:
  """Answer whether one account exists and is enabled — ``PIN 9``'s target check.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction — the same
    one that performs the reassignment.
  user_id : UUID
    The candidate owner submitted by an administrator.

  Returns
  -------
  bool
    ``True`` only for an existing, active account. **Missing** and
    **disabled** both answer ``False``, which is what ``ACC-032`` wants: one
    400 for "not a valid target", with no branch that would tell an admin
    which of the two it was.

  Notes
  -----
  Additive, and a **read**: no existing function changes and ``ARC-018`` is
  untouched. It takes no ``Scope`` — ``users`` is an identity repository, and
  a scope would add a second, redundant authorization input to a lookup that
  is already id-keyed (``ARC-001``'s identity/infrastructure side).

  Composing it **inside** the reassign transaction is the load-bearing part: a
  concurrent ``disable-user`` updates the row this transaction read,
  PostgreSQL's SSI sees the read-write conflict and aborts one side with
  ``40001``, and the retry re-reads and refuses. The same check in an earlier
  transaction would be a TOCTOU window instead.

  ``count(*) = 1`` rather than ``EXISTS``, to keep the module's
  one-shape-per-read convention and because the caller wants a boolean, not a
  row.
  """
  cursor = await conn.execute(_IS_ACTIVE_USER_SQL, {"id": str(user_id)})
  row = await cursor.fetchone()
  return bool(row is not None and int(str(row[0])) == 1)


async def list_active_users(conn: PoolConnection) -> tuple[UserOptionRow, ...]:
  """List every enabled account as an id and a display name.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's short ``READ COMMITTED`` transaction.
    The read is on the detail page's path, not inside a mutation.

  Returns
  -------
  tuple[UserOptionRow, ...]
    Ordered by ``display_name`` then ``id``. Empty is possible in principle
    and renders an empty control; it cannot happen in practice, because the
    administrator making the request is themselves an active account.

  Notes
  -----
  Amendment **A-10**: ``contacts/detail.html``'s frozen
  ``reassign.assignable_users`` has no other source, and the template is
  rendered under ``StrictUndefined``. Two columns and no more — an account's
  address, role and flags are not needed to pick an owner, and a read that
  returned them would widen what a reassignment control discloses.

  No ``Scope``, for the same reason as :func:`is_active_user`; the **route**
  is admin-only, and that decision is taken before this is ever reached.
  """
  cursor = await conn.execute(_LIST_ACTIVE_USERS_SQL)
  rows = await cursor.fetchall()
  return tuple(UserOptionRow(id=UUID(str(row[0])), display_name=str(row[1])) for row in rows)
