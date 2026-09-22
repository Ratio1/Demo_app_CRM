"""``app_settings`` — the stored origin and the provisioning state.

Two keys, both written only by the maintenance CLI (``bootstrap``,
``set-origin``) and read on every non-health request through the five-second
origin cache. The runtime role holds ``SELECT`` alone on this table, which is
why :func:`upsert_setting` is reachable only from
``app/services/accounts.py`` under the owner role: the serving process could
not execute it if it tried (``DATA_CONTRACT.md`` §5.2, §3.7).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, LiteralString

import psycopg

if TYPE_CHECKING:
  from datetime import datetime
  from uuid import UUID

  from app.db.pool import PoolConnection

__all__ = ["read_setting", "upsert_setting"]

_READ_SETTING_SQL: Final[LiteralString] = """
SELECT value FROM public.app_settings WHERE key = %(key)s
"""

_UPDATE_SETTING_SQL: Final[LiteralString] = """
UPDATE public.app_settings
   SET value = %(value)s, updated_at = %(now)s, updated_by_user_id = %(updated_by_user_id)s
 WHERE key = %(key)s
"""

_INSERT_SETTING_SQL: Final[LiteralString] = """
INSERT INTO public.app_settings (key, value, updated_at, updated_by_user_id)
VALUES (%(key)s, %(value)s, %(now)s, %(updated_by_user_id)s)
"""

_UNIQUE_VIOLATION: Final = "23505"


async def read_setting(conn: PoolConnection, *, key: str) -> str | None:
  """Read one setting's value.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's transaction.
  key : str
    ``public_origin`` or ``provisioning_state``; ``ck_app_settings_key``
    admits nothing else.

  Returns
  -------
  str | None
    The stored value, or ``None`` when the row does not exist. For
    ``public_origin`` that ``None`` is what the middleware reads as
    *unprovisioned* and answers ``503`` to.
  """
  cursor = await conn.execute(_READ_SETTING_SQL, {"key": key})
  row = await cursor.fetchone()
  if row is None:
    return None
  value: str = row[0]
  return value


async def upsert_setting(
  conn: PoolConnection,
  *,
  key: str,
  value: str,
  now: datetime,
  updated_by_user_id: UUID | None,
) -> None:
  """Insert or update one setting — maintenance role only.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction.
  key : str
    ``public_origin`` or ``provisioning_state``.
  value : str
    The new value, 1..1000 characters (``ck_app_settings_value``).
  now : datetime
    The caller's instant, written to ``updated_at``.
  updated_by_user_id : UUID | None
    The acting user, or ``None`` when the CLI ran with no session behind it
    — which is every ``set-origin``.

  Notes
  -----
  The ``DATA_CONTRACT.md`` §6.5 idiom, and the reason it is UPDATE-first: the
  preceding ``UPDATE`` is what opens the transaction, so the nested
  ``conn.transaction()`` is a **savepoint** rather than a bare ``BEGIN``, and
  a ``23505`` raised by the race can be recovered from. The ``except`` sits
  **outside** the ``async with`` because psycopg issues ``ROLLBACK TO`` only
  when the exception leaves the block; catching it inside would ``RELEASE``
  against a connection the server has already put in the error state and
  raise ``25P02`` (verified, ``DATA_CONTRACT.md`` §1.2 probe 8).

  ``ON CONFLICT`` would be one statement and is banned: it is not portable to
  a CockroachDB-style target (§9.1).
  """
  params: dict[str, object] = {
    "key": key,
    "value": value,
    "now": now,
    "updated_by_user_id": None if updated_by_user_id is None else str(updated_by_user_id),
  }
  cursor = await conn.execute(_UPDATE_SETTING_SQL, params)
  if cursor.rowcount != 0:
    return

  inserted = True
  try:
    async with conn.transaction():
      await conn.execute(_INSERT_SETTING_SQL, params)
  except psycopg.Error as error:
    if error.sqlstate != _UNIQUE_VIOLATION:
      raise
    inserted = False
  if not inserted:
    await conn.execute(_UPDATE_SETTING_SQL, params)
