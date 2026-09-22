"""The one lazy connection pool this process owns.

Spec §5 pins the shape: "one lazy DB pool per process, zero minimum/four
maximum connections, a five-second acquisition timeout, bounded waiters, and
bounded query/connect/reconnection timeouts. All settings are code defaults,
not extra environment variables." Every value below is therefore a module
constant; nothing here reads the environment.

The pool is built with ``open=False`` and opened by the application lifespan,
so importing this module — or ``app.main`` — with all five variables absent
connects to nothing, which is what the Deploy gate asserts.

Connection parameters come from :meth:`app.config.Config.connect_kwargs` and
are handed to the pool through its ``kwargs`` argument, which psycopg passes
to :meth:`psycopg.AsyncConnection.connect` for every new connection. They are
*not* splatted into the pool constructor, whose own keywords are the sizing
ones. ``connect_timeout`` travels inside those kwargs; the pool only overrides
it when it is given an explicit per-call timeout, which this module never does.

``statement_timeout`` is applied per connection by :func:`configure_connection`
rather than through libpq ``options``, because ``options`` must stay the empty
string: anything else would reopen the back door that passing every parameter
explicitly closes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from psycopg import AsyncConnection, sql
from psycopg.rows import TupleRow
from psycopg_pool import AsyncConnectionPool

if TYPE_CHECKING:
  from app.config import Config

__all__ = [
  "IDLE_IN_TRANSACTION_SESSION_TIMEOUT_MS",
  "POOL_ACQUIRE_TIMEOUT_S",
  "POOL_MAX_IDLE_S",
  "POOL_MAX_LIFETIME_S",
  "POOL_MAX_SIZE",
  "POOL_MAX_WAITING",
  "POOL_MIN_SIZE",
  "POOL_NAME",
  "POOL_RECONNECT_TIMEOUT_S",
  "STATEMENT_TIMEOUT_MS",
  "Pool",
  "PoolConnection",
  "close_pool",
  "configure_connection",
  "create_pool",
  "open_pool",
]

POOL_MIN_SIZE: int = 0
POOL_MAX_SIZE: int = 4
POOL_ACQUIRE_TIMEOUT_S: float = 5.0
POOL_MAX_WAITING: int = 16
POOL_MAX_LIFETIME_S: float = 1800.0
POOL_MAX_IDLE_S: float = 300.0
POOL_RECONNECT_TIMEOUT_S: float = 30.0
STATEMENT_TIMEOUT_MS: int = 10_000

#: ``CONTRACTS.md`` §6 D3 / ruling **R4**. A transaction left open with no
#: statement running holds its row locks and, at ``SERIALIZABLE``, its
#: predicate locks against every concurrent writer. Fifteen seconds is well
#: above ``STATEMENT_TIMEOUT_MS`` — a slow statement is never mistaken for an
#: abandoned transaction — and well below anything a human would wait for.
IDLE_IN_TRANSACTION_SESSION_TIMEOUT_MS: int = 15_000

POOL_NAME: str = "demo-crm"

type PoolConnection = AsyncConnection[TupleRow]
type Pool = AsyncConnectionPool[PoolConnection]


async def configure_connection(conn: PoolConnection) -> None:
  """Bound every statement on a freshly created pooled connection.

  Parameters
  ----------
  conn : PoolConnection
    A connection the pool has just opened, before any caller sees it.

  Notes
  -----
  ``SET`` takes no bind parameters, so the value is composed with
  :class:`psycopg.sql.Literal` rather than passed as a query parameter.

  Two bounds are set, not one. ``statement_timeout`` bounds a *statement*;
  ``idle_in_transaction_session_timeout`` bounds a transaction that is open
  with nothing running — the state a cancelled request or a stalled client
  leaves behind, and the one that keeps holding locks (``R4``). Neither is a
  variable: both are code constants, and libpq ``options`` stays the empty
  string.

  The ``COMMIT`` is not optional. psycopg's pool inspects the transaction
  status after this hook and discards any connection left outside ``IDLE``;
  it also rolls a returned connection back, which would undo an uncommitted
  ``SET``. Committing here makes the setting last for the life of the session
  while leaving the connection idle, which is what the pool requires.
  """
  await conn.execute(
    sql.SQL("SET statement_timeout = {}").format(sql.Literal(STATEMENT_TIMEOUT_MS))
  )
  await conn.execute(
    sql.SQL("SET idle_in_transaction_session_timeout = {}").format(
      sql.Literal(IDLE_IN_TRANSACTION_SESSION_TIMEOUT_MS)
    )
  )
  await conn.commit()


def create_pool(config: Config) -> Pool:
  """Build the process-wide pool without opening it.

  Parameters
  ----------
  config : Config
    Configuration built from the five environment names.

  Returns
  -------
  Pool
    A closed pool. Call :func:`open_pool` from the application lifespan; with
    ``POOL_MIN_SIZE`` at zero no connection is attempted until the first
    caller asks for one.

  Notes
  -----
  ``max_waiting`` is explicit because psycopg treats ``0`` — its default — as
  *unbounded*: the guard reads ``elif self.max_waiting and len(self._waiting)
  >= self.max_waiting``, so a falsy value disables the check entirely. An
  unbounded queue in front of four connections is an unbounded memory
  commitment under load, which the container profile cannot afford.
  """
  # `connect_kwargs` is typed `dict[str, object]` by the frozen contract in
  # app/config.py; psycopg types the same mapping as connection parameters.
  connect_kwargs = cast("dict[str, Any]", config.connect_kwargs())
  return AsyncConnectionPool(
    kwargs=connect_kwargs,
    connection_class=AsyncConnection[TupleRow],
    min_size=POOL_MIN_SIZE,
    max_size=POOL_MAX_SIZE,
    open=False,
    configure=configure_connection,
    name=POOL_NAME,
    timeout=POOL_ACQUIRE_TIMEOUT_S,
    max_waiting=POOL_MAX_WAITING,
    max_lifetime=POOL_MAX_LIFETIME_S,
    max_idle=POOL_MAX_IDLE_S,
    reconnect_timeout=POOL_RECONNECT_TIMEOUT_S,
  )


async def open_pool(pool: Pool) -> None:
  """Open the pool without waiting for a connection.

  Parameters
  ----------
  pool : Pool
    The pool returned by :func:`create_pool`.

  Notes
  -----
  ``wait=False`` keeps startup independent of the database: a server that is
  down at boot produces a sanitized failure on the first request instead of a
  container that never becomes live. ``/health/live`` checks the process only,
  and ``/health/ready`` is what reports the database.
  """
  await pool.open(wait=False)


async def close_pool(pool: Pool) -> None:
  """Close the pool and every connection it holds.

  Parameters
  ----------
  pool : Pool
    The pool to close. Closing twice is harmless.
  """
  await pool.close()
