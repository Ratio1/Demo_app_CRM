"""The ``SERIALIZABLE`` transaction runner and its retry contract.

Spec §5: "Short ``SERIALIZABLE`` writes recheck authorization inside the
transaction. Retry the entire transaction on ``40001``/confirmed retryable
``40P01``: maximum five attempts, exponential backoff/jitter. […] never
blindly retry ambiguous commits."

Three properties carry that:

*Classification is by SQLSTATE string, never by exception class name.* The
psycopg class names were never independently confirmed (``DECISIONS.md`` §3),
and a class hierarchy is the library's business; the five-character SQLSTATE
is the server's contract and is identical on PostgreSQL and on a Cockroach-wire
database.

*The whole transaction is retried, not the failed statement.* A serialization
failure invalidates everything the transaction read, so ``fn`` re-reads under
the scope predicate and the version inside each new transaction. ``fn`` can run
up to ``attempts`` times and must therefore have no effect outside the
database.

*A commit whose outcome is unknown is never retried.* It raises
:class:`AmbiguousCommit`, which the service layer maps to a sanitized 503 and
resolves through the receipt table. Retrying it blindly is how a single
submission becomes two rows.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

import psycopg
from psycopg import sql

if TYPE_CHECKING:
  from app.db.pool import Pool, PoolConnection

__all__ = [
  "AMBIGUOUS_SQLSTATES",
  "AMBIGUOUS_SQLSTATE_CLASSES",
  "BACKOFF_BASE_S",
  "BACKOFF_CAP_S",
  "MAX_ATTEMPTS",
  "RETRYABLE_SQLSTATES",
  "AmbiguousCommit",
  "run_serializable",
]

MAX_ATTEMPTS: int = 5
BACKOFF_BASE_S: float = 0.025
BACKOFF_CAP_S: float = 1.0

#: ``40001`` serialization_failure and ``40P01`` deadlock_detected. Both are
#: reported by the server, which means the transaction is confirmed aborted and
#: nothing it wrote survives, so replaying it cannot duplicate an effect.
RETRYABLE_SQLSTATES: frozenset[str] = frozenset({"40001", "40P01"})

#: SQLSTATE *classes* whose appearance during ``COMMIT`` leaves the outcome
#: unknown. Class 08 is "connection exception": the link failed around the
#: commit and the server may or may not have written it.
AMBIGUOUS_SQLSTATE_CLASSES: frozenset[str] = frozenset({"08"})

#: Individual SQLSTATEs that mean the backend went away rather than that it
#: refused the commit: admin shutdown, crash shutdown, idle-session timeout.
AMBIGUOUS_SQLSTATES: frozenset[str] = frozenset({"57P01", "57P02", "57P05"})

_SET_SERIALIZABLE = sql.SQL("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")


class AmbiguousCommit(Exception):
  """Raised when a transaction failed with ``COMMIT`` already in flight.

  The database may or may not have applied the transaction, so it is neither
  retried nor reported as a failure. The caller resolves the real outcome from
  the mutation receipt and, until then, answers with a sanitized 503.

  The message carries the operation name and the attempt number only — never
  SQL text, parameters or record values — so it is safe to log verbatim.
  """


def _commit_outcome_unknown(sqlstate: str | None) -> bool:
  """Decide whether a failure raised during ``COMMIT`` leaves an unknown outcome.

  Parameters
  ----------
  sqlstate : str | None
    ``Error.sqlstate`` of the raised exception. ``None`` means the failure was
    raised by the client — a closed socket, a timeout — with no word from the
    server at all.

  Returns
  -------
  bool
    ``True`` when the transaction may or may not have been applied.

  Notes
  -----
  A SQLSTATE *is* a word from the server, so a commit that comes back with
  ``40001`` or a constraint violation is definitively aborted and is handled by
  the ordinary paths. What remains unknown is a client-side failure or a lost
  connection, and those are the cases enumerated here.

  The classification deliberately errs towards "unknown". Calling a failure
  ambiguous when the commit had in fact not been sent costs one sanitized 503
  and a receipt lookup; calling an ambiguous failure retryable can apply the
  same mutation twice.
  """
  if sqlstate is None:
    return True
  if sqlstate in RETRYABLE_SQLSTATES:
    return False
  return sqlstate[:2] in AMBIGUOUS_SQLSTATE_CLASSES or sqlstate in AMBIGUOUS_SQLSTATES


def _backoff_delay(attempt: int) -> float:
  """Return the full-jitter backoff delay before the next attempt.

  Parameters
  ----------
  attempt : int
    The 1-based number of the attempt that just failed.

  Returns
  -------
  float
    A delay drawn uniformly from ``[0, ceiling]`` where the ceiling doubles per
    attempt from :data:`BACKOFF_BASE_S` and is clamped at
    :data:`BACKOFF_CAP_S`.

  Notes
  -----
  Full jitter — a uniform draw from zero to the ceiling rather than the ceiling
  itself — is what stops a set of conflicting transactions from retrying in
  lockstep and colliding again at the same instant.
  """
  ceiling = min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2 ** (attempt - 1))
  # S311: this picks a retry delay, not a secret. A CSPRNG would add cost and
  # entropy-pool pressure to the hot path for no security property.
  return random.uniform(0.0, ceiling)  # noqa: S311


async def run_serializable[T](
  pool: Pool,
  fn: Callable[[PoolConnection], Awaitable[T]],
  *,
  op: str,
  attempts: int = MAX_ATTEMPTS,
) -> T:
  """Run ``fn`` inside a ``SERIALIZABLE`` transaction, retrying the whole of it.

  Parameters
  ----------
  pool : Pool
    The process pool. A connection is acquired per attempt, so a connection
    broken by the failure is never reused for the retry.
  fn : Callable[[PoolConnection], Awaitable[T]]
    The transaction body. It receives a connection already inside an open
    ``SERIALIZABLE`` transaction and must re-read every row it depends on —
    the scope predicate and the version — inside that transaction. It may run
    up to ``attempts`` times and must have no effect outside the database: no
    email, no file, no counter in process memory.
  op : str
    Operation name for the audit and correlation record. It never influences
    control flow.
  attempts : int, optional
    Maximum number of attempts, at least one. Defaults to
    :data:`MAX_ATTEMPTS`.

  Returns
  -------
  T
    Whatever ``fn`` returned on the attempt that committed.

  Raises
  ------
  ValueError
    If ``attempts`` is below one.
  AmbiguousCommit
    If an attempt failed with ``COMMIT`` in flight and an unknown outcome.
  psycopg.Error
    The last retryable error, once ``attempts`` have been spent; or any
    non-retryable database error, immediately and unwrapped.

  Notes
  -----
  The isolation level is set with a plain ``SET TRANSACTION`` as the first
  statement of each transaction rather than by mutating the connection's
  isolation attribute. The statement is standard SQL, it applies to exactly
  this transaction, and it leaves no state on a connection that goes back to a
  shared pool.

  The commit window is tracked by a flag set as the very last statement inside
  the transaction block and cleared as the very first statement after it, so
  only a failure raised by the block's own exit — which is where ``COMMIT`` is
  sent — can be classified as ambiguous.
  """
  if attempts < 1:
    raise ValueError("attempts must be at least 1")

  for attempt in range(1, attempts + 1):
    committing = False
    try:
      async with pool.connection() as conn:
        async with conn.transaction():
          await conn.execute(_SET_SERIALIZABLE)
          result = await fn(conn)
          committing = True
        committing = False
      return result
    except psycopg.Error as error:
      sqlstate = error.sqlstate
      if committing and _commit_outcome_unknown(sqlstate):
        raise AmbiguousCommit(
          f"commit outcome unknown for op={op} on attempt {attempt} of {attempts}"
        ) from error
      if sqlstate not in RETRYABLE_SQLSTATES or attempt >= attempts:
        raise
      await asyncio.sleep(_backoff_delay(attempt))

  raise RuntimeError("unreachable: the retry loop always returns or raises")
