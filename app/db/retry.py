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

Slice C adds a fourth, and it is a *testability* property rather than a new
rule (``contracts/slice-c.md`` §1(c), ``PIN C4``): *the timing is injected.*
:class:`TransactionRunner` takes its ``sleep``, its ``jitter`` and its optional
``Clock`` through construction, so a test can observe the exact backoff
schedule with no wall-clock wait at all, and an exhausted budget raises
:class:`RetryExhausted` — carrying the attempt count as an **attribute**
rather than as a message to parse. The two module-level functions stay, build a
default runner and delegate, so the fourteen shipped call sites do not move.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

import psycopg
from psycopg import sql

if TYPE_CHECKING:
  from app.db.pool import Pool, PoolConnection
  from app.security.clock import Clock

__all__ = [
  "AMBIGUOUS_SQLSTATES",
  "AMBIGUOUS_SQLSTATE_CLASSES",
  "BACKOFF_BASE_S",
  "BACKOFF_CAP_S",
  "DEFAULT_POLICY",
  "MAX_ATTEMPTS",
  "RC_MAX_ATTEMPTS",
  "RETRYABLE_SQLSTATES",
  "AmbiguousCommit",
  "RetryExhausted",
  "RetryPolicy",
  "TransactionRunner",
  "run_read_committed",
  "run_serializable",
]

MAX_ATTEMPTS: int = 5
BACKOFF_BASE_S: float = 0.025
BACKOFF_CAP_S: float = 1.0

#: Attempt ceiling for the short ``READ COMMITTED`` transactions — session
#: reads, counter increments, the origin lookup. Lower than
#: :data:`MAX_ATTEMPTS` because none of them re-reads a business row under a
#: version guard: a serialization failure here is the portability hedge of
#: ``DATA_CONTRACT.md`` §6.1 (a Cockroach-wire target may promote
#: ``READ COMMITTED``), not the expected outcome it is for a business write.
RC_MAX_ATTEMPTS: int = 3

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
_SET_READ_COMMITTED = sql.SQL("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")

#: ``SERIALIZABLE, READ ONLY`` — the pipeline's snapshot (``PIN C6``,
#: ``contracts/slice-c.md`` §1(c)). ``READ ONLY`` is not decoration: a write
#: attempted inside such a transaction is refused by the **server** with
#: ``25006``, which makes "this transaction reads" a property of the
#: transaction rather than of the caller's good behaviour.
_SET_READ_ONLY_SERIALIZABLE = sql.SQL("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE, READ ONLY")


class AmbiguousCommit(Exception):
  """Raised when a transaction failed with ``COMMIT`` already in flight.

  The database may or may not have applied the transaction, so it is neither
  retried nor reported as a failure. The caller resolves the real outcome from
  the mutation receipt and, until then, answers with a sanitized 503.

  The message carries the operation name and the attempt number only — never
  SQL text, parameters or record values — so it is safe to log verbatim.

  Attributes
  ----------
  op : str | None
    The operation name the runner was given. ``None`` only when the exception
    was constructed by hand, which nothing in ``app/`` does.
  attempts : int | None
    The 1-based number of the attempt whose commit was in flight. The same two
    facts the message spells out, as attributes, so a caller never has to
    parse the message (``contracts/slice-c.md`` §1(c)).
  """

  def __init__(self, message: str, *, op: str | None = None, attempts: int | None = None) -> None:
    """Record the message and the two structured facts that go with it.

    Parameters
    ----------
    message : str
      The sanitized message, unchanged from the shipped wording.
    op : str | None, optional
      The operation name.
    attempts : int | None, optional
      The attempt the commit was in flight on.
    """
    super().__init__(message)
    self.op = op
    self.attempts = attempts


class RetryExhausted(Exception):
  """Every attempt of a retryable transaction failed. Nothing was committed.

  Raised ``from`` the last retryable :class:`psycopg.Error` once the attempt
  budget is spent, and **only** by :meth:`TransactionRunner.serializable` —
  see that method's notes for why the ``READ COMMITTED`` paths keep the bare
  re-raise.

  It is deliberately **not** a :class:`psycopg.Error` subclass: a caller that
  catches ``psycopg.Error`` today is catching *database* failures, and this is
  a *budget* failure. It is also the opposite of :class:`AmbiguousCommit` — a
  serialization failure reported by the server is a **confirmed** abort, so
  nothing was written and the honest answer is "try again", never "do not
  resubmit" (``contracts/slice-c.md`` §1(h) ask A-2, answered in §2(b) note 5:
  the 503 ``unavailable`` page).

  The message carries ``op`` and the attempt count only — no SQL text, no
  parameters, no record values — so it is safe to log verbatim. The count is
  an **attribute**, never a message to parse.

  Attributes
  ----------
  op : str
    The operation name the runner was given. It never influences control flow.
  attempts : int
    How many attempts ran. All of them failed.
  sqlstate : str | None
    The SQLSTATE of the last failure — ``40001`` or ``40P01``.
  elapsed_s : float | None
    Seconds from the first attempt to the last, read from the injected
    :class:`app.security.clock.Clock`. ``None`` when the runner was built
    without one, which is the module-level shims' case (``ARC-019`` forbids
    ``time.monotonic()`` outside ``app/security/clock.py``, and B3 forbids
    ``app/db/**`` from importing ``app/security/**`` at runtime, so a default
    runner cannot own a clock).
  """

  def __init__(
    self, *, op: str, attempts: int, sqlstate: str | None, elapsed_s: float | None
  ) -> None:
    """Record the operation, the spent budget and the last SQLSTATE.

    Parameters
    ----------
    op : str
      The operation name.
    attempts : int
      How many attempts ran.
    sqlstate : str | None
      The SQLSTATE of the last failure.
    elapsed_s : float | None
      Elapsed seconds, or ``None`` without a clock.
    """
    super().__init__(f"retry budget spent for op={op} after {attempts} attempt(s)")
    self.op = op
    self.attempts = attempts
    self.sqlstate = sqlstate
    self.elapsed_s = elapsed_s


@dataclass(frozen=True, slots=True)
class RetryPolicy:
  """The tuning a runner applies, as one value rather than three constants.

  Attributes
  ----------
  max_attempts : int
    The **``SERIALIZABLE``** attempt ceiling. It is deliberately not shared
    with the ``READ COMMITTED`` paths: one number for both would silently
    promote every counter transaction from :data:`RC_MAX_ATTEMPTS` to five.
  base_s : float
    The first attempt's backoff ceiling, doubling per attempt.
  cap_s : float
    The ceiling's clamp.
  """

  max_attempts: int = MAX_ATTEMPTS
  base_s: float = BACKOFF_BASE_S
  cap_s: float = BACKOFF_CAP_S


#: The policy every module-level shim and every runner built without one uses.
#: Built from the module constants, which keep their values and their exports,
#: so the shipped tuning is stated in exactly one place.
DEFAULT_POLICY: Final[RetryPolicy] = RetryPolicy()

#: The most times a backoff ceiling is doubled before the ``cap_s`` clamp.
#: Well past any sane attempt budget; it exists so the doubling cannot build a
#: gigantic integer on the way to a clamp that discards it.
_MAX_DOUBLINGS: Final[int] = 32


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


def _backoff_ceiling(attempt: int, policy: RetryPolicy) -> float:
  """Return the backoff ceiling for the attempt that just failed.

  Parameters
  ----------
  attempt : int
    The 1-based number of the attempt that just failed.
  policy : RetryPolicy
    The tuning in force.

  Returns
  -------
  float
    ``base_s`` doubled once per attempt and clamped at ``cap_s``: with the
    shipped values, ``0.025, 0.05, 0.1, 0.2`` over the four sleeps of a
    five-attempt budget — the 1 s cap is never reached.

  Notes
  -----
  Separating the ceiling from the draw is what makes the schedule assertable:
  a test injects ``jitter=lambda ceiling: ceiling`` and observes those four
  numbers exactly, while production keeps the full-jitter draw
  (``contracts/slice-c.md`` §1(c), ``SQL-012`` part 3).

  The doubling is a shift rather than ``2 ** n``, and the shift count is
  bounded by :data:`_MAX_DOUBLINGS`: the clamp against ``cap_s`` comes
  *after* the multiplication, so an absurd ``attempts`` would otherwise build
  a gigantic integer only to throw it away.
  """
  return min(policy.cap_s, policy.base_s * (1 << min(attempt - 1, _MAX_DOUBLINGS)))


def _full_jitter(ceiling: float) -> float:
  """Return a delay drawn uniformly from ``[0, ceiling]``.

  Parameters
  ----------
  ceiling : float
    The attempt's backoff ceiling, from :func:`_backoff_ceiling`.

  Returns
  -------
  float
    The delay to wait before the next attempt.

  Notes
  -----
  Full jitter — a uniform draw from zero to the ceiling rather than the ceiling
  itself — is what stops a set of conflicting transactions from retrying in
  lockstep and colliding again at the same instant. It is the default
  :class:`TransactionRunner` jitter; a test may replace it, and replacing it
  changes the *schedule*, never whether a failure is retryable.
  """
  # S311: this picks a retry delay, not a secret. A CSPRNG would add cost and
  # entropy-pool pressure to the hot path for no security property.
  return random.uniform(0.0, ceiling)  # noqa: S311


class TransactionRunner:
  """The ``SERIALIZABLE``/``READ COMMITTED`` wrapper, with its timing injected.

  One instance is built in the application lifespan with the application
  :class:`app.security.clock.Clock` and reaches the services through the
  request context (``contracts/slice-c.md`` §2(i) amendment A-14). The two
  module-level functions build a default instance per call and delegate, so
  every shipped call site keeps working unchanged.

  Notes
  -----
  Three seams, and each exists for one reason:

  ``sleep`` receives the **computed delay in seconds** and may return at once,
  so a test records the schedule without any wall-clock wait while production
  passes :func:`asyncio.sleep`. It is the hook ``PIN C4`` names.

  ``jitter`` receives the attempt's **ceiling** and returns a delay inside it.
  Without an injectable jitter the schedule could only ever be asserted as an
  interval.

  ``clock`` is **optional and is never control flow**: only ``monotonic()`` is
  read, and only to stamp elapsed time onto :class:`RetryExhausted` and the
  log line. It has to be optional because two standing rules make a mandatory
  one impossible — ``ARC-019`` forbids ``time.monotonic()`` outside
  ``app/security/clock.py``, and B3 forbids ``app/db/**`` from importing
  ``app/security/**`` at runtime — so a module-level default runner cannot own
  a clock (``contracts/slice-c.md`` §1(h) ask A-1).
  """

  def __init__(
    self,
    pool: Pool,
    *,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    jitter: Callable[[float], float] = _full_jitter,
    policy: RetryPolicy = DEFAULT_POLICY,
    clock: Clock | None = None,
  ) -> None:
    """Build a runner over one pool.

    Parameters
    ----------
    pool : Pool
      The process pool. A connection is acquired per attempt, so a connection
      broken by a failure is never reused for the retry.
    sleep : Callable[[float], Awaitable[None]], optional
      Awaited with the computed delay between attempts. Defaults to
      :func:`asyncio.sleep`.
    jitter : Callable[[float], float], optional
      Maps an attempt's ceiling to the delay actually waited. Defaults to
      :func:`_full_jitter`.
    policy : RetryPolicy, optional
      The attempt ceiling and the backoff shape. Defaults to
      :data:`DEFAULT_POLICY`.
    clock : Clock | None, optional
      Read only for :attr:`RetryExhausted.elapsed_s`. Defaults to ``None``.
    """
    self._pool = pool
    self._sleep = sleep
    self._jitter = jitter
    self._policy = policy
    self._clock = clock

  async def serializable[T](
    self,
    fn: Callable[[PoolConnection], Awaitable[T]],
    *,
    op: str,
    attempts: int | None = None,
  ) -> T:
    """Run ``fn`` inside a ``SERIALIZABLE`` transaction, retrying the whole of it.

    Parameters
    ----------
    fn : Callable[[PoolConnection], Awaitable[T]]
      The transaction body. See :func:`run_serializable`.
    op : str
      Operation name for the audit and correlation record.
    attempts : int | None, optional
      Maximum number of attempts. ``None`` resolves to the policy's
      ``max_attempts``.

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
    RetryExhausted
      Once the budget is spent. **Nothing was committed**: every failure that
      reaches it was reported by the server and is therefore a confirmed
      abort.
    psycopg.Error
      Any non-retryable database error, immediately and unwrapped.

    Notes
    -----
    This is the **only** method that wraps an exhausted budget. The
    ``READ COMMITTED`` paths keep the bare re-raise deliberately:
    ``app/security/audit.py``'s ``record_denial`` swallows
    ``(psycopg.Error, OSError)`` around its ``run_read_committed`` call so that
    a failed deny-audit never turns a 404 into a 503, and a new
    non-``psycopg.Error`` escaping that wrapper would walk straight past the
    ``except`` clause and turn exactly that 404 into a 500. The same shape
    guards ``session_store``'s touch and the throttle counters. On the
    ``SERIALIZABLE`` side there is no such catcher — ``app/services/contacts.py``
    catches ``psycopg.Error`` only to test for ``23505`` and re-raises
    everything else — so :class:`RetryExhausted` propagating past it is the
    intended path (``contracts/slice-c.md`` §1(c)).
    """
    return await self._run(
      fn,
      set_statement=_SET_SERIALIZABLE,
      op=op,
      attempts=self._policy.max_attempts if attempts is None else attempts,
      wrap_exhaustion=True,
    )

  async def read_committed[T](
    self,
    fn: Callable[[PoolConnection], Awaitable[T]],
    *,
    op: str,
    attempts: int | None = None,
  ) -> T:
    """Run ``fn`` inside a short ``READ COMMITTED`` transaction of its own.

    Parameters
    ----------
    fn : Callable[[PoolConnection], Awaitable[T]]
      The transaction body. See :func:`run_read_committed`.
    op : str
      Operation name for the correlation record.
    attempts : int | None, optional
      Maximum number of attempts. ``None`` resolves to
      :data:`RC_MAX_ATTEMPTS`, **not** to the policy's ``max_attempts``.

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
      The last retryable error once the budget is spent — **not**
      :class:`RetryExhausted`; or any non-retryable database error.
    """
    return await self._run(
      fn,
      set_statement=_SET_READ_COMMITTED,
      op=op,
      attempts=RC_MAX_ATTEMPTS if attempts is None else attempts,
      wrap_exhaustion=False,
    )

  async def read_only_serializable[T](
    self,
    fn: Callable[[PoolConnection], Awaitable[T]],
    *,
    op: str,
    attempts: int | None = None,
  ) -> T:
    """Run ``fn`` inside a ``SERIALIZABLE, READ ONLY`` transaction.

    Parameters
    ----------
    fn : Callable[[PoolConnection], Awaitable[T]]
      The transaction body. It may only read: a write is refused by the server
      with ``25006``.
    op : str
      Operation name for the correlation record.
    attempts : int | None, optional
      Maximum number of attempts. ``None`` resolves to
      :data:`RC_MAX_ATTEMPTS`, like :meth:`read_committed` — a read that
      cannot commit three times is not made right by two more tries.

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
      The last retryable error once the budget is spent, or any non-retryable
      database error.

    Notes
    -----
    The pipeline is this wrapper's first caller (``PIN C6``): a column's header
    count and € total come from one statement and its cards from another, the
    two are rendered side by side, and at ``READ COMMITTED`` a commit between
    them is *visible* as a column whose header disagrees with its cards. The
    deal **list** deliberately stays at ``READ COMMITTED`` with its documented
    one-row drift, because a total and a page are not read as a reconciliation.
    """
    return await self._run(
      fn,
      set_statement=_SET_READ_ONLY_SERIALIZABLE,
      op=op,
      attempts=RC_MAX_ATTEMPTS if attempts is None else attempts,
      wrap_exhaustion=False,
    )

  async def _run[T](
    self,
    fn: Callable[[PoolConnection], Awaitable[T]],
    *,
    set_statement: sql.SQL,
    op: str,
    attempts: int,
    wrap_exhaustion: bool,
  ) -> T:
    """Run one attempt loop. The single body all three methods share.

    Parameters
    ----------
    fn : Callable[[PoolConnection], Awaitable[T]]
      The transaction body.
    set_statement : sql.SQL
      The ``SET TRANSACTION ISOLATION LEVEL …`` statement, issued as the
      transaction's **first** statement — it must be first, or PostgreSQL
      raises ``25001``.
    op : str
      Operation name.
    attempts : int
      The already-resolved attempt ceiling.
    wrap_exhaustion : bool
      ``True`` to raise :class:`RetryExhausted` once the budget is spent,
      ``False`` to re-raise the last retryable :class:`psycopg.Error` bare.

    Returns
    -------
    T
      Whatever ``fn`` returned on the attempt that committed.

    Raises
    ------
    ValueError
      If ``attempts`` is below one.

    Notes
    -----
    The isolation level is set with a plain ``SET TRANSACTION`` rather than by
    mutating the connection's isolation attribute: the statement is standard
    SQL, it applies to exactly this transaction, and it leaves no state on a
    connection that goes back to a shared pool.

    The commit window is tracked by a flag set as the very last statement
    inside the transaction block and cleared as the very first statement after
    it, so only a failure raised by the block's own exit — which is where
    ``COMMIT`` is sent — can be classified as ambiguous.
    """
    if attempts < 1:
      raise ValueError("attempts must be at least 1")

    clock = self._clock
    started = None if clock is None else clock.monotonic()

    for attempt in range(1, attempts + 1):
      committing = False
      try:
        async with self._pool.connection() as conn:
          async with conn.transaction():
            await conn.execute(set_statement)
            result = await fn(conn)
            committing = True
          committing = False
        return result
      except psycopg.Error as error:
        sqlstate = error.sqlstate
        if committing and _commit_outcome_unknown(sqlstate):
          raise AmbiguousCommit(
            f"commit outcome unknown for op={op} on attempt {attempt} of {attempts}",
            op=op,
            attempts=attempt,
          ) from error
        if sqlstate not in RETRYABLE_SQLSTATES:
          raise
        if attempt >= attempts:
          if not wrap_exhaustion:
            raise
          elapsed_s = None if clock is None or started is None else clock.monotonic() - started
          raise RetryExhausted(
            op=op, attempts=attempt, sqlstate=sqlstate, elapsed_s=elapsed_s
          ) from error
        await self._sleep(self._jitter(_backoff_ceiling(attempt, self._policy)))

    raise RuntimeError("unreachable: the retry loop always returns or raises")


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
  RetryExhausted
    Once ``attempts`` have been spent. Nothing was committed.
  psycopg.Error
    Any non-retryable database error, immediately and unwrapped.

  Notes
  -----
  A thin shim over :meth:`TransactionRunner.serializable` on a runner built
  with the production defaults and **no clock** — see that class for why a
  module-level runner cannot own one. Same attempt ceiling, same SQLSTATE
  sets, same commit-window flag, same :class:`AmbiguousCommit`.

  The one behavioural delta against the Slice B shim is the exhausted budget:
  it now raises :class:`RetryExhausted` instead of re-raising the last
  ``psycopg.Error`` bare. That is the intended path — ``contracts/slice-c.md``
  §1(c) reasons it through ``app/services/contacts.py``'s
  ``except psycopg.Error`` clause, which tests for ``23505`` and re-raises
  everything else — and it is what makes ``SQL-012``'s cap assertable.
  """
  return await TransactionRunner(pool).serializable(fn, op=op, attempts=attempts)


async def run_read_committed[T](
  pool: Pool,
  fn: Callable[[PoolConnection], Awaitable[T]],
  *,
  op: str,
  attempts: int = RC_MAX_ATTEMPTS,
) -> T:
  """Run ``fn`` inside a short ``READ COMMITTED`` transaction of its own.

  Parameters
  ----------
  pool : Pool
    The process pool. A connection is acquired per attempt.
  fn : Callable[[PoolConnection], Awaitable[T]]
    The transaction body. It receives a connection already inside an open
    ``READ COMMITTED`` transaction. It may run up to ``attempts`` times and
    must have no effect outside the database.
  op : str
    Operation name for the correlation record. It never influences control
    flow.
  attempts : int, optional
    Maximum number of attempts, at least one. Defaults to
    :data:`RC_MAX_ATTEMPTS`.

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
  ``slice-a.md`` §10(c): the same body as :func:`run_serializable` with
  ``SET TRANSACTION ISOLATION LEVEL READ COMMITTED`` as the transaction's
  first statement. The level is set explicitly although it is PostgreSQL's
  default, because a CockroachDB-style target's default is not, and the
  ``40001``/``40P01`` wrapping is kept for the same reason: such an engine
  may promote this level and hand back a serialization failure the caller
  never asked for (``DATA_CONTRACT.md`` §6.1, §9.3 item 2).

  This is the wrapper the counter transactions use. ``register_failure`` and
  ``charge`` run here on their **own** acquisition so that the count survives
  the rollback of the auth path that provoked it (``SQL-027``) — which is a
  property of *where the caller opens this*, not of anything in this
  function.

  A thin shim over :meth:`TransactionRunner.read_committed`, and **behaviour
  is unchanged in every respect**, exhaustion included: the last retryable
  error is re-raised bare, because the three callers that swallow
  ``(psycopg.Error, OSError)`` around this function — the deny-audit, the
  session touch, the throttle counters — must keep swallowing it.
  """
  return await TransactionRunner(pool).read_committed(fn, op=op, attempts=attempts)
