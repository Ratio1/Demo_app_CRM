"""The login throttle and the four rate budgets.

Both counters commit in their **own** short ``READ COMMITTED``
transaction, so a refusal is recorded even when the request it refuses
rolls back.

Three properties worth stating plainly:

*The key is a hash, never an identifier.* ``account_key`` is
``sha256(submitted.strip().lower())`` — byte for byte the normalization
``users.email_norm`` uses, so a known account always keys to one row while
the address itself never reaches ``login_throttle``.

*Neither counter is keyed on a client address.* There is no IP, no
``X-Forwarded-For``, no header anywhere in this module: those are
attacker-chosen, and keying on them would make the throttle both evadable
and a denial weapon against a shared address.

*A refusal survives the rollback of what it refused.* Both counters commit
in their own transaction, so a failed login that rolls its own work back
cannot also erase the failure it just recorded.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final

from app.db.repositories.throttle import (
  charge,
  clear_throttle,
  read_throttle,
  register_failure,
)
from app.db.retry import run_read_committed
from app.security.sessions import sha256_hex

if TYPE_CHECKING:
  from app.db.pool import Pool, PoolConnection
  from app.security.clock import Clock

__all__ = [
  "ACCOUNT_MUTATION_LIMIT",
  "ACCOUNT_QUERY_LIMIT",
  "BUDGET_WINDOW",
  "GLOBAL_SUBJECT_KEY",
  "LOGIN_FAILURES",
  "LOGIN_GLOBAL_LIMIT",
  "LOGIN_LOCK",
  "LOGIN_WINDOW",
  "PREAUTH_GLOBAL_LIMIT",
  "BudgetDecision",
  "BudgetService",
  "ThrottleService",
  "ThrottleState",
  "account_key",
  "window_start_of",
]

LOGIN_FAILURES: Final = 5
LOGIN_WINDOW: Final = timedelta(minutes=15)
LOGIN_LOCK: Final = timedelta(minutes=15)

#: The global budget, 120 a minute, applied **per bucket** rather than
#: across both, so that exhausting the pre-auth page cannot also deny
#: ``POST /login``.
BUDGET_WINDOW: Final = timedelta(minutes=1)
PREAUTH_GLOBAL_LIMIT: Final = 120
LOGIN_GLOBAL_LIMIT: Final = 120

#: The per-account mutation and query budgets. The figures are chosen
#: here: a query ceiling equal to the global one, and a mutation ceiling
#: half of it, since every mutation costs a
#: ``SERIALIZABLE`` transaction and an audit row while a query does not.
#: Both are per authenticated user per minute; a human never approaches
#: either, and a runaway client is refused before it can matter.
ACCOUNT_QUERY_LIMIT: Final = 120
ACCOUNT_MUTATION_LIMIT: Final = 60

#: ``subject_key`` for the two global buckets.
GLOBAL_SUBJECT_KEY: Final = "*"

BUCKET_PREAUTH_GLOBAL: Final = "preauth_global"
BUCKET_LOGIN_GLOBAL: Final = "login_global"
BUCKET_ACCOUNT_QUERY: Final = "account_query"
BUCKET_ACCOUNT_MUTATION: Final = "account_mutation"

_BUCKET_LIMITS: Final[dict[str, int]] = {
  BUCKET_PREAUTH_GLOBAL: PREAUTH_GLOBAL_LIMIT,
  BUCKET_LOGIN_GLOBAL: LOGIN_GLOBAL_LIMIT,
  BUCKET_ACCOUNT_QUERY: ACCOUNT_QUERY_LIMIT,
  BUCKET_ACCOUNT_MUTATION: ACCOUNT_MUTATION_LIMIT,
}


def account_key(identifier: str) -> str:
  """Return the throttle key for a submitted login identifier.

  Parameters
  ----------
  identifier : str
    Exactly what the user typed into the email field.

  Returns
  -------
  str
    ``sha256(identifier.strip().lower())`` as 64 lowercase hex characters.

  Notes
  -----
  The normalization is byte for byte the one behind
  ``users.email_norm``, so ``" Ada@Example.test "`` and
  ``ada@example.test`` count against one row and capitalisation cannot
  multiply an attacker's budget by five.

  The hash is pseudonymisation, not secrecy: it is unsalted so that
  ``manage erase-subject`` can recompute a subject's key and delete their
  row. It still removes the plaintext address from a table that outlives
  the request.
  """
  return sha256_hex(identifier.strip().lower())


def window_start_of(now: datetime) -> datetime:
  """Floor ``now`` to the start of its one-minute budget window.

  Parameters
  ----------
  now : datetime
    A timezone-aware instant from the injected clock.

  Returns
  -------
  datetime
    The same instant with seconds and microseconds cleared, in UTC.

  Notes
  -----
  Floored in Python, never with ``date_trunc``:
  the window boundary must not depend on the engine's date functions or on
  the database's own clock, both of which differ on the portability target.
  """
  return now.astimezone(UTC).replace(second=0, microsecond=0)


@dataclass(frozen=True, slots=True)
class ThrottleState:
  """What the throttle says about one account key, right now.

  Attributes
  ----------
  locked : bool
    Whether the key is inside a lock window.
  retry_after_s : int
    Whole seconds until the lock lifts; ``0`` when not locked.
  """

  locked: bool
  retry_after_s: int


@dataclass(frozen=True, slots=True)
class BudgetDecision:
  """The outcome of charging one request against one bucket.

  Attributes
  ----------
  allowed : bool
    Whether the request may proceed.
  retry_after_s : int
    Whole seconds until this window rolls — at most the window length, so
    the advertised recovery matches the real one.
  transitioned : bool
    ``True`` on the single request whose increment crossed the limit. Only
    that one writes a ``budget_denied`` audit row, which is what keeps the
    deny trail bounded by the budget it records.
  """

  allowed: bool
  retry_after_s: int
  transitioned: bool


class ThrottleService:
  """Five failures per account per fifteen minutes, with a temporary lock."""

  def __init__(
    self,
    pool: Pool,
    clock: Clock,
    *,
    failures: int = LOGIN_FAILURES,
    window: timedelta = LOGIN_WINDOW,
    lock_for: timedelta = LOGIN_LOCK,
  ) -> None:
    """Build the service around the pool and the injected clock.

    Parameters
    ----------
    pool : Pool
      The process pool. Every method here opens its **own** short
      ``READ COMMITTED`` transaction on its own acquisition.
    clock : Clock
      Injected time source.
    failures : int, optional
      Failures inside one window before the lock engages.
    window : timedelta, optional
      How long failures accumulate.
    lock_for : timedelta, optional
      How long the lock lasts. A temporary backoff, never a permanent
      lockout: an attacker must not be able to lock a known account out of
      its own service indefinitely.
    """
    self._pool = pool
    self._clock = clock
    self._failures = failures
    self._window = window
    self._lock_for = lock_for

  @property
  def failures(self) -> int:
    """Failures inside one window before the lock engages."""
    return self._failures

  @property
  def window(self) -> timedelta:
    """How long failures accumulate."""
    return self._window

  @property
  def lock_for(self) -> timedelta:
    """How long a lock lasts once it engages."""
    return self._lock_for

  async def state(self, key: str, *, now: datetime) -> ThrottleState:
    """Return whether ``key`` is currently locked.

    Parameters
    ----------
    key : str
      An :func:`account_key` value.
    now : datetime
      The instant to compare the lock against.

    Returns
    -------
    ThrottleState
      The repository filters nothing by time; the comparison is made here,
      against the injected clock, so a test can drive it.
    """

    async def _read(conn: PoolConnection) -> ThrottleState:
      row = await read_throttle(conn, account_key=key)
      if row is None or row.locked_until is None or row.locked_until <= now:
        return ThrottleState(locked=False, retry_after_s=0)
      remaining = (row.locked_until - now).total_seconds()
      return ThrottleState(locked=True, retry_after_s=max(1, int(remaining) + 1))

    return await run_read_committed(self._pool, _read, op="read-login-throttle")

  async def register_failure(self, key: str, *, now: datetime) -> ThrottleState:
    """Count one failed attempt against ``key`` and report the new state.

    Parameters
    ----------
    key : str
      An :func:`account_key` value — for an unknown account too, so that
      the presence of a throttle row is not an account oracle
     .
    now : datetime
      The instant of the failure.

    Returns
    -------
    ThrottleState
      ``locked`` is ``True`` once this failure reached the threshold, so
      the *next* attempt is refused rather than this one.

    Notes
    -----
    Its own transaction, committed independently of the authentication
    path: a login that fails and rolls back must not also roll back the
    record of the failure.
    """
    window_cutoff = now - self._window
    locked_until = now + self._lock_for

    async def _count(conn: PoolConnection) -> ThrottleState:
      outcome = await register_failure(
        conn,
        account_key=key,
        now=now,
        window_cutoff=window_cutoff,
        threshold=self._failures,
        locked_until=locked_until,
      )
      if outcome.locked_until is None or outcome.locked_until <= now:
        return ThrottleState(locked=False, retry_after_s=0)
      remaining = (outcome.locked_until - now).total_seconds()
      return ThrottleState(locked=True, retry_after_s=max(1, int(remaining) + 1))

    return await run_read_committed(self._pool, _count, op="register-login-failure")

  async def clear(self, key: str, *, now: datetime) -> None:
    """Zero the counter for ``key`` after a successful authentication.

    Parameters
    ----------
    key : str
      An :func:`account_key` value.
    now : datetime
      The instant recorded as ``updated_at``.

    Notes
    -----
    An ``UPDATE``, never a ``DELETE``: the runtime role holds no ``DELETE``
    on ``login_throttle``, so a delete would
    fail with a privilege error on the happy path of the hottest route.
    """

    async def _clear(conn: PoolConnection) -> None:
      await clear_throttle(conn, account_key=key, now=now)

    await run_read_committed(self._pool, _clear, op="clear-login-throttle")


class BudgetService:
  """The four ``rate_budget`` counters, one minute-long window at a time."""

  def __init__(self, pool: Pool, clock: Clock) -> None:
    """Build the service around the pool and the injected clock.

    Parameters
    ----------
    pool : Pool
      The process pool; every charge is its own short transaction.
    clock : Clock
      Injected time source.
    """
    self._pool = pool
    self._clock = clock

  async def charge(self, bucket: str, subject_key: str, *, now: datetime) -> BudgetDecision:
    """Count one request against ``(bucket, subject_key)`` for this minute.

    Parameters
    ----------
    bucket : str
      One of the four bucket names; anything else is a programming error.
    subject_key : str
      ``'*'`` for a global bucket, the actor's user id for an account one.
    now : datetime
      The instant of the request.

    Returns
    -------
    BudgetDecision

    Raises
    ------
    KeyError
      If ``bucket`` is not one of the four. The set is closed by a CHECK in
      the database as well, so this only ever catches a typo in this
      repository.

    Notes
    -----
    Charged **before** the handler runs and, on the login path, **before**
    the Argon2 gate is entered, so a flood costs one indexed counter update
    rather than a 19 MiB hash arena.
    """
    limit = _BUCKET_LIMITS[bucket]
    window_start = window_start_of(now)
    retry_after_s = max(1, int((window_start + BUDGET_WINDOW - now).total_seconds()) + 1)

    async def _charge(conn: PoolConnection) -> BudgetDecision:
      outcome = await charge(
        conn,
        bucket=bucket,
        subject_key=subject_key,
        window_start=window_start,
        now=now,
        limit=limit,
      )
      return BudgetDecision(
        allowed=outcome.allowed,
        retry_after_s=retry_after_s,
        transitioned=outcome.transitioned,
      )

    return await run_read_committed(self._pool, _charge, op=f"charge-{bucket}")
