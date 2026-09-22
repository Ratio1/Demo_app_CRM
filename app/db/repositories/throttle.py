"""``login_throttle`` and ``rate_budget`` — the two counters, one module.

Folded together by amendment **A1**: both tables share one row shape, one
idiom (``DATA_CONTRACT.md`` §6.5) and one transaction class, and the Slice A
module list is five.

Everything here runs in a **short ``READ COMMITTED`` transaction of its
own**, on its own acquisition. That is ``SQL-027``: a failed login's rollback
must not undo the failure it recorded, so the counter cannot share the auth
path's transaction. The wrapper is the caller's
(:func:`app.db.retry.run_read_committed`); this module only assumes a
transaction is already open, which the §6.5 idiom's nested savepoint
requires.

Three rules the statements below never break: the increment is
``SET counter = counter + 1`` in a single UPDATE, so the row lock makes it
atomic with no ``SELECT … FOR UPDATE``; the post-increment value is read back
with a plain ``SELECT`` in the same transaction, never ``RETURNING``, because
that is the form ruling **R13** was pinned against; and every window boundary
and cutoff arrives as a bound parameter, computed in Python, never
``date_trunc`` and never interval arithmetic (§9.1).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, LiteralString

import psycopg

if TYPE_CHECKING:
  from datetime import datetime

  from app.db.pool import PoolConnection

__all__ = [
  "BudgetOutcome",
  "ThrottleOutcome",
  "ThrottleRow",
  "charge",
  "clear_throttle",
  "read_throttle",
  "register_failure",
]

_UNIQUE_VIOLATION: Final = "23505"

_READ_THROTTLE_SQL: Final[LiteralString] = """
SELECT account_key, failure_count, window_started_at, locked_until
  FROM public.login_throttle
 WHERE account_key = %(account_key)s
"""

#: One locked-row statement that both increments and rolls the window over.
#: At ``READ COMMITTED`` PostgreSQL re-evaluates the ``SET`` expressions
#: against the concurrently updated row version, so the increment cannot be
#: lost. The rollover also clears a stale lock — without that, a second lock
#: transition could never fire for the same key.
_COUNT_FAILURE_SQL: Final[LiteralString] = """
UPDATE public.login_throttle
   SET failure_count = CASE WHEN window_started_at < %(window_cutoff)s THEN 1
                            ELSE failure_count + 1 END,
       window_started_at = CASE WHEN window_started_at < %(window_cutoff)s THEN %(now)s
                                ELSE window_started_at END,
       locked_until = CASE WHEN window_started_at < %(window_cutoff)s THEN NULL
                           ELSE locked_until END,
       updated_at = %(now)s
 WHERE account_key = %(account_key)s
"""

_INSERT_FAILURE_SQL: Final[LiteralString] = """
INSERT INTO public.login_throttle
  (account_key, failure_count, window_started_at, locked_until, updated_at)
VALUES (%(account_key)s, 1, %(now)s, NULL, %(now)s)
"""

_READ_FAILURE_STATE_SQL: Final[LiteralString] = """
SELECT failure_count, locked_until
  FROM public.login_throttle
 WHERE account_key = %(account_key)s
"""

#: The transition, once and only once. The conditional UPDATE is the arbiter:
#: the row lock serializes the increments, so exactly one concurrent caller
#: can flip ``locked_until`` away from ``NULL`` and report ``transitioned``.
_LOCK_ACCOUNT_SQL: Final[LiteralString] = """
UPDATE public.login_throttle
   SET locked_until = %(locked_until)s, updated_at = %(now)s
 WHERE account_key = %(account_key)s AND locked_until IS NULL
"""

_CLEAR_THROTTLE_SQL: Final[LiteralString] = """
UPDATE public.login_throttle
   SET failure_count = 0, locked_until = NULL, updated_at = %(now)s
 WHERE account_key = %(account_key)s
"""

_CHARGE_SQL: Final[LiteralString] = """
UPDATE public.rate_budget
   SET counter = counter + 1, updated_at = %(now)s
 WHERE bucket = %(bucket)s
   AND subject_key = %(subject_key)s
   AND window_start = %(window_start)s
"""

_INSERT_BUDGET_SQL: Final[LiteralString] = """
INSERT INTO public.rate_budget (bucket, subject_key, window_start, counter, updated_at)
VALUES (%(bucket)s, %(subject_key)s, %(window_start)s, 1, %(now)s)
"""

_READ_BUDGET_SQL: Final[LiteralString] = """
SELECT counter FROM public.rate_budget
 WHERE bucket = %(bucket)s
   AND subject_key = %(subject_key)s
   AND window_start = %(window_start)s
"""


@dataclass(frozen=True, slots=True)
class ThrottleRow:
  """One account's login-failure counter.

  Attributes
  ----------
  account_key : str
    ``sha256(submitted.strip().lower())``, 64 lowercase hex characters —
    the identifier **hash**, never the address (ruling **R13**).
  failure_count : int
    Failures inside the current window.
  window_started_at : datetime
    When the current window opened.
  locked_until : datetime | None
    ``None`` means not locked. The caller compares it with its own instant;
    this module never judges whether a lock is still in force.
  """

  account_key: str
  failure_count: int
  window_started_at: datetime
  locked_until: datetime | None


@dataclass(frozen=True, slots=True)
class ThrottleOutcome:
  """What one counted failure did to the row.

  Attributes
  ----------
  failure_count : int
    The post-increment count.
  locked_until : datetime | None
    The lock instant now on the row, or ``None`` when it is not locked.
  transitioned : bool
    ``True`` for the one caller whose failure flipped the account into the
    locked state. It is what makes ``throttle_locked`` exactly one audit row
    per key per lock window (§3.6) rather than one per refused request.
  """

  failure_count: int
  locked_until: datetime | None
  transitioned: bool


@dataclass(frozen=True, slots=True)
class BudgetOutcome:
  """What one charge did to a budget window.

  Attributes
  ----------
  count : int
    The post-increment counter for this ``(bucket, subject_key,
    window_start)``.
  allowed : bool
    ``count <= limit``. The charge is recorded either way: a refused request
    still consumed the attempt.
  transitioned : bool
    ``count == limit + 1`` — the **first** refused request of this window,
    and the only one that writes a ``budget_denied`` row.
  """

  count: int
  allowed: bool
  transitioned: bool


async def read_throttle(conn: PoolConnection, *, account_key: str) -> ThrottleRow | None:
  """Read one account's throttle row without touching it.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's short ``READ COMMITTED`` transaction.
  account_key : str
    The 64-character hash.

  Returns
  -------
  ThrottleRow | None
    ``None`` when the account has no failures on record. No ``now``
    parameter (amendment **A6**): the repository decides nothing, and
    whether ``locked_until`` is still in the future is the caller's
    comparison against its own clock.
  """
  cursor = await conn.execute(_READ_THROTTLE_SQL, {"account_key": account_key})
  row = await cursor.fetchone()
  if row is None:
    return None
  return ThrottleRow(
    account_key=str(row[0]),
    failure_count=int(str(row[1])),
    window_started_at=row[2],
    locked_until=row[3],
  )


async def register_failure(
  conn: PoolConnection,
  *,
  account_key: str,
  now: datetime,
  window_cutoff: datetime,
  threshold: int,
  locked_until: datetime,
) -> ThrottleOutcome:
  """Count one failed login and report whether it locked the account.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside a short ``READ COMMITTED`` transaction of this
    counter's **own** — never the auth path's, whose rollback must not undo
    the count (``SQL-027``).
  account_key : str
    The 64-character hash. A row is written for an **unknown** account too:
    the alternative would make the presence of a throttle row an account
    oracle (§3.4).
  now : datetime
    The caller's instant.
  window_cutoff : datetime
    ``now - 15 min``, computed in Python (amendment **A6**). A window that
    started before it is rolled over rather than continued.
  threshold : int
    Five, by ``LOGIN_FAILURES``. Passed rather than read from a constant so
    that the statement stays a statement.
  locked_until : datetime
    ``now + 15 min``, computed in Python; written only on the transition.

  Returns
  -------
  ThrottleOutcome
    The post-increment count, the lock instant now on the row, and whether
    *this* call was the one that locked it.

  Notes
  -----
  Three statements, in one transaction, in this order.

  1. The ``CASE`` UPDATE increments or rolls the window over in one locked
     row. ``rowcount == 0`` means no row exists yet, which is the §6.5
     idiom's INSERT branch: a nested ``conn.transaction()`` — a **savepoint**,
     because the UPDATE already opened the transaction — with the ``except``
     **outside** the block, because catching ``23505`` inside would
     ``RELEASE`` against an errored connection and raise ``25P02``. On the
     race, one retry of the UPDATE.
  2. A plain ``SELECT`` reads the post-increment value back. No
     ``RETURNING``: the re-read is the form §3.6's once-per-transition rule
     was pinned against, and the row lock is what makes it exact.
  3. The conditional lock UPDATE runs only when the count has reached the
     threshold, and only matches while ``locked_until IS NULL``. Exactly one
     concurrent caller can match, so exactly one gets ``transitioned``.
  """
  params: dict[str, object] = {
    "account_key": account_key,
    "now": now,
    "window_cutoff": window_cutoff,
  }
  cursor = await conn.execute(_COUNT_FAILURE_SQL, params)
  if cursor.rowcount == 0:
    inserted = True
    try:
      async with conn.transaction():
        await conn.execute(_INSERT_FAILURE_SQL, params)
    except psycopg.Error as error:
      if error.sqlstate != _UNIQUE_VIOLATION:
        raise
      inserted = False
    if not inserted:
      await conn.execute(_COUNT_FAILURE_SQL, params)

  state = await conn.execute(_READ_FAILURE_STATE_SQL, {"account_key": account_key})
  row = await state.fetchone()
  if row is None:
    # The row was removed between the increment and the read back, which on
    # this table means `manage cleanup` ran in the gap. Nothing is locked and
    # nothing transitioned; reporting a fabricated count would be worse.
    return ThrottleOutcome(failure_count=0, locked_until=None, transitioned=False)

  failure_count = int(str(row[0]))
  current_lock: datetime | None = row[1]
  if failure_count < threshold:
    return ThrottleOutcome(
      failure_count=failure_count, locked_until=current_lock, transitioned=False
    )

  lock = await conn.execute(
    _LOCK_ACCOUNT_SQL,
    {"account_key": account_key, "now": now, "locked_until": locked_until},
  )
  transitioned = lock.rowcount == 1
  return ThrottleOutcome(
    failure_count=failure_count,
    locked_until=locked_until if transitioned else current_lock,
    transitioned=transitioned,
  )


async def clear_throttle(conn: PoolConnection, *, account_key: str, now: datetime) -> None:
  """Zero one account's counter after a successful login.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's short ``READ COMMITTED`` transaction,
    opened only **after** the login's rotation committed: a login that
    failed to rotate must not clear the counter that recorded why.
  account_key : str
    The 64-character hash.
  now : datetime
    Written to ``updated_at``.

  Notes
  -----
  An ``UPDATE``, never a ``DELETE``. The runtime role holds no ``DELETE`` on
  ``login_throttle`` (migration step 12) — expiry is maintenance's job — so a
  delete would fail with a privilege error on the happy path of the hottest
  route (§6.8 note 2). If no row exists, nothing is written and nothing is
  wrong: zero failures and no row mean the same thing, which is why the §6.5
  insert-or-update idiom is **not** used here.
  """
  await conn.execute(_CLEAR_THROTTLE_SQL, {"account_key": account_key, "now": now})


async def charge(
  conn: PoolConnection,
  *,
  bucket: str,
  subject_key: str,
  window_start: datetime,
  now: datetime,
  limit: int,
) -> BudgetOutcome:
  """Charge one request against a budget window and report the verdict.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside a short ``READ COMMITTED`` transaction of this
    counter's own.
  bucket : str
    One of the four ``ck_rate_budget_bucket`` admits.
  subject_key : str
    The literal ``'*'`` for a global bucket, the actor's id for an
    ``account_*`` one.
  window_start : datetime
    The window floored to the minute **in Python** (amendment **A7**), never
    ``date_trunc``: the boundary must not depend on the engine's date
    functions or on the database's clock.
  now : datetime
    Written to ``updated_at``.
  limit : int
    The ceiling for this bucket. Compared here so the caller gets one
    answer, not three numbers to reason about.

  Returns
  -------
  BudgetOutcome
    ``allowed`` is ``count <= limit``; ``transitioned`` is
    ``count == limit + 1``, the first refusal of this window and the only
    request that writes a ``budget_denied`` row.

  Notes
  -----
  ``retry_after_s`` is deliberately **not** returned (amendment **A7**):
  ``Retry-After`` is a presentation value the caller computes from the window
  it already holds, and a repository that returned it would be deciding part
  of the response.

  A new window is a new row — the primary key covers ``window_start`` — so
  at the top of each minute the UPDATE misses and the §6.5 idiom inserts with
  ``counter = 1``. That is the common path here, not the rare one, which is
  why the INSERT branch is written to survive a race rather than to be
  avoided.
  """
  params: dict[str, object] = {
    "bucket": bucket,
    "subject_key": subject_key,
    "window_start": window_start,
    "now": now,
  }
  cursor = await conn.execute(_CHARGE_SQL, params)
  if cursor.rowcount == 0:
    inserted = True
    try:
      async with conn.transaction():
        await conn.execute(_INSERT_BUDGET_SQL, params)
    except psycopg.Error as error:
      if error.sqlstate != _UNIQUE_VIOLATION:
        raise
      inserted = False
    if not inserted:
      await conn.execute(_CHARGE_SQL, params)

  read = await conn.execute(_READ_BUDGET_SQL, params)
  row = await read.fetchone()
  count = 0 if row is None else int(str(row[0]))
  return BudgetOutcome(
    count=count,
    allowed=count <= limit,
    transitioned=count == limit + 1,
  )
