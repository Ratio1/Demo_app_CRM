"""Slice C concurrency — SQL-012 (retry cap/backoff), SQL-013 (ambiguous commit), SQL-029.

Authority: ``ACCESS_MATRIX.md`` §7 (``SQL-012``, ``SQL-013``, ``SQL-010``,
``SQL-011``, ``SQL-028``, ``SQL-029``, ``ACC-219``, ``ACC-220``);
``contracts/slice-c.md`` §1(c) (**PIN C4**/**PIN C5**, the
``TransactionRunner`` seams), §1(e) (the canonical mutation, statement by
statement), §2(g) hooks 2-4 (the exact barrier ordering, the synthetic
cap/backoff harness, the commit-raising pool).

In-process, at the **service** layer, not through ``live_server``: forcing
an engine-raised ``40001`` with an attempt-aware barrier, or a commit that
raises after ``COMMIT`` may have been sent, needs code inside this same
process wrapping the real connection pool — a separate uvicorn subprocess
cannot give us that seam (``tests/concurrency/test_audit_atomicity.py``'s
module docstring makes the identical argument for ``SQL-016``). This
module therefore builds its own pool (``app.db.pool``, shipped) and its
own seed data (``app.db.repositories.contacts``/``deals``, shipped), then
drives ``app.services.deals.change_stage``/``update_deal`` (shipped) —
the real production code path minus the HTTP layer, which
``app/routes/deals.py`` has not shipped yet.

Every ``app.*`` import is deferred into the fixture or test body that
needs it (this repo's running convention while a lane is still landing
code), even though most of what this module needs has now shipped.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Any, cast

import pytest
from _pool_wrappers import CommitFailingPool, GatedPool, statement_matches

if TYPE_CHECKING:
  from uuid import UUID

  from app.db.pool import Pool
  from app.security.principal import Scope

pytestmark = pytest.mark.asyncio


def _fresh_clock() -> Any:
  """Return a `ManualClock` fixed at a known instant (deferred import, module docstring)."""
  from datetime import UTC, datetime

  from app.security.clock import ManualClock

  return ManualClock(start=datetime(2026, 9, 22, 12, 0, 0, tzinfo=UTC))


# ---------------------------------------------------------------------------
# Seeding: one fictional user, one active contact it owns, one deal under it —
# all at the repository layer, inside their own SERIALIZABLE transactions, so
# no receipt/audit bookkeeping from a create flow clutters what this module
# measures.
# ---------------------------------------------------------------------------


async def _seed_user_and_contact(tmp_path: Any) -> tuple[Scope, str]:
  """Provision one fictional agent (owner role) and return its `Scope` and email.

  Returns
  -------
  tuple[Scope, str]
    The agent's `Scope` (`is_admin=False`) and its fictional email, for
    log messages only — never asserted on for content.
  """
  from conftest import insert_test_user_row

  from app.security.principal import Scope

  clock = _fresh_clock()
  user_id = uuid.uuid4()
  email = f"deal-concurrency+{uuid.uuid4().hex[:10]}@example.test"
  insert_test_user_row(
    user_id=str(user_id),
    email=email,
    display_name="Deal Concurrency Agent",
    role="agent",
    password_hash="$argon2id$v=19$m=19456,t=2,p=1$" + "a" * 32,
    must_change_password=False,
    now=clock.now().isoformat(),
    log_path=tmp_path / "seed_user.log",
  )
  return Scope(actor_id=user_id, is_admin=False), email


async def _seed_contact(pool: Pool, scope: Scope) -> UUID:
  """Insert one active contact owned by `scope.actor_id`, return its id."""
  from app.db.repositories.contacts import ContactFields, insert_contact
  from app.db.retry import run_serializable

  contact_id = uuid.uuid4()
  now = _fresh_clock().now()
  fields = ContactFields(
    full_name="Concurrency Test Contact",
    full_name_lower="concurrency test contact",
    company="Acme Corp",
    company_lower="acme corp",
    email=f"contact+{uuid.uuid4().hex[:10]}@example.test",
    email_lower=f"contact+{uuid.uuid4().hex[:10]}@example.test",
    phone="+1 555 0301",
    kind="lead",
  )

  async def _work(conn: Any) -> None:
    await insert_contact(conn, scope, contact_id=contact_id, fields=fields, now=now)

  await run_serializable(pool, _work, op="seed-contact")
  return contact_id


async def _seed_deal(pool: Pool, scope: Scope, *, contact_id: UUID, title: str) -> UUID:
  """Insert one `new`-stage deal under `contact_id`, return its id."""
  from decimal import Decimal

  from app.db.repositories.deals import DealFields, insert_deal
  from app.db.retry import run_serializable

  deal_id = uuid.uuid4()
  now = _fresh_clock().now()
  fields = DealFields(
    title=title, title_lower=title.lower(), amount=Decimal("100.00"), close_date=None
  )

  async def _work(conn: Any) -> str:
    return await insert_deal(
      conn, scope, deal_id=deal_id, contact_id=contact_id, fields=fields, now=now
    )

  outcome = await run_serializable(pool, _work, op="seed-deal")
  assert outcome == "created", f"deal seeding failed: {outcome!r}"
  return deal_id


async def _read_deal_row(pool: Pool, scope: Scope, *, deal_id: UUID) -> Any:
  """Re-read one deal (fresh connection, fresh transaction) for post-hoc assertions."""
  from app.db.repositories.deals import get_deal
  from app.db.retry import run_read_committed

  async def _work(conn: Any) -> Any:
    return await get_deal(conn, scope, deal_id=deal_id)

  return await run_read_committed(pool, _work, op="verify-deal")


async def _count_receipts(pool: Pool, *, user_id: UUID, operation: str, deal_id: UUID) -> int:
  """Count `mutation_receipts` rows for one user/operation/object (fresh connection)."""
  async with pool.connection() as conn:
    cursor = await conn.execute(
      "SELECT count(*) FROM mutation_receipts "
      "WHERE user_id = %(user_id)s AND operation = %(operation)s "
      "AND result_object_id = %(object_id)s",
      {"user_id": str(user_id), "operation": operation, "object_id": str(deal_id)},
    )
    row = await cursor.fetchone()
    assert row is not None
    return int(row[0])


# ---------------------------------------------------------------------------
# SQL-012 part 1 — an engine-raised 40001 on the SAME deal row, attempt-aware
# barrier, retried to a commit within five attempts (§2(g) hook 2).
# ---------------------------------------------------------------------------


async def test_sql012_part1_engine_raised_40001_is_retried_to_a_commit(tmp_path: Any) -> None:
  """Two concurrent transactions racing on one row: the loser gets `40001`, retries, commits.

  This proves the **retry mechanism** (`SQL-012`), deliberately at the
  same level as `contracts/slice-c.md` §1(g) probe 8 rather than through
  `app.services.deals.change_stage`'s own business layer: probe 8's own
  harness re-reads the row's *current* version on every attempt before
  writing, and so does the `fn` below — each attempt calls
  `deals_repo.get_deal` then `deals_repo.change_stage_versioned` with
  **that attempt's own fresh read**, not a version fixed once outside the
  retry loop. That distinction is load-bearing: `change_stage`'s real
  `expected_version` is *the version the user's browser last saw*, fixed
  for the whole call — and after this exact race, T2's original
  submission genuinely **is** stale (proven separately by
  `test_sql010_stale_stage_change_returns_stale_not_a_silent_overwrite`
  above, which is `SQL-010`'s test, not this one). `SQL-012` is a
  narrower claim: that an engine-raised `40001` inside a transaction
  whose *own* body would otherwise succeed on retry is retried
  correctly, without ever applying twice or silently losing a write —
  which is exactly what probe 8 measured and what this test reproduces
  as a real, unmocked two-connection race.

  Ordering (§2(g) hook 2, §1(g) probe 3): T1's scope-read SELECT, T2's
  scope-read SELECT, **barrier**, T1's UPDATE + COMMIT, **barrier**, T2's
  UPDATE — raised as `40001` because Postgres detects, under
  `SERIALIZABLE`, that the row T2 read has since been changed by a
  transaction that has already committed (this holds regardless of
  whether T2's own `WHERE version = …` would still textually match; at
  `SERIALIZABLE` the engine raises rather than silently re-evaluating,
  unlike `READ COMMITTED`'s `EvalPlanQual`). The retry then re-reads
  (attempt 2, gated on `t1_committed` only for the FIRST attempt — an
  already-set `asyncio.Event` never blocks again, which is what makes
  this attempt-aware without extra bookkeeping) and its own UPDATE now
  matches the current row, so it commits.
  """
  from app.config import load_config
  from app.db.pool import close_pool, create_pool, open_pool
  from app.db.repositories import deals as deals_repo
  from app.db.retry import TransactionRunner

  scope, _email = await _seed_user_and_contact(tmp_path)
  config = load_config()
  pool = create_pool(config)
  await open_pool(pool)
  try:
    contact_id = await _seed_contact(pool, scope)
    deal_id = await _seed_deal(pool, scope, contact_id=contact_id, title="Barrier race deal")
    now = _fresh_clock().now()

    t1_selected = asyncio.Event()
    t2_selected = asyncio.Event()
    t1_committed = asyncio.Event()

    def _is_select_from_deals(text: str) -> bool:
      return statement_matches(text, "SELECT", "FROM public.deals")

    def _is_stage_update(text: str) -> bool:
      return statement_matches(text, "UPDATE public.deals", "SET")

    async def t1_before_execute(text: str) -> None:
      if _is_select_from_deals(text):
        t1_selected.set()
        await t2_selected.wait()

    def t1_on_committed() -> None:
      t1_committed.set()

    async def t2_before_execute(text: str) -> None:
      if _is_select_from_deals(text):
        t2_selected.set()
        await t1_selected.wait()
      elif _is_stage_update(text):
        # Attempt-aware by construction: on a retry this Event is already
        # set, so `.wait()` returns immediately — no second block, no
        # deadlock against a barrier this connection already passed.
        await t1_committed.wait()

    t1_pool = GatedPool(pool, before_execute=t1_before_execute, on_committed=t1_on_committed)
    t2_pool = GatedPool(pool, before_execute=t2_before_execute)

    # `GatedPool` duck-types a `Pool` (`connection()` proxying through to the
    # real pool) but is not, and must not become, a subclass of
    # `AsyncConnectionPool` — the cast opts `TransactionRunner`'s nominal
    # parameter type out for this test-only substitute, exactly here.
    t1_runner = TransactionRunner(cast("Pool", t1_pool))
    t2_runner = TransactionRunner(cast("Pool", t2_pool))

    def _blind_mover(*, to_stage: str) -> Any:
      """Build a transaction body that re-reads the CURRENT row and moves it, every attempt."""

      async def _work(conn: Any) -> Any:
        row = await deals_repo.get_deal(conn, scope, deal_id=deal_id)
        assert row is not None
        moved = await deals_repo.change_stage_versioned(
          conn,
          scope,
          deal_id=deal_id,
          expected_version=row.version,
          from_stage=row.stage,
          new_stage=to_stage,
          stage_changed_at=now,
          now=now,
        )
        assert moved is not None, "this harness's own fresh read must always match its own write"
        return moved

      return _work

    t1_task = asyncio.create_task(
      t1_runner.serializable(_blind_mover(to_stage="qualified"), op="test-sql-012-t1")
    )
    t2_task = asyncio.create_task(
      t2_runner.serializable(_blind_mover(to_stage="proposal"), op="test-sql-012-t2")
    )
    t1_row, t2_row = await asyncio.gather(t1_task, t2_task)

    assert t1_row.version == 2, f"T1 (winner) should commit cleanly at version 2: {t1_row!r}"
    assert t2_row.version == 3, (
      f"T2 (loser) should retry and commit on top, at version 3: {t2_row!r}"
    )

    final = await _read_deal_row(pool, scope, deal_id=deal_id)
    assert final is not None
    assert final.version == 3, (
      f"two accepted stage changes on one row should leave version=3, got {final.version}"
    )
    assert final.stage == "proposal", "the loser's (T2's) move is the one that lands LAST"
  finally:
    await close_pool(pool)


# ---------------------------------------------------------------------------
# SQL-012 parts 2-3 — the cap (five attempts, then the sanitized error) and
# the exact backoff schedule, through a SYNTHETIC failure and the injected
# sleep/jitter hooks. No database race: a race cannot be made to fail
# exactly five times (§2(g) hook 3).
# ---------------------------------------------------------------------------


async def test_sql012_part2_the_cap_is_five_attempts_then_retryexhausted() -> None:
  """A body that raises `40001` every time exhausts the budget at exactly five attempts."""
  import psycopg

  from app.db.retry import RetryExhausted, TransactionRunner

  attempts_run = 0

  async def _always_fails(conn: object) -> None:
    nonlocal attempts_run
    attempts_run += 1
    del conn
    raise psycopg.errors.SerializationFailure("synthetic 40001")

  async def _no_sleep(delay: float) -> None:
    del delay

  # `_UnusedPool` never opens a real connection (module docstring above);
  # the cast opts its structural stand-in out of `Pool`'s nominal check.
  runner = TransactionRunner(
    pool=cast("Pool", _UnusedPool()), sleep=_no_sleep, jitter=lambda ceiling: ceiling
  )

  with pytest.raises(RetryExhausted) as excinfo:
    await runner.serializable(_always_fails, op="test-sql-012-cap")

  assert attempts_run == 5, f"exactly five bodies should have run, got {attempts_run}"
  assert excinfo.value.attempts == 5
  assert excinfo.value.op == "test-sql-012-cap"
  assert excinfo.value.sqlstate == "40001"


async def test_sql012_part3_the_backoff_schedule_through_injected_hooks() -> None:
  """With `jitter = lambda ceiling: ceiling`, the four recorded delays are exactly the ceilings.

  `0.025, 0.05, 0.1, 0.2` over four sleeps of a five-attempt budget — the
  `1.0` s cap is never reached at this attempt count (`contracts/slice-c.md`
  §1(c)). No wall-clock wait anywhere: `sleep` records the delay and
  returns immediately.
  """
  import psycopg

  from app.db.retry import RetryExhausted, TransactionRunner

  delays: list[float] = []

  async def _always_fails(conn: object) -> None:
    del conn
    raise psycopg.errors.SerializationFailure("synthetic 40001")

  async def _recording_sleep(delay: float) -> None:
    delays.append(delay)

  runner = TransactionRunner(
    pool=cast("Pool", _UnusedPool()), sleep=_recording_sleep, jitter=lambda ceiling: ceiling
  )

  with pytest.raises(RetryExhausted):
    await runner.serializable(_always_fails, op="test-sql-012-backoff")

  assert delays == pytest.approx([0.025, 0.05, 0.1, 0.2]), delays


async def test_sql012_part3_default_jitter_stays_within_the_ceiling() -> None:
  """With the DEFAULT (production) jitter, every recorded delay is inside `[0, ceiling]`."""
  import psycopg

  from app.db.retry import RetryExhausted, TransactionRunner

  delays: list[float] = []

  async def _always_fails(conn: object) -> None:
    del conn
    raise psycopg.errors.SerializationFailure("synthetic 40001")

  async def _recording_sleep(delay: float) -> None:
    delays.append(delay)

  runner = TransactionRunner(pool=cast("Pool", _UnusedPool()), sleep=_recording_sleep)

  with pytest.raises(RetryExhausted):
    await runner.serializable(_always_fails, op="test-sql-012-backoff-default")

  ceilings = [0.025, 0.05, 0.1, 0.2]
  assert len(delays) == 4
  for delay, ceiling in zip(delays, ceilings, strict=True):
    assert 0.0 <= delay <= ceiling, f"delay {delay} outside [0, {ceiling}]"


class _UnusedPool:
  """A `Pool` stand-in for the synthetic-failure tests, which never actually acquire a connection.

  `TransactionRunner._run` calls `self._pool.connection()` unconditionally
  before invoking `fn` — but the synthetic body raises before touching
  `conn` at all in these tests, so the fake `connection()` context manager
  below is never truly exercised against a real socket; it exists only so
  `_run`'s `async with self._pool.connection() as conn:` has something
  awaitable to enter.
  """

  def connection(self, *args: object, **kwargs: object) -> _UnusedConnectionContext:
    """Return a fake, no-op async connection context manager."""
    del args, kwargs
    return _UnusedConnectionContext()


class _UnusedConnectionContext:
  """The async context manager `_UnusedPool.connection()` returns."""

  async def __aenter__(self) -> _FakeConnection:
    return _FakeConnection()

  async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
    del exc_type, exc, tb


class _FakeConnection:
  """A connection stand-in whose `.execute`/`.transaction()` are never actually reached.

  The synthetic body raises immediately, before `fn` calls anything on
  `conn` — but `TransactionRunner._run` still issues
  `await conn.execute(set_statement)` as the transaction's first
  statement, so this needs one working `execute` and one working
  `transaction()` context manager to reach the body at all.
  """

  async def execute(self, *args: object, **kwargs: object) -> None:
    del args, kwargs

  def transaction(self) -> _FakeTransaction:
    """Return a real-enough async context manager for `SET TRANSACTION ISOLATION LEVEL`."""
    return _FakeTransaction()


class _FakeTransaction:
  async def __aenter__(self) -> None:
    return None

  async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
    del exc_type, exc, tb


# ---------------------------------------------------------------------------
# SQL-013 — an ambiguous commit is never retried; it resolves through the
# receipt (§2(g) hook 4, PIN C5's two variants).
# ---------------------------------------------------------------------------


async def test_sql013_landed_ambiguous_commit_replays_instead_of_writing_twice(
  tmp_path: Any,
) -> None:
  """The row DID land; the fresh re-read finds the receipt and `change_stage` replays."""
  from app.config import load_config
  from app.db.pool import close_pool, create_pool, open_pool
  from app.db.retry import TransactionRunner
  from app.services.deals import Applied

  scope, _email = await _seed_user_and_contact(tmp_path)
  config = load_config()
  pool = create_pool(config)
  await open_pool(pool)
  try:
    contact_id = await _seed_contact(pool, scope)
    deal_id = await _seed_deal(pool, scope, contact_id=contact_id, title="Landed ambiguous deal")

    commit_failing_pool = CommitFailingPool(pool, land=True)
    runner = TransactionRunner(cast("Pool", commit_failing_pool))
    clock = _fresh_clock()
    key = uuid.uuid4()

    result = await change_stage_or_fail(
      runner, clock, scope, deal_id=deal_id, expected_version=1, to_stage="qualified", key=key
    )

    assert isinstance(result, Applied), f"a LANDED ambiguous commit should replay, got {result!r}"
    assert result.replayed is True
    assert result.deal_id == deal_id

    final = await _read_deal_row(pool, scope, deal_id=deal_id)
    assert final is not None
    assert final.stage == "qualified"
    assert final.version == 2, f"exactly one stage change should have landed, got v={final.version}"

    receipts = await _count_receipts(
      pool, user_id=scope.actor_id, operation="deal_stage_change", deal_id=deal_id
    )
    assert receipts == 1, "exactly one receipt — the settle path adds no second write"
  finally:
    await close_pool(pool)


async def test_sql013_not_landed_ambiguous_commit_answers_a_re_raised_ambiguouscommit(
  tmp_path: Any,
) -> None:
  """The row did NOT land; the fresh re-read finds no receipt, so the original error re-raises.

  `main.py`'s shipped handler maps this to the sanitized 503
  `ambiguous_commit` page whose copy forbids resubmission — this test
  stops at the service boundary and asserts the propagated exception and
  the unchanged row, which is what that handler would receive.
  """
  from app.config import load_config
  from app.db.pool import close_pool, create_pool, open_pool
  from app.db.retry import AmbiguousCommit, TransactionRunner

  scope, _email = await _seed_user_and_contact(tmp_path)
  config = load_config()
  pool = create_pool(config)
  await open_pool(pool)
  try:
    contact_id = await _seed_contact(pool, scope)
    deal_id = await _seed_deal(
      pool, scope, contact_id=contact_id, title="Not-landed ambiguous deal"
    )

    commit_failing_pool = CommitFailingPool(pool, land=False)
    runner = TransactionRunner(cast("Pool", commit_failing_pool))
    clock = _fresh_clock()
    key = uuid.uuid4()

    with pytest.raises(AmbiguousCommit):
      await change_stage_or_fail(
        runner, clock, scope, deal_id=deal_id, expected_version=1, to_stage="qualified", key=key
      )

    final = await _read_deal_row(pool, scope, deal_id=deal_id)
    assert final is not None
    assert final.stage == "new", "the rolled-back move must never be visible"
    assert final.version == 1, (
      f"a NOT-landed commit must leave version unchanged, got {final.version}"
    )

    receipts = await _count_receipts(
      pool, user_id=scope.actor_id, operation="deal_stage_change", deal_id=deal_id
    )
    assert receipts == 0, "no receipt for a transaction that never landed"
  finally:
    await close_pool(pool)


async def change_stage_or_fail(
  runner: Any,
  clock: Any,
  scope: Scope,
  *,
  deal_id: UUID,
  expected_version: int,
  to_stage: str,
  key: UUID,
) -> Any:
  """Thin pass-through to `app.services.deals.change_stage` (deferred import, module docstring)."""
  from app.services.deals import change_stage

  return await change_stage(
    runner,
    clock,
    scope,
    deal_id=deal_id,
    expected_version=expected_version,
    to_stage=to_stage,
    key=key,
    correlation_id=str(uuid.uuid4()),
  )


# ---------------------------------------------------------------------------
# SQL-010 / ACC-219 / ACC-220 — stale edit, same-stage 400, terminal 409 —
# driven directly at the service layer (no HTTP needed).
# ---------------------------------------------------------------------------


async def test_sql010_stale_stage_change_returns_stale_not_a_silent_overwrite(
  tmp_path: Any,
) -> None:
  """Two sessions read version 1; the second's `change_stage` sees `Stale`, never overwrites."""
  from app.config import load_config
  from app.db.pool import close_pool, create_pool, open_pool
  from app.db.retry import TransactionRunner
  from app.services.deals import Applied, Stale

  scope, _email = await _seed_user_and_contact(tmp_path)
  config = load_config()
  pool = create_pool(config)
  await open_pool(pool)
  try:
    contact_id = await _seed_contact(pool, scope)
    deal_id = await _seed_deal(pool, scope, contact_id=contact_id, title="Stale race deal")
    runner = TransactionRunner(pool)
    clock = _fresh_clock()

    first = await change_stage_or_fail(
      runner,
      clock,
      scope,
      deal_id=deal_id,
      expected_version=1,
      to_stage="qualified",
      key=uuid.uuid4(),
    )
    assert isinstance(first, Applied)

    second = await change_stage_or_fail(
      runner,
      clock,
      scope,
      deal_id=deal_id,
      expected_version=1,
      to_stage="proposal",
      key=uuid.uuid4(),
    )
    assert isinstance(second, Stale), f"a stale version should never silently overwrite: {second!r}"
    assert second.version == 2, "Stale carries the CURRENT version, for the keep-my-changes form"

    final = await _read_deal_row(pool, scope, deal_id=deal_id)
    assert final is not None
    assert final.stage == "qualified", "only the first (winning) move should be visible"
  finally:
    await close_pool(pool)


async def test_acc219_same_stage_move_returns_samestage_not_stage_terminal(
  tmp_path: Any,
) -> None:
  """Posting the CURRENT stage as `to_stage` is `SameStage` (400), never `StageTerminal`."""
  from app.config import load_config
  from app.db.pool import close_pool, create_pool, open_pool
  from app.db.retry import TransactionRunner
  from app.services.deals import SameStage

  scope, _email = await _seed_user_and_contact(tmp_path)
  config = load_config()
  pool = create_pool(config)
  await open_pool(pool)
  try:
    contact_id = await _seed_contact(pool, scope)
    deal_id = await _seed_deal(pool, scope, contact_id=contact_id, title="Same-stage deal")
    runner = TransactionRunner(pool)
    clock = _fresh_clock()

    result = await change_stage_or_fail(
      runner, clock, scope, deal_id=deal_id, expected_version=1, to_stage="new", key=uuid.uuid4()
    )
    assert isinstance(result, SameStage)

    final = await _read_deal_row(pool, scope, deal_id=deal_id)
    assert final is not None
    assert final.version == 1, "a same-stage no-op must write nothing, not even bump the version"
  finally:
    await close_pool(pool)


async def test_acc220_moving_out_of_a_terminal_stage_is_stageterminal(tmp_path: Any) -> None:
  """Once a deal is `won`, every further `change_stage` call answers `StageTerminal`."""
  from app.config import load_config
  from app.db.pool import close_pool, create_pool, open_pool
  from app.db.retry import TransactionRunner
  from app.services.deals import Applied, StageTerminal

  scope, _email = await _seed_user_and_contact(tmp_path)
  config = load_config()
  pool = create_pool(config)
  await open_pool(pool)
  try:
    contact_id = await _seed_contact(pool, scope)
    deal_id = await _seed_deal(pool, scope, contact_id=contact_id, title="Terminal deal")
    runner = TransactionRunner(pool)
    clock = _fresh_clock()

    won = await change_stage_or_fail(
      runner, clock, scope, deal_id=deal_id, expected_version=1, to_stage="won", key=uuid.uuid4()
    )
    assert isinstance(won, Applied)

    reopen = await change_stage_or_fail(
      runner,
      clock,
      scope,
      deal_id=deal_id,
      expected_version=2,
      to_stage="qualified",
      key=uuid.uuid4(),
    )
    assert isinstance(reopen, StageTerminal)
    assert reopen.stage_label == "Won"

    final = await _read_deal_row(pool, scope, deal_id=deal_id)
    assert final is not None
    assert final.stage == "won", "a terminal deal must never move again"
    assert final.version == 2
  finally:
    await close_pool(pool)


# ---------------------------------------------------------------------------
# SQL-029 — archived-parent race: the contact is archived between the form
# render and the submit.
# ---------------------------------------------------------------------------


async def test_sql029_archived_parent_race_answers_blocked_not_a_silent_write(
  tmp_path: Any,
) -> None:
  """A `change_stage` submitted after the parent was archived answers `Blocked`, never `Applied`."""
  from app.config import load_config
  from app.db.pool import close_pool, create_pool, open_pool
  from app.db.repositories.contacts import archive_contact as repo_archive_contact
  from app.db.retry import TransactionRunner, run_serializable
  from app.services.deals import Blocked

  scope, _email = await _seed_user_and_contact(tmp_path)
  config = load_config()
  pool = create_pool(config)
  await open_pool(pool)
  try:
    contact_id = await _seed_contact(pool, scope)
    deal_id = await _seed_deal(
      pool, scope, contact_id=contact_id, title="Archived-parent race deal"
    )
    clock = _fresh_clock()

    # Simulates "archived between form render and submit": the version the
    # about-to-submit request read is still 1, but the parent is archived
    # out from under it before `change_stage` ever runs.
    async def _archive(conn: Any) -> None:
      await repo_archive_contact(
        conn,
        scope,
        contact_id=contact_id,
        expected_version=1,
        archived_at=clock.now(),
        now=clock.now(),
      )

    await run_serializable(pool, _archive, op="seed-archive-race")

    runner = TransactionRunner(pool)
    result = await change_stage_or_fail(
      runner,
      clock,
      scope,
      deal_id=deal_id,
      expected_version=1,
      to_stage="qualified",
      key=uuid.uuid4(),
    )
    assert isinstance(result, Blocked), f"an archived-parent race must answer Blocked: {result!r}"
    assert result.contact_id == contact_id

    final = await _read_deal_row(pool, scope, deal_id=deal_id)
    assert final is not None
    assert final.stage == "new", "the blocked move must write nothing"
    assert final.version == 1
  finally:
    await close_pool(pool)
