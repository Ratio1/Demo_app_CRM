"""Audit atomicity — SQL-016.

Authority: ``ACCESS_MATRIX.md`` §7 (SQL-016); ``DATA_CONTRACT.md`` §10
(SQL-016's mechanism: "Force a failure after the audit INSERT and before
COMMIT; assert zero rows for that ``correlation_id`` in both the business
table and ``audit_events``"); ``slice-a.md`` §10(b) (``insert_event``: "the
**caller's** transaction" — never its own).

In-process, not through ``live_server``: forcing a failure *inside* a
specific transaction requires code in this same process, which a separate
uvicorn subprocess cannot give us (``live_server`` runs a different
process's Python entirely). This module therefore builds its own pool
(``app.db.pool``, already shipped) and drives ``app.db.retry.run_serializable``
(already shipped) directly around ``promote_session`` and ``insert_event``
(``app.db.repositories.*``, not yet shipped) — the same generic mechanism
every Slice A mutation uses, rather than guessing at the not-yet-contracted
internal signature of ``app.services.auth.login``.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest

pytestmark = pytest.mark.asyncio


class _ForcedRollback(RuntimeError):
  """Raised deliberately, after the audit INSERT, to force the transaction to abort.

  Never a ``psycopg.Error``, so ``run_serializable`` does not retry it — it
  propagates once, which is exactly what this test needs.
  """


async def test_sql016_a_forced_failure_after_the_audit_insert_leaves_no_row_in_either_table(
  clock: Any, tmp_path: object
) -> None:
  """Both the session row and the audit row vanish together when the transaction aborts."""
  from app.db.repositories.audit import insert_event  # type: ignore[import-not-found]
  from app.db.repositories.sessions import (  # type: ignore[import-not-found]
    promote_session,
    read_live_session,
  )
  from app.security.sessions import ABSOLUTE_TTL, IDLE_TTL  # type: ignore[import-not-found]
  from conftest import insert_test_user_row

  from app.config import load_config
  from app.db.pool import close_pool, create_pool, open_pool
  from app.db.retry import run_serializable

  now = clock.now()
  correlation_id = str(uuid.uuid4())
  session_id = uuid.uuid4()
  user_id = str(uuid.uuid4())
  token_sha256 = "0" * 64
  csrf_sha256 = "1" * 64
  event_id = uuid.uuid4()

  insert_test_user_row(
    user_id=user_id,
    email=f"sql016+{uuid.uuid4().hex[:8]}@example.test",
    display_name="SQL-016 Test",
    role="agent",
    password_hash="$argon2id$v=19$m=19456,t=2,p=1$" + "a" * 32,
    must_change_password=False,
    now=now.isoformat(),
    log_path=tmp_path / "seed_user.log",  # type: ignore[operator]
  )

  config = load_config()
  pool = create_pool(config)
  await open_pool(pool)
  try:

    async def _mutate(conn: Any) -> None:
      await promote_session(
        conn,
        preauth_id=None,
        session_id=session_id,
        user_id=uuid.UUID(user_id),
        token_sha256=token_sha256,
        csrf_sha256=csrf_sha256,
        now=now,
        idle_expires_at=now + IDLE_TTL,
        absolute_expires_at=now + ABSOLUTE_TTL,
      )
      await insert_event(
        conn,
        event_id=event_id,
        at=now,
        actor_id=uuid.UUID(user_id),
        object_type="user",
        object_id=None,
        action="login_succeeded",
        outcome="success",
        correlation_id=correlation_id,
      )
      raise _ForcedRollback("deliberate failure after the audit INSERT, before COMMIT")

    with pytest.raises(_ForcedRollback):
      await run_serializable(pool, _mutate, op="test-sql-016")

    # A fresh connection/transaction, well after the aborted one, reads
    # what actually persisted.
    async with pool.connection() as verify_conn:
      session_row = await read_live_session(
        verify_conn, token_sha256=token_sha256, now=now + timedelta(seconds=1)
      )
      assert session_row is None, "the session row survived a rolled-back transaction"

      cursor = await verify_conn.execute(
        "SELECT count(*) FROM audit_events WHERE correlation_id = %(correlation_id)s",
        {"correlation_id": correlation_id},
      )
      row = await cursor.fetchone()
      assert row is not None and row[0] == 0, (
        "an audit row survived a rolled-back transaction — atomicity is broken"
      )
  finally:
    await close_pool(pool)


async def test_sql016_control_the_same_mutation_without_a_forced_failure_commits_both(
  clock: Any, tmp_path: object
) -> None:
  """Negative control: without a forced failure, both rows commit (proves the harness works)."""
  from app.db.repositories.audit import insert_event
  from app.db.repositories.sessions import (
    promote_session,
    read_live_session,
  )
  from app.security.sessions import ABSOLUTE_TTL, IDLE_TTL
  from conftest import insert_test_user_row

  from app.config import load_config
  from app.db.pool import close_pool, create_pool, open_pool
  from app.db.retry import run_serializable

  now = clock.now()
  correlation_id = str(uuid.uuid4())
  session_id = uuid.uuid4()
  user_id = str(uuid.uuid4())
  token_sha256 = "2" * 64
  csrf_sha256 = "3" * 64
  event_id = uuid.uuid4()

  insert_test_user_row(
    user_id=user_id,
    email=f"sql016-control+{uuid.uuid4().hex[:8]}@example.test",
    display_name="SQL-016 Control",
    role="agent",
    password_hash="$argon2id$v=19$m=19456,t=2,p=1$" + "a" * 32,
    must_change_password=False,
    now=now.isoformat(),
    log_path=tmp_path / "seed_user.log",  # type: ignore[operator]
  )

  config = load_config()
  pool = create_pool(config)
  await open_pool(pool)
  try:

    async def _mutate(conn: Any) -> None:
      await promote_session(
        conn,
        preauth_id=None,
        session_id=session_id,
        user_id=uuid.UUID(user_id),
        token_sha256=token_sha256,
        csrf_sha256=csrf_sha256,
        now=now,
        idle_expires_at=now + IDLE_TTL,
        absolute_expires_at=now + ABSOLUTE_TTL,
      )
      await insert_event(
        conn,
        event_id=event_id,
        at=now,
        actor_id=uuid.UUID(user_id),
        object_type="user",
        object_id=None,
        action="login_succeeded",
        outcome="success",
        correlation_id=correlation_id,
      )

    await run_serializable(pool, _mutate, op="test-sql-016-control")

    async with pool.connection() as verify_conn:
      session_row = await read_live_session(
        verify_conn, token_sha256=token_sha256, now=now + timedelta(seconds=1)
      )
      assert session_row is not None, "the control's session row did not commit"

      cursor = await verify_conn.execute(
        "SELECT count(*) FROM audit_events WHERE correlation_id = %(correlation_id)s",
        {"correlation_id": correlation_id},
      )
      row = await cursor.fetchone()
      assert row is not None and row[0] == 1, "the control's audit row did not commit"
  finally:
    await close_pool(pool)
