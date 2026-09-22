"""Audit rows: identifiers only, and atomic with what they describe (``S7``).

Authority: ``slice-a.md`` §1.1, ``DATA_CONTRACT.md`` §3.6 (the closed
action and object-type vocabulary, and the ``outcome`` pinned per action),
§6.8 (which row writes which action).

Two rules carry the control:

*A business audit row rides the caller's transaction.* :func:`record` takes
the connection the mutation is already using, so the row commits with the
mutation or not at all — there is no window in which the change exists and
its record does not (``SQL-016``).

*A denial audit row does not.* :func:`record_denial` opens its own short
transaction **after** the denying transaction has ended, and swallows its
own failures: a denial is already decided, and failing to record it must
never turn a clean ``403`` into a ``503``.

Nothing written here is free text. The row carries an action from a closed
list, an object type, two identifiers and the correlation id that joins it
to the log line; the request's method and path live in that log line, not
here.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Final

import psycopg

from app.db.repositories.audit import insert_event
from app.db.retry import run_read_committed

if TYPE_CHECKING:
  from datetime import datetime
  from uuid import UUID

  from app.db.pool import Pool, PoolConnection

__all__ = [
  "ACTION_BUDGET_DENIED",
  "ACTION_FORCED_RESET_BLOCKED",
  "ACTION_LOGIN_FAILED",
  "ACTION_LOGIN_SUCCEEDED",
  "ACTION_LOGOUT",
  "ACTION_ORIGIN_SET",
  "ACTION_PASSWORD_CHANGED",
  "ACTION_PASSWORD_RESET",
  "ACTION_PROVISIONED",
  "ACTION_THROTTLE_LOCKED",
  "ACTION_USER_CREATED",
  "ACTION_USER_DISABLED",
  "OUTCOME_DENIED",
  "OUTCOME_FAILURE",
  "OUTCOME_SUCCESS",
  "record",
  "record_denial",
]

#: The Slice A subset of ``ck_audit_events_action``'s 31 values. Every one
#: is emitted by a named row of ``DATA_CONTRACT.md`` §6.8; nothing here is
#: admitted-but-unwritten.
ACTION_LOGIN_SUCCEEDED: Final = "login_succeeded"
ACTION_LOGIN_FAILED: Final = "login_failed"
ACTION_LOGOUT: Final = "logout"
ACTION_PASSWORD_CHANGED: Final = "password_changed"  # noqa: S105
ACTION_PASSWORD_RESET: Final = "password_reset"  # noqa: S105
ACTION_THROTTLE_LOCKED: Final = "throttle_locked"
ACTION_USER_CREATED: Final = "user_created"
ACTION_USER_DISABLED: Final = "user_disabled"
ACTION_ORIGIN_SET: Final = "origin_set"
ACTION_PROVISIONED: Final = "provisioned"
ACTION_FORCED_RESET_BLOCKED: Final = "forced_reset_blocked"
ACTION_BUDGET_DENIED: Final = "budget_denied"

OBJECT_USER: Final = "user"
OBJECT_SESSION: Final = "session"
OBJECT_SETTINGS: Final = "settings"
OBJECT_SYSTEM: Final = "system"

OUTCOME_SUCCESS: Final = "success"
OUTCOME_DENIED: Final = "denied"
OUTCOME_FAILURE: Final = "failure"


async def record(
  conn: PoolConnection,
  *,
  actor_id: UUID | None,
  object_type: str,
  object_id: UUID | None,
  action: str,
  outcome: str,
  correlation_id: str,
  at: datetime,
) -> None:
  """Write one audit row **inside the caller's transaction**.

  Parameters
  ----------
  conn : PoolConnection
    The connection the mutation is running on. Not a new one: that is the
    whole control.
  actor_id : UUID | None
    Who acted. ``None`` for an anonymous path — a failed login against an
    account that does not exist.
  object_type : str
    One of the seven values ``ck_audit_events_object_type`` admits.
  object_id : UUID | None
    The object acted on, or ``None`` where §3.6's emission map says so.
  action : str
    One of the 31 values ``ck_audit_events_action`` admits.
  outcome : str
    ``success``, ``failure`` or ``denied``. ``ck_audit_events_denied``
    makes the pairing an *iff*, so a mismatched pair is rejected by the
    database rather than silently stored.
  correlation_id : str
    The request's id, 36 characters (**R33**) — the join to the log line.
  at : datetime
    The instant, supplied by the caller's clock; the schema bans server
    clocks (``DATA_CONTRACT.md`` §2.3).

  Notes
  -----
  The event id is generated here rather than by the database: ids are
  application-generated throughout this schema (§2.2), which also lets a
  test pin one.
  """
  await insert_event(
    conn,
    event_id=uuid.uuid4(),
    at=at,
    actor_id=actor_id,
    object_type=object_type,
    object_id=object_id,
    action=action,
    outcome=outcome,
    correlation_id=correlation_id,
  )


async def record_denial(
  pool: Pool,
  *,
  actor_id: UUID | None,
  object_type: str,
  object_id: UUID | None,
  action: str,
  correlation_id: str,
  at: datetime,
) -> None:
  """Write one ``outcome='denied'`` row, best effort, in its own transaction.

  Parameters
  ----------
  pool : Pool
    The process pool. A fresh acquisition, taken only after the denying
    transaction has ended and released its own connection — a request
    holds at most one connection at a time (``DATA_CONTRACT.md`` §6.1).
  actor_id : UUID | None
    The authenticated actor. Pre-session denials never reach this function
    at all (§3.6): they are logged to stdout and nothing else.
  object_type : str
    The surface the request targeted.
  object_id : UUID | None
    The requested identifier when the application has already validated it
    as a canonical UUID, else ``None`` — a hostile 200-character path
    segment would violate ``ck_audit_events_object_id`` and the write would
    then fail on exactly the inputs this row exists to record.
  action : str
    One of the four denial actions row 25 carries.
  correlation_id : str
    The request's id.
  at : datetime
    The instant of the denial.

  Notes
  -----
  Every failure is swallowed after one log line naming the exception class.
  The alternative — letting it propagate — would turn a correct ``403``
  into a ``500`` and hand an attacker a way to make denials fail loudly.
  """
  try:

    async def _write(conn: PoolConnection) -> None:
      await record(
        conn,
        actor_id=actor_id,
        object_type=object_type,
        object_id=object_id,
        action=action,
        outcome=OUTCOME_DENIED,
        correlation_id=correlation_id,
        at=at,
      )

    await run_read_committed(pool, _write, op="record-denial")
  except (psycopg.Error, OSError) as error:  # pragma: no cover - defensive
    logging.getLogger("app").warning(
      "",
      extra={
        "crm_payload": {
          "event": f"audit-denial-failed:{type(error).__name__}",
          "correlation_id": correlation_id,
        }
      },
    )
