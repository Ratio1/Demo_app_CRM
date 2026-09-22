"""``audit_events`` — one INSERT, and deliberately nothing else.

``S7``: the runtime role holds ``INSERT`` and ``SELECT`` on this table and no
``UPDATE``, ``DELETE`` or ``TRUNCATE`` (migration step 20). There is no
update statement in this module because there is no privilege behind one and
no operation that would want it — an audit row is written once and never
revised.

The single most important property here is the one the signature carries:
:func:`insert_event` runs **in the caller's transaction**. It is what makes
the audit row atomic with the mutation it describes, so a rolled-back login
leaves neither a session row nor a claim that a login happened (``SQL-016``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, LiteralString

if TYPE_CHECKING:
  from datetime import datetime
  from uuid import UUID

  from app.db.pool import PoolConnection

__all__ = ["insert_event"]

_INSERT_EVENT_SQL: Final[LiteralString] = """
INSERT INTO public.audit_events
  (id, at, actor_user_id, object_type, object_id, action, outcome, correlation_id)
VALUES
  (%(id)s, %(at)s, %(actor_user_id)s, %(object_type)s, %(object_id)s,
   %(action)s, %(outcome)s, %(correlation_id)s)
"""


async def insert_event(
  conn: PoolConnection,
  *,
  event_id: UUID,
  at: datetime,
  actor_id: UUID | None,
  object_type: str,
  object_id: UUID | None,
  action: str,
  outcome: str,
  correlation_id: str,
) -> None:
  """Append one audit row inside the caller's transaction.

  Parameters
  ----------
  conn : PoolConnection
    The connection the mutation being audited is running on. Never a fresh
    one: sharing the transaction is the control, not an optimisation.
  event_id : UUID
    The row's application-generated id (``A3``).
  at : datetime
    The caller's instant — the same one the mutation wrote.
  actor_id : UUID | None
    Who acted, or ``None`` on an anonymous path such as a failed login
    against an account that does not exist.
  object_type : str
    One of the seven values ``ck_audit_events_object_type`` admits.
  object_id : UUID | None
    The object acted on, or ``None`` where ``DATA_CONTRACT.md`` §3.6's
    emission map says so.
  action : str
    One of the 31 values ``ck_audit_events_action`` admits.
  outcome : str
    ``success``, ``failure`` or ``denied``.
  correlation_id : str
    The request's id — a canonical lowercase 36-character UUIDv4 string
    (**R33**), which ``ck_audit_events_correlation`` enforces exactly. It is
    the join between this row, the JSON log line and the error page.

  Notes
  -----
  Nothing is validated here. The database validates: a bad ``action``, a
  mismatched ``action``/``outcome`` pair, an over-long ``object_id`` or a
  ``correlation_id`` of the wrong length is rejected ``23514`` by
  ``ck_audit_events_action``, ``ck_audit_events_denied``,
  ``ck_audit_events_object_id`` or ``ck_audit_events_correlation``. A second
  copy of those lists in Python would be a second thing to keep in step, and
  a check that can be forgotten is not a check.
  """
  await conn.execute(
    _INSERT_EVENT_SQL,
    {
      "id": str(event_id),
      "at": at,
      "actor_user_id": None if actor_id is None else str(actor_id),
      "object_type": object_type,
      "object_id": None if object_id is None else str(object_id),
      "action": action,
      "outcome": outcome,
      "correlation_id": correlation_id,
    },
  )
