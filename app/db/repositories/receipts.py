"""``mutation_receipts`` — write-once idempotency, read before every mutation.

`contracts/slice-b.md` §1(b). Two statements: the lookup every mutation runs
before it writes anything, and the insert that records what it did. Nothing
here decides whether a submission is a replay, a duplicate or a first
execution — that is ``app/security/idempotency.py``'s ``decide``; this module
only reads and writes the row.

Three properties are load-bearing and all three live in the SQL:

*The lookup binds all three key columns.* ``PIN 1`` abbreviates the key as
``(user_id, key)``; ``DATA_CONTRACT.md`` §3.8 scopes a key to
``(user_id, operation)``. A two-column read is **not unique** — the same key
under a different operation is a different receipt — so it could replay
another operation's outcome and would not use ``uq_mutation_receipts_key``.
Binding the whole tuple also makes the read after a conflict the *same*
statement as the read before it.

*The insert catches nothing.* A duplicate raises ``23505``, which is not in
``RETRYABLE_SQLSTATES``, so ``run_serializable`` re-raises it unwrapped on the
first attempt and the whole transaction unwinds with no business write —
``DATA_CONTRACT.md`` §6.4 step 1, for free. The service then opens a **fresh**
transaction and re-reads, because the failed one can carry no further
statement (``25P02``).

*There is no ``response_location`` column.* §3.8 stores the outcome —
``result_status``, ``result_object_type``, ``result_object_id`` — and never a
URL: a stored URL would go stale the moment a route was renamed, and this
table's whole discipline is identifiers only. Replay rebuilds the ``Location``
from those three values through the same route-name function that built it the
first time.

This module takes **no** ``Scope`` (§1(b) B2): a receipt is keyed by the
session's ``user_id``, never by a request value, and it has no owner other
than that user, so a scope would add a second, redundant authorization input
to a lookup that is already identity-keyed. ``ARC-001``'s allowlist records it
alongside the identity repositories (ask **A-3**).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, LiteralString, cast
from uuid import UUID

if TYPE_CHECKING:
  from datetime import datetime

  from app.db.pool import PoolConnection

__all__ = [
  "Operation",
  "ReceiptRow",
  "ResultObjectType",
  "ResultStatus",
  "insert_receipt",
  "read_receipt",
]

#: The nine operations ``ck_mutation_receipts_operation`` admits. Slice B uses
#: the five ``contact_*`` values; the deal and activity names are already in
#: the CHECK so Slice C and Slice D add no migration to use them.
type Operation = Literal[
  "contact_create",
  "contact_update",
  "contact_archive",
  "contact_restore",
  "contact_reassign",
  "deal_create",
  "deal_update",
  "deal_stage_change",
  "activity_create",
]

#: The five outcomes ``ck_mutation_receipts_status`` admits. Note that there is
#: no ``stage_changed``: a Slice C stage change records ``updated`` or the
#: INSERT fails ``23514`` at runtime (§1(h) ask **A-5**).
type ResultStatus = Literal["created", "updated", "archived", "restored", "reassigned"]

#: What the recorded outcome points at.
type ResultObjectType = Literal["contact", "deal", "activity"]

_READ_RECEIPT_SQL: Final[LiteralString] = """
SELECT id, user_id, operation, idempotency_key, payload_sha256,
       result_status, result_object_type, result_object_id, created_at
  FROM public.mutation_receipts
 WHERE user_id = %(user_id)s
   AND operation = %(operation)s
   AND idempotency_key = %(idempotency_key)s
"""

_INSERT_RECEIPT_SQL: Final[LiteralString] = """
INSERT INTO public.mutation_receipts
  (id, user_id, operation, idempotency_key, payload_sha256,
   result_status, result_object_type, result_object_id, created_at)
VALUES
  (%(id)s, %(user_id)s, %(operation)s, %(idempotency_key)s, %(payload_sha256)s,
   %(result_status)s, %(result_object_type)s, %(result_object_id)s, %(now)s)
"""


@dataclass(frozen=True, slots=True)
class ReceiptRow:
  """One recorded mutation outcome.

  Attributes
  ----------
  id : UUID
    The row's application-generated id.
  user_id : UUID
    Whose submission. It comes from the session, never from the request, and
    it is the leading column of ``uq_mutation_receipts_key``.
  operation : str
    One of :data:`Operation`. Part of the key: one operation's key can never
    replay another operation's outcome.
  idempotency_key : UUID
    The key the rendered form carried.
  payload_sha256 : str
    The digest of the submitted payload. Equal digest means *replay*; a
    different digest under the same key means *duplicate* and answers 409.
  result_status : str
    One of :data:`ResultStatus` — what the first submission did.
  result_object_type : str
    One of :data:`ResultObjectType`.
  result_object_id : UUID
    Which record it did it to. The ``Location`` of a replay is rebuilt from
    this and ``result_object_type``, never stored.
  created_at : datetime
    When the receipt was written, from the caller's injected clock.
  """

  id: UUID
  user_id: UUID
  operation: str
  idempotency_key: UUID
  payload_sha256: str
  result_status: str
  result_object_type: str
  result_object_id: UUID
  created_at: datetime


def _row_to_receipt(row: tuple[object, ...]) -> ReceiptRow:
  """Build a :class:`ReceiptRow` from one row of the receipt SELECT.

  Parameters
  ----------
  row : tuple[object, ...]
    The tuple as psycopg returned it, in the order of the SELECT list.

  Returns
  -------
  ReceiptRow
    The row with its ``TEXT`` ids converted back to :class:`uuid.UUID`. This
    is the module's single conversion point in that direction
    (``DATA_CONTRACT.md`` §2.2).

  Notes
  -----
  The tuple is typed ``object`` rather than ``Any`` so that every column has
  to be converted deliberately; the one cast is the timestamp, which psycopg
  already hands back as a :class:`datetime.datetime` and which no conversion
  would improve.
  """
  return ReceiptRow(
    id=UUID(str(row[0])),
    user_id=UUID(str(row[1])),
    operation=str(row[2]),
    idempotency_key=UUID(str(row[3])),
    payload_sha256=str(row[4]),
    result_status=str(row[5]),
    result_object_type=str(row[6]),
    result_object_id=UUID(str(row[7])),
    created_at=cast("datetime", row[8]),
  )


async def read_receipt(
  conn: PoolConnection,
  *,
  user_id: UUID,
  operation: Operation,
  idempotency_key: UUID,
) -> ReceiptRow | None:
  """Look one receipt up by the whole of its unique key.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's transaction — the ``SERIALIZABLE`` one
    the mutation runs in, or the **fresh** ``READ COMMITTED`` one opened after
    a ``23505`` (§6.4).
  user_id : UUID
    From the session. Never a request value.
  operation : Operation
    Which mutation the key was minted for.
  idempotency_key : UUID
    The key the submitted form carried.

  Returns
  -------
  ReceiptRow | None
    ``None`` when this user has never submitted this key for this operation,
    which is the ordinary first-submission case.

  Notes
  -----
  The three bound columns are exactly ``uq_mutation_receipts_key``'s tuple, so
  this is an index lookup and it is the identical statement before the
  mutation and after a conflict.

  Under ``SERIALIZABLE`` a **miss** takes an SSI predicate lock on a range of
  that index rather than on a row that does not exist, which is why a
  concurrent duplicate surfaces as ``40001`` — handled invisibly by
  ``run_serializable`` — rather than as the ``23505`` the unique index would
  otherwise report (§1(d), measured). Tests must therefore assert the
  *outcome*, never a SQLSTATE.
  """
  cursor = await conn.execute(
    _READ_RECEIPT_SQL,
    {
      "user_id": str(user_id),
      "operation": operation,
      "idempotency_key": str(idempotency_key),
    },
  )
  row = await cursor.fetchone()
  return None if row is None else _row_to_receipt(row)


async def insert_receipt(
  conn: PoolConnection,
  *,
  receipt_id: UUID,
  user_id: UUID,
  operation: Operation,
  idempotency_key: UUID,
  payload_sha256: str,
  result_status: ResultStatus,
  result_object_type: ResultObjectType,
  result_object_id: UUID,
  now: datetime,
) -> None:
  """Record what one submission did, in the transaction that did it.

  Parameters
  ----------
  conn : PoolConnection
    A connection inside the caller's ``SERIALIZABLE`` transaction. The receipt
    and the business row commit together or not at all, which is what makes
    "exactly one receipt, one business row, one audit row" (``SQL-011``) a
    property of the schema rather than of the service's care.
  receipt_id : UUID
    The application-generated id (``A3``).
  user_id : UUID
    From the session.
  operation : Operation
    Which mutation this receipt records.
  idempotency_key : UUID
    The key the submitted form carried.
  payload_sha256 : str
    64 lowercase hex characters, digested over the **normalized** payload.
  result_status : ResultStatus
    What happened — the value a replay's ``?notice=`` code is derived from.
  result_object_type : ResultObjectType
    What kind of record the outcome points at.
  result_object_id : UUID
    Which record. A replay's ``Location`` is rebuilt from this pair.
  now : datetime
    The caller's instant, written to ``created_at``.

  Notes
  -----
  Nothing is caught here. A duplicate key raises ``23505``, and letting it
  propagate is the design: it is not retryable, so the whole transaction
  unwinds with no business write, and the service resolves the outcome by
  re-reading the receipt in a fresh transaction. Catching it in this module
  would put a decision in a layer whose contract is "no function decides
  anything".

  ``INSERT`` is issued **before** the business write (§6.2), so a duplicate can
  never have a business write in flight.
  """
  await conn.execute(
    _INSERT_RECEIPT_SQL,
    {
      "id": str(receipt_id),
      "user_id": str(user_id),
      "operation": operation,
      "idempotency_key": str(idempotency_key),
      "payload_sha256": payload_sha256,
      "result_status": result_status,
      "result_object_type": result_object_type,
      "result_object_id": str(result_object_id),
      "now": now,
    },
  )
