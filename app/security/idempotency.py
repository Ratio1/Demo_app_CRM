"""Receipts: one submission is one mutation, however many times it arrives.

Authority: ``contracts/slice-b.md`` §2(b) (this module's whole surface),
§1(b)/§1(c) (``app/db/repositories/receipts.py``'s two statements), §1(d)
(the statement order inside a Slice B mutation and the three arms a
duplicate can take), ``DATA_CONTRACT.md`` §3.8 (the table) and §6.4 (the
rollback-and-re-read recovery), spec §5 (*"user/operation-scoped
idempotency keys bind to payloads"*).

Four decisions carry the control, and each is here rather than in a
service so that five mutations cannot implement it five ways:

*The key is minted by the server, once per rendered form.* A client never
chooses one and never re-uses one: :func:`mint_key` is called while the
form is built, and the 409-stale recovery view mints a **fresh** one
(**PIN 3**) because re-posting the submitted key would meet the receipt
and answer 409 ``duplicate``, which explains nothing.

*The digest is injective.* :func:`payload_sha256` length-prefixes every
key and every value, so no value containing a delimiter can forge a
different field list into the same digest. That is what makes "same key,
different payload" (**R19**'s ``duplicate`` context) a decision about the
payload rather than about how it was spelled.

*The receipt is read inside the transaction that will write it.*
:func:`decide` runs as the first statement after ``SET TRANSACTION
ISOLATION LEVEL SERIALIZABLE`` and :func:`commit_receipt` runs **before**
the business write (``DATA_CONTRACT.md`` §6.2, *"so a duplicate can never
have a business write in flight"*).

*A duplicate is resolved by reading the receipt, never by writing again.*
Three arms converge on that one rule (§1(d)): a receipt that is already
committed is a **replay**; a concurrent submission usually loses to SSI
with ``40001``, which :func:`app.db.retry.run_serializable` retries
invisibly; and a ``23505`` on the receipt insert aborts its transaction
outright, so the replay read cannot ride it and
:func:`replay_after_conflict` opens a **fresh** one.

Nothing here is a secret. ``payload_sha256`` digests the caller's own
submitted values, so it is compared with ``==``: a constant-time compare
would protect nothing, and saying so out loud keeps a reviewer from
reading plain equality as an oversight.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal
from uuid import UUID

from app.db.repositories.receipts import insert_receipt, read_receipt

if TYPE_CHECKING:
  from collections.abc import Sequence
  from datetime import datetime

  from app.db.pool import PoolConnection
  from app.db.repositories.receipts import (
    Operation,
    ReceiptRow,
    ResultObjectType,
    ResultStatus,
  )
  from app.db.retry import AmbiguousCommit, TransactionRunner

__all__ = [
  "CANONICAL_UUID",
  "NOTICE_FOR_STATUS",
  "ReceiptDecision",
  "commit_receipt",
  "decide",
  "mint_key",
  "parse_canonical",
  "payload_sha256",
  "replay_after_conflict",
  "settle_ambiguous",
]

#: The canonical 36-character form, case-insensitive hex. ``uuid.UUID()``
#: also accepts braces, URNs and the dash-free form; ``ck_contacts_id`` and
#: ``ACCESS_MATRIX.md`` §4.5 rule 1 accept only this one, so the regex runs
#: **first** and the constructor second.
CANONICAL_UUID: Final = re.compile(r"\A[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")

#: ``mutation_receipts.result_status`` → the ``?notice=`` code a replay
#: re-emits (**R20**, ``CONTRACTS.md`` §8.5). The ``Location`` itself is
#: rebuilt by the **route** from ``(result_object_type, result_object_id)``
#: plus this code: there is no ``response_location`` column and none is
#: added (§1(b)), because a stored URL goes stale the moment a route is
#: renamed and a URL is free text in a table whose whole discipline is
#: identifiers only.
NOTICE_FOR_STATUS: Final[dict[str, str]] = {
  "created": "contact_created",
  "updated": "contact_saved",
  "archived": "contact_archived",
  "restored": "contact_restored",
  "reassigned": "owner_changed",
}


@dataclass(frozen=True, slots=True)
class ReceiptDecision:
  """What the receipt lookup says this submission is.

  Attributes
  ----------
  kind : {"replay", "duplicate", "execute"}
    ``replay`` — a receipt exists and its ``payload_sha256`` equals this
    submission's, so the stored outcome is returned and **nothing at all**
    is written, not even an audit row. ``duplicate`` — a receipt exists
    under the same key with a *different* payload, which is **R19**'s
    ``duplicate`` context at 409 (``SQL-028``). ``execute`` — no receipt,
    so the mutation runs.
  receipt : ReceiptRow | None
    The stored row for the first two kinds; ``None`` for ``execute``.
  """

  kind: Literal["replay", "duplicate", "execute"]
  receipt: ReceiptRow | None


def mint_key() -> UUID:
  """Return a fresh idempotency key for one rendered mutation form.

  Returns
  -------
  UUID
    A version-4 UUID. One per form: a page with N forms carries N keys
    (``CONTRACTS.md`` §8 rule 2), and the 409-stale recovery form gets a
    new one rather than the submitted one (**PIN 3**).
  """
  return uuid.uuid4()


def parse_canonical(value: str | None) -> UUID | None:
  """Return ``value`` as a UUID when it is the canonical 36-character form.

  Parameters
  ----------
  value : str | None
    A path segment or a submitted field. Attacker-controlled in every
    caller.

  Returns
  -------
  UUID | None
    ``None`` for absent, malformed, or any of the non-canonical spellings
    :class:`uuid.UUID` would otherwise accept — braces, a URN prefix, the
    dash-free form. The schema's id CHECKs admit exactly one spelling, so
    accepting more here would let two different strings name one row and
    would put free text into a deny row's ``object_id``.
  """
  if value is None or CANONICAL_UUID.match(value) is None:
    return None
  try:
    return UUID(value)
  # Unreachable behind the regex; kept so a future regex edit degrades to
  # "not canonical" rather than to a 500.
  except ValueError:  # pragma: no cover - defensive
    return None


def _chunk(value: str) -> bytes:
  """Return one length-prefixed piece of the digest's input.

  Parameters
  ----------
  value : str
    A key or a value.

  Returns
  -------
  bytes
    ``<byte length>:<utf-8 bytes>``. The length prefix is what makes the
    whole encoding **injective**: a plain ``k=v`` join lets a value
    containing the delimiter forge a different field list into the same
    digest, which would turn an edited resubmission into a silent replay.
  """
  encoded = value.encode()
  return str(len(encoded)).encode() + b":" + encoded


def payload_sha256(
  *,
  operation: str,
  target_id: UUID | None,
  version: int | None = None,
  fields: Sequence[tuple[str, str]] = (),
) -> str:
  """Digest one submission's meaning, in a fixed and injective order.

  Parameters
  ----------
  operation : str
    The ``mutation_receipts.operation`` value this submission belongs to.
  target_id : UUID | None
    The object being changed, or ``None`` on a create. Included so that the
    same key against a **different** contact is a 409 rather than a replay
    of the wrong record.
  version : int | None, optional
    The concurrency token the form carried, or ``None`` where the form has
    none. Included so a re-post at a different version is a 409; the one
    form that legitimately re-posts at a new version — **PIN 3**'s "Keep my
    changes" — carries a **fresh** key by construction, so it never meets
    its own receipt.
  fields : Sequence[tuple[str, str]], optional
    The operation's declared writable fields, already **normalized** — the
    same strings the statement will bind — in
    :data:`app.services.contacts.CONTACT_FIELDS` order (``owner_id`` alone
    for a reassign). Normalizing first makes a resubmission differing only
    in trailing whitespace a replay rather than a conflict.

  Returns
  -------
  str
    Lowercase hex SHA-256, 64 characters — ``ck_mutation_receipts_payload``.

  Notes
  -----
  ``csrf_token`` and ``idempotency_key`` are **excluded**, deliberately:
  the CSRF token rotates independently of the payload, so including it
  would turn every rotation into a spurious 409 ``duplicate``, and the key
  is the lookup, not the content.

  ``version`` is an explicit parameter rather than the caller's first
  ``fields`` pair — a refinement of §2(b)'s sketch, recorded in the build
  report — so that the contracted pair order ``op``, ``target``,
  ``version``, then the declared fields is enforced by this function and
  not by five call sites remembering it.
  """
  pairs: list[tuple[str, str]] = [
    ("op", operation),
    ("target", "" if target_id is None else str(target_id)),
    ("version", "" if version is None else str(version)),
    *fields,
  ]
  digest = hashlib.sha256()
  for key, value in pairs:
    digest.update(_chunk(key) + b"=" + _chunk(value))
  return digest.hexdigest()


async def decide(
  conn: PoolConnection,
  *,
  user_id: UUID,
  operation: Operation,
  key: UUID,
  digest: str,
) -> ReceiptDecision:
  """Look the receipt up, inside the caller's transaction.

  Parameters
  ----------
  conn : PoolConnection
    A connection already inside the caller's ``SERIALIZABLE`` transaction.
    This is step 1 of §1(d): it runs **before** the scope re-read and
    before any write, so a duplicate can never have a business write in
    flight.
  user_id : UUID
    The session's user — never a submitted value. One user's key can never
    replay another user's mutation.
  operation : Operation
    The operation the key is scoped to. One operation's key can never
    replay another operation's.
  key : UUID
    The submitted idempotency key, already parsed as canonical.
  digest : str
    :func:`payload_sha256` of this submission.

  Returns
  -------
  ReceiptDecision

  Notes
  -----
  The lookup binds all three columns of ``uq_mutation_receipts_key``, not
  two: a two-column ``(user_id, key)`` read is **not unique** and could
  return another operation's row. Binding the full tuple also makes this
  the *same* statement before the mutation and after a ``23505``, so the
  replay path and the first-look path cannot diverge.

  The digest is compared with ``==``. It is a digest of the caller's own
  payload, not a secret.
  """
  receipt = await read_receipt(conn, user_id=user_id, operation=operation, idempotency_key=key)
  if receipt is None:
    return ReceiptDecision(kind="execute", receipt=None)
  if receipt.payload_sha256 == digest:
    return ReceiptDecision(kind="replay", receipt=receipt)
  return ReceiptDecision(kind="duplicate", receipt=receipt)


async def commit_receipt(
  conn: PoolConnection,
  *,
  user_id: UUID,
  operation: Operation,
  key: UUID,
  digest: str,
  status: ResultStatus,
  object_type: ResultObjectType,
  object_id: UUID,
  now: datetime,
) -> None:
  """Write the receipt, **before** the business statement it describes.

  Parameters
  ----------
  conn : PoolConnection
    The connection the mutation is running on — the same transaction, so
    the receipt and the business row and the audit row commit together or
    not at all (``SQL-011``, ``SQL-013``).
  user_id : UUID
    The session's user.
  operation : Operation
    The operation being recorded.
  key : UUID
    The submitted idempotency key.
  digest : str
    :func:`payload_sha256` of this submission.
  status : ResultStatus
    What the mutation did, in ``ck_mutation_receipts_status``'s vocabulary.
  object_type : ResultObjectType
    The kind of object the outcome names.
  object_id : UUID
    The object the outcome names — for a create, the id generated **before**
    the transaction opened, so every retry records the same one.
  now : datetime
    The caller's instant; the schema bans server clocks.

  Notes
  -----
  Nothing is caught here. A ``23505`` means a concurrent submission won the
  race; it is **not** in :data:`app.db.retry.RETRYABLE_SQLSTATES`, so the
  whole transaction unwinds with no business write — ``DATA_CONTRACT.md``
  §6.4 step 1, for free — and the caller then performs steps 2 and 3 with
  :func:`replay_after_conflict`.

  The receipt id is generated per attempt rather than once, exactly as the
  audit row's is: only the attempt that commits leaves a row.
  """
  await insert_receipt(
    conn,
    receipt_id=uuid.uuid4(),
    user_id=user_id,
    operation=operation,
    idempotency_key=key,
    payload_sha256=digest,
    result_status=status,
    result_object_type=object_type,
    result_object_id=object_id,
    now=now,
  )


async def replay_after_conflict(
  runner: TransactionRunner,
  *,
  user_id: UUID,
  operation: Operation,
  key: UUID,
  digest: str,
) -> ReceiptDecision:
  """Re-read the receipt in a **fresh** transaction after a ``23505``.

  Parameters
  ----------
  runner : TransactionRunner
    The process runner (amendment **A-14**). A new acquisition, taken only
    after the conflicting transaction has ended and released its own
    connection (``DATA_CONTRACT.md`` §6.1).
  user_id : UUID
    The session's user.
  operation : Operation
    The operation the key is scoped to.
  key : UUID
    The submitted idempotency key.
  digest : str
    :func:`payload_sha256` of this submission.

  Returns
  -------
  ReceiptDecision
    ``replay`` when the winner stored the same payload, ``duplicate`` when
    it stored a different one. ``execute`` is a state this application does
    not produce — a receipt that provoked a ``23505`` a moment ago can only
    disappear through the 24-hour cleanup — and the caller re-raises the
    original error rather than running the mutation a second time.

  Notes
  -----
  The transaction **must** be a fresh one. A ``23505`` leaves its
  transaction aborted, so the very next statement on it fails ``25P02``
  (``in_failed_sql_transaction``) — measured, §1(g) probe 4. That is also
  why this is not the §6.5 savepoint idiom: there the recovery happens
  inside one transaction, here the whole transaction must die.
  """

  async def _read(conn: PoolConnection) -> ReceiptDecision:
    return await decide(conn, user_id=user_id, operation=operation, key=key, digest=digest)

  return await runner.read_committed(_read, op="receipt-replay")


async def settle_ambiguous(
  runner: TransactionRunner,
  error: AmbiguousCommit,
  *,
  user_id: UUID,
  operation: Operation,
  key: UUID,
  digest: str,
) -> ReceiptRow:
  """Resolve a commit whose outcome is unknown, through the receipt (**PIN C5**).

  Parameters
  ----------
  runner : TransactionRunner
    The process runner. The transaction that was committing is gone —
    whether it landed or not — so this opens a **fresh** one.
  error : AmbiguousCommit
    The original signal, re-raised unchanged when the receipt is absent.
  user_id : UUID
    The session's user; the same value the lost transaction would have
    written.
  operation : Operation
    The operation the key is scoped to.
  key : UUID
    The submitted idempotency key.
  digest : str
    :func:`payload_sha256` of this submission.

  Returns
  -------
  ReceiptRow
    The stored receipt, which proves the transaction **landed**: the
    caller rebuilds the ``303`` it would have answered, so an ambiguous
    commit that in fact succeeded is invisible to the user.

  Raises
  ------
  AmbiguousCommit
    The original error, unchanged, when the receipt is **absent** — the
    transaction did not land — and also when a receipt exists under this
    key carrying a *different* payload. That second case is not a
    duplicate submission: the key is ours and the digest is ours, so a row
    with another payload proves the row under this key was **not** written
    by the transaction that vanished, and we cannot claim it landed.
    ``main.py``'s shipped handler then renders the 503 whose ``CP-19``
    copy forbids resubmission and sends the user to the record.

  Notes
  -----
  This is the whole of ``SQL-013``'s resolution and it adds **no second
  lookup path**: it reuses :func:`replay_after_conflict`'s fresh
  ``READ COMMITTED`` read, which is the one **PIN C5** names.

  The transaction is never retried. Retrying a commit whose outcome is
  unknown is precisely how one submission becomes two rows, which is why
  :class:`app.db.retry.AmbiguousCommit` exists at all.
  """
  decision = await replay_after_conflict(
    runner, user_id=user_id, operation=operation, key=key, digest=digest
  )
  if decision.kind != "replay" or decision.receipt is None:
    raise error
  return decision.receipt
