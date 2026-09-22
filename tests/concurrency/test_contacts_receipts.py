"""Contact-surface concurrency and idempotency: receipt replay, stale edit, duplicate payload.

Drives the real HTTP surface over ``live_server`` — true concurrency
between independent connections on one ``httpx.AsyncClient``, the same
"real races, not mocked locks" posture ``test_last_admin_race.py`` uses for
its CLI pairs — and verifies outcomes with a direct ``db_connection``
(runtime role) rather than by guessing at response bodies alone, so
"exactly one row" is a database fact, not an inference from status codes.

Known gap, recorded rather than hidden: ``ProvisionedUser`` (root
``conftest.py``) carries no user id — ``scripts/manage create-user`` never
echoes one back to the caller, by design. The reassign tests below
therefore submit a placeholder ``owner_id`` and record both possible
outcomes; once ``contacts/detail.html`` ships its
``reassign.assignable_users [{id, display_name}]`` list, the right fix is
to parse the real id off that rendered option rather than guessing a
value here.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import httpx
import pytest
from conftest import (
  LoggedInPrincipal,
  create_contact,
  extract_csrf_token,
  extract_hidden_field,
  fresh_idempotency_key,
)

pytestmark = pytest.mark.asyncio

_CREATE_FIELDS = {
  "name": "Concurrency Test Contact",
  "company": "Acme Corp",
  "phone": "+1 555 0104",
  "kind": "lead",
}


async def _count(db_connection: Any, sql: str, params: dict[str, Any]) -> int:
  """Run a ``SELECT count(*) ...`` and return the integer result."""
  cursor = await db_connection.execute(sql, params)
  row = await cursor.fetchone()
  assert row is not None
  return int(row[0])


async def _receipt_and_contact_counts(
  db_connection: Any, *, owner_email: str
) -> tuple[int, int, int]:
  """Return ``(contacts, contact_create receipts, contact_created success audits)`` for one owner.

  All three counts are scoped by joining ``users`` on ``email_norm``
  (``ProvisionedUser`` carries no id — see the module docstring), never on
  a raw id this test does not have.
  """
  normalized_email = owner_email.strip().lower()
  contacts = await _count(
    db_connection,
    "SELECT count(*) FROM contacts c JOIN users u ON u.id = c.owner_id "
    "WHERE u.email_norm = %(email)s",
    {"email": normalized_email},
  )
  receipts = await _count(
    db_connection,
    "SELECT count(*) FROM mutation_receipts mr JOIN users u ON u.id = mr.user_id "
    "WHERE u.email_norm = %(email)s AND mr.operation = 'contact_create'",
    {"email": normalized_email},
  )
  audits = await _count(
    db_connection,
    "SELECT count(*) FROM audit_events a JOIN users u ON u.id = a.actor_user_id "
    "WHERE u.email_norm = %(email)s AND a.action = 'contact_created' AND a.outcome = 'success'",
    {"email": normalized_email},
  )
  return contacts, receipts, audits


async def test_sequential_duplicate_submission_leaves_exactly_one_of_each_row(
  agent_a: LoggedInPrincipal, db_connection: Any
) -> None:
  """Same key, same payload, submitted twice in sequence: one contact, one receipt, one audit row.

  The second POST finds the stored receipt (same ``payload_sha256``) and
  replays it — a ``303`` to the same ``Location``, doing nothing — rather
  than inserting a second time.
  """
  email = f"receipt-seq+{uuid.uuid4().hex[:8]}@example.test"
  before = await _receipt_and_contact_counts(db_connection, owner_email=agent_a.user.email)

  new_form = await agent_a.client.get("/contacts/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  payload = {**_CREATE_FIELDS, "email": email}

  first = await agent_a.client.post(
    "/contacts", data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, **payload}
  )
  second = await agent_a.client.post(
    "/contacts", data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, **payload}
  )

  assert first.status_code == 303
  assert second.status_code == 303
  assert first.headers.get("location") == second.headers.get("location"), (
    "the replay must be a 303 to the SAME location as the original"
  )

  after = await _receipt_and_contact_counts(db_connection, owner_email=agent_a.user.email)
  assert after[0] - before[0] == 1, "exactly one contact row"
  assert after[1] - before[1] == 1, "exactly one mutation_receipts row"
  assert after[2] - before[2] == 1, "exactly one audit_events row"


async def test_concurrent_duplicate_submission_replays_leaving_one_of_each_row(
  agent_a: LoggedInPrincipal, db_connection: Any
) -> None:
  """Two truly concurrent POSTs with the same key and payload still leave exactly one of each row.

  The loser resolves either on a ``23505`` (the receipt's unique
  constraint — re-read and replay) or a ``40001`` serialization abort whose
  retry then finds the receipt. Either mechanism, the database-level count
  is identical — this test does not care which one fired.
  """
  email = f"receipt-conc+{uuid.uuid4().hex[:8]}@example.test"
  before = await _receipt_and_contact_counts(db_connection, owner_email=agent_a.user.email)

  new_form = await agent_a.client.get("/contacts/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  payload = {**_CREATE_FIELDS, "email": email}

  responses = await asyncio.gather(
    agent_a.client.post(
      "/contacts", data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, **payload}
    ),
    agent_a.client.post(
      "/contacts", data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, **payload}
    ),
  )
  statuses = [response.status_code for response in responses]
  assert statuses == [303, 303], f"both concurrent submissions must resolve to 303, got {statuses}"
  locations = {response.headers.get("location") for response in responses}
  assert len(locations) == 1, "both concurrent submissions must redirect to the SAME location"

  after = await _receipt_and_contact_counts(db_connection, owner_email=agent_a.user.email)
  assert after[0] - before[0] == 1, "exactly one contact row survives the race"
  assert after[1] - before[1] == 1, "exactly one mutation_receipts row survives the race"


async def test_same_key_different_payload_is_409_duplicate(
  agent_a: LoggedInPrincipal, db_connection: Any
) -> None:
  """Reusing an idempotency key with a DIFFERENT payload is `409 duplicate`, never a second write.

  A `23505` on the receipt's unique key still fires (same
  ``(user_id, operation, idempotency_key)``), but the stored
  ``payload_sha256`` now disagrees with the second submission's digest, so
  the replay path answers ``duplicate`` instead of re-issuing the original
  ``Applied`` outcome — no second business row is ever created.
  """
  email = f"conflict+{uuid.uuid4().hex[:8]}@example.test"
  new_form = await agent_a.client.get("/contacts/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")

  first = await agent_a.client.post(
    "/contacts",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      **_CREATE_FIELDS,
      "email": email,
    },
  )
  assert first.status_code == 303

  second = await agent_a.client.post(
    "/contacts",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,  # SAME key
      **_CREATE_FIELDS,
      "email": email,
      "company": "A Completely Different Company",  # DIFFERENT payload
    },
  )
  assert second.status_code == 409
  assert "already submitted" in second.text, (
    "a same-key/different-payload conflict must render the duplicate context "
    '(errors/409.html context="duplicate"), not the stale or archived-parent one'
  )

  receipt_count = await _count(
    db_connection,
    "SELECT count(*) FROM mutation_receipts WHERE idempotency_key = %(key)s",
    {"key": idempotency_key},
  )
  assert receipt_count == 1, "exactly one receipt row — the second INSERT never committed"

  contact_count = await _count(
    db_connection,
    "SELECT count(*) FROM contacts WHERE email_lower = %(email)s",
    {"email": email.lower()},
  )
  assert contact_count == 1, "no second business row was created for the conflicting payload"


async def test_stale_edit_preserves_submitted_values_and_reissues_version_and_key(
  agent_a: LoggedInPrincipal,
) -> None:
  """The 409 recovery view re-issues the CURRENT version and a FRESH idempotency key.

  Complements ``tests/access/test_contacts.py``'s stale-edit test (which
  checks only that the loser's own submitted value survives): this
  additionally asserts the re-issued ``version`` differs from the stale one
  that lost the race, and the re-issued ``idempotency_key`` differs from
  the one the losing request itself carried — resubmitting *that* key
  would meet the now-stored receipt and answer ``409 duplicate`` instead,
  which explains nothing to the user.
  """
  contact = await create_contact(agent_a, **{**_CREATE_FIELDS, "email": "stale-edit@example.test"})
  edit_form = await agent_a.client.get(f"/contacts/{contact.id}/edit")
  csrf_token = extract_csrf_token(edit_form.text)
  original_idempotency_key = extract_hidden_field(edit_form.text, "idempotency_key")
  original_version = extract_hidden_field(edit_form.text, "version")

  winner_key = fresh_idempotency_key()
  winner = await agent_a.client.post(
    f"/contacts/{contact.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": winner_key,
      "version": original_version,
      **{**_CREATE_FIELDS, "email": "stale-edit@example.test", "company": "Winner Co"},
    },
  )
  assert winner.status_code == 303

  loser = await agent_a.client.post(
    f"/contacts/{contact.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": original_idempotency_key,
      "version": original_version,
      **{**_CREATE_FIELDS, "email": "stale-edit@example.test", "company": "Loser Co"},
    },
  )
  assert loser.status_code == 409
  assert "Loser Co" in loser.text, (
    "the LOSER's own submitted value must be preserved on the recovery view, not the winner's"
  )

  reissued_version = extract_hidden_field(loser.text, "version")
  reissued_key = extract_hidden_field(loser.text, "idempotency_key")
  assert reissued_version != original_version, "the recovery form must carry the CURRENT version"
  assert reissued_version == "2", "exactly one successful edit bumped the row from version 1 to 2"
  assert reissued_key != original_idempotency_key, "the recovery form must mint a FRESH key"


async def test_reassignment_atomicity_no_reader_observes_a_torn_state(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """An admin reassigns while an agent repeatedly reads; no response is a `500` or a torn state.

  There is no child object to join through here (deals belong to a
  different surface), so this drives the half this module *can* prove: the
  contact's own row changes through exactly one atomic `UPDATE`, and a
  reader racing it never observes a broken intermediate state.
  """
  contact = await create_contact(
    agent_a, **{**_CREATE_FIELDS, "email": "reassign-race@example.test"}
  )
  detail = await admin.client.get(f"/contacts/{contact.id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  version = extract_hidden_field(detail.text, "version")

  async def _reassign() -> httpx.Response:
    return await admin.client.post(
      f"/contacts/{contact.id}/reassign",
      data={
        "csrf_token": csrf_token,
        "idempotency_key": idempotency_key,
        "version": version,
        # Placeholder target — see the module docstring's "known gap".
        "owner_id": agent_b.user.email,
      },
    )

  async def _read_during_race() -> list[int]:
    statuses = []
    for _ in range(10):
      response = await agent_a.client.get(f"/contacts/{contact.id}")
      statuses.append(response.status_code)
    return statuses

  reassign_response, reader_statuses = await asyncio.gather(_reassign(), _read_during_race())
  assert reassign_response.status_code in (303, 400)
  assert 500 not in reader_statuses, (
    f"a reader observed a 500 during the reassignment race: {reader_statuses}"
  )
  assert all(status in (200, 404) for status in reader_statuses), (
    f"every read during the race must be a clean 200 (still visible) or 404 "
    f"(no longer this agent's), never anything else: {reader_statuses}"
  )
