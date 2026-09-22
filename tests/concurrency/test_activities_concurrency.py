"""Racing writes on `POST /activities`.

Two duplicate-submission shapes: sequential (the wire-level `303`/`303`
replay pair `tests/access/test_activities.py` already proves at the status
level) and genuinely concurrent (`asyncio.gather`, which can drive
psycopg's `23505` unique violation on `mutation_receipts` rather than the
receipt-already-there path a sequential pair takes) — then, for both, a
`db_connection` read proving exactly one `activities` row, one
`mutation_receipts` row and one `audit_events` row resulted, never two.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
from conftest import (
  LoggedInPrincipal,
  create_contact,
  extract_csrf_token,
  extract_scoped_hidden_field,
)

pytestmark = pytest.mark.asyncio

_CONTACT_FIELDS = {
  "name": "Activity Concurrency Contact",
  "company": "Northwind Traders",
  "phone": "+1 555 0302",
  "kind": "lead",
}


async def _activities_count(db_connection: Any, *, contact_id: str) -> int:
  """Count `activities` rows for one contact, as the runtime role."""
  cursor = await db_connection.execute(
    "SELECT count(*) FROM public.activities WHERE contact_id = %(contact_id)s",
    {"contact_id": contact_id},
  )
  row = await cursor.fetchone()
  return 0 if row is None else int(row[0])


async def _receipt_count(db_connection: Any, *, idempotency_key: str) -> int:
  """Count `mutation_receipts` rows for one `activity_create` key, as the runtime role."""
  cursor = await db_connection.execute(
    "SELECT count(*) FROM public.mutation_receipts "
    "WHERE idempotency_key = %(key)s AND operation = 'activity_create'",
    {"key": idempotency_key},
  )
  row = await cursor.fetchone()
  return 0 if row is None else int(row[0])


async def _audit_count(db_connection: Any, *, activity_id: str) -> int:
  """Count `audit_events` rows for one `activity_created` object, as the runtime role."""
  cursor = await db_connection.execute(
    "SELECT count(*) FROM public.audit_events "
    "WHERE object_type = 'activity' AND action = 'activity_created' AND object_id = %(id)s",
    {"id": activity_id},
  )
  row = await cursor.fetchone()
  return 0 if row is None else int(row[0])


async def _one_activity_id(db_connection: Any, *, contact_id: str) -> str:
  """Return the single activity id written for one contact."""
  cursor = await db_connection.execute(
    "SELECT id FROM public.activities WHERE contact_id = %(contact_id)s",
    {"contact_id": contact_id},
  )
  row = await cursor.fetchone()
  assert row is not None, "expected exactly one activities row, found none"
  return str(row[0])


async def test_sequential_duplicate_submission_writes_exactly_one_row_receipt_and_audit(
  agent_a: LoggedInPrincipal, db_connection: Any
) -> None:
  """Two sequential `POST`s, same key and payload, leave one row, one receipt, one audit event."""
  contact = await create_contact(agent_a, **_CONTACT_FIELDS)
  detail = await agent_a.client.get(f"/contacts/{contact.id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_scoped_hidden_field(
    detail.text, form_action="/activities", name="idempotency_key"
  )
  payload = {
    "csrf_token": csrf_token,
    "idempotency_key": idempotency_key,
    "contact_id": contact.id,
    "kind": "call",
    "occurred_on": "2026-09-15",
    "summary": "Sequential duplicate submission probe.",
  }
  first = await agent_a.client.post("/activities", data=payload)
  second = await agent_a.client.post("/activities", data=payload)
  assert first.status_code == 303
  assert second.status_code == 303
  assert first.headers.get("location") == second.headers.get("location")

  assert await _activities_count(db_connection, contact_id=contact.id) == 1
  assert await _receipt_count(db_connection, idempotency_key=idempotency_key) == 1
  activity_id = await _one_activity_id(db_connection, contact_id=contact.id)
  assert await _audit_count(db_connection, activity_id=activity_id) == 1


async def test_concurrent_duplicate_submission_writes_exactly_one_row_receipt_and_audit(
  agent_a: LoggedInPrincipal, http_client_factory: Any, db_connection: Any
) -> None:
  """Two genuinely concurrent `POST`s (`asyncio.gather`), same key and payload, still leave one row.

  Unlike the sequential pair, one of the two concurrent transactions can
  race past the receipt lookup before the other commits its own receipt
  row, so the second writer can meet ``mutation_receipts``' `23505` unique
  violation directly rather than finding the receipt already there on its
  first look — `app.services.activities.log_activity`'s
  ``except psycopg.Error`` branch (`replay_after_conflict`), which the
  sequential pair above cannot reliably exercise.
  """
  contact = await create_contact(agent_a, **_CONTACT_FIELDS)
  detail = await agent_a.client.get(f"/contacts/{contact.id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_scoped_hidden_field(
    detail.text, form_action="/activities", name="idempotency_key"
  )
  payload = {
    "csrf_token": csrf_token,
    "idempotency_key": idempotency_key,
    "contact_id": contact.id,
    "kind": "meeting",
    "occurred_on": "2026-09-16",
    "summary": "Concurrent duplicate submission probe.",
  }
  # A second client, its own cookie jar, carrying the SAME session cookie:
  # two independent connections racing the same (user_id, operation, key)
  # receipt row, rather than one connection serializing its own requests.
  second_client: httpx.AsyncClient = http_client_factory()
  second_client.cookies.update(agent_a.client.cookies)

  first_response, second_response = await asyncio.gather(
    agent_a.client.post("/activities", data=payload),
    second_client.post("/activities", data=payload),
  )
  assert first_response.status_code == 303
  assert second_response.status_code == 303
  assert first_response.headers.get("location") == second_response.headers.get("location")

  assert await _activities_count(db_connection, contact_id=contact.id) == 1
  assert await _receipt_count(db_connection, idempotency_key=idempotency_key) == 1
  activity_id = await _one_activity_id(db_connection, contact_id=contact.id)
  assert await _audit_count(db_connection, activity_id=activity_id) == 1
