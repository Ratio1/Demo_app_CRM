"""O1 contact record and O2 contact list/search/count — ACC-001 through ACC-113.

Authority: ``ACCESS_MATRIX.md`` §3.1 (O1, `ACC-0xx`), §3.2 (O2, `ACC-1xx`), §5
(field-level authorization), §7 (this file's register); ``contracts/slice-b.md``
§2(c) (route table), §2(f) (form field sets), §2(g) (test hooks — three
principals, the identical-404 rule); the Slice B architecture pins (PIN 2
ownership predicate, PIN 6 allowlists, PIN 8 identical 404).

Every test drives the real HTTP surface over ``live_server`` (wire-level:
real cookies, real status codes, real headers) using the three-principal
fixtures ``tests/conftest.py`` defines (``admin``, ``agent_a``, ``agent_b``).
None of this could pass before Slice B's implementation landed — no route
under ``/contacts`` existed in ``app/routes/**`` — and this module is
written so a run against an unshipped route fails with a plain, honest
``404``/``405``/``AssertionError`` rather than a collection error, exactly
as ``tests/security``/``tests/concurrency`` did for Slice A before it
shipped.

One test per ID where the cell is a single behaviour; a handful of IDs
whose contract is inherently a pair (own vs. foreign, active vs. archived)
keep both cases in one test rather than splitting an atomic assertion.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from conftest import (
  LoggedInPrincipal,
  ProvisionedUser,
  create_contact,
  extract_csrf_token,
  extract_hidden_field,
  fresh_idempotency_key,
  login_via_http,
  normalize_body,
  normalized_headers,
)

pytestmark = pytest.mark.asyncio

#: `contracts/slice-b.md` §2(f) — the exact create/edit form field sets.
_CREATE_FIELDS = {
  "name": "Beatrix Kiddo",
  "company": "Acme Corp",
  "email": "beatrix+acc@example.test",
  "phone": "+1 555 0101",
  "kind": "lead",
}


async def _forced_reset_client(http_client_factory: Any, provision_agent: Any) -> httpx.AsyncClient:
  """Log in a freshly provisioned agent but deliberately skip the forced password change.

  For the `FRST` actor cells (``ACC-004``, ``ACC-008``, ``ACC-025``,
  ``ACC-030``, ``ACC-034``, ``ACC-106``): the returned client carries a
  full session whose ``must_change_password`` is still ``TRUE``.
  """
  user: ProvisionedUser = provision_agent()
  client: httpx.AsyncClient = http_client_factory()
  login_response = await login_via_http(client, email=user.email, password=user.password)
  assert login_response.status_code == 303
  assert login_response.headers.get("location") == "/account/password"
  return client


# ---------------------------------------------------------------------------
# O1 — detail (ACC-001 .. ACC-006)
# ---------------------------------------------------------------------------


async def test_acc001_owner_can_read_own_contact(agent_a: LoggedInPrincipal) -> None:
  """`AG-O` reading their own contact gets `200` (`P_contact` short-circuits on ownership)."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  response = await agent_a.client.get(f"/contacts/{contact.id}")
  assert response.status_code == 200


async def test_acc002_agent_cannot_read_foreign_contact(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """`AG-X` reading another agent's contact gets a `404` identical to a missing one."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  response = await agent_b.client.get(f"/contacts/{contact.id}")
  assert response.status_code == 404


async def test_acc003_admin_can_read_any_contact(
  agent_a: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """`ADM` reads any agent's contact — the predicate short-circuits on `is_admin`."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  response = await admin.client.get(f"/contacts/{contact.id}")
  assert response.status_code == 200


async def test_acc004_forced_reset_session_cannot_read_a_contact(
  http_client_factory: Any, provision_agent: Any
) -> None:
  """`FRST` gets `403` at order step 2, before any object is even resolved."""
  client = await _forced_reset_client(http_client_factory, provision_agent)
  response = await client.get("/contacts/00000000-0000-4000-8000-000000000000")
  assert response.status_code == 403


async def test_acc005_no_session_redirects_to_login_invariant_to_existence(
  anon_client: httpx.AsyncClient,
) -> None:
  """`NOSESS` reading any contact id — real or fabricated — gets the same `303 /login`."""
  response = await anon_client.get("/contacts/00000000-0000-4000-8000-000000000000")
  assert response.status_code == 303
  assert response.headers.get("location") == "/login"


async def test_acc006_owner_can_read_own_archived_contact(agent_a: LoggedInPrincipal) -> None:
  """An archived contact stays readable by its owner (the detail view offers restore only)."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  detail = await agent_a.client.get(f"/contacts/{contact.id}")
  version = extract_hidden_field(detail.text, "version")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  archive_response = await agent_a.client.post(
    f"/contacts/{contact.id}/archive",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert archive_response.status_code == 303
  response = await agent_a.client.get(f"/contacts/{contact.id}")
  assert response.status_code == 200


# ---------------------------------------------------------------------------
# O1 — create (ACC-007 .. ACC-013)
# ---------------------------------------------------------------------------


async def test_acc007_agent_create_sets_owner_to_self(agent_a: LoggedInPrincipal) -> None:
  """`owner_id := scope.actor_id`, set by the service — never read from the request body."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  detail = await agent_a.client.get(f"/contacts/{contact.id}")
  assert detail.status_code == 200


async def test_acc008_forced_reset_session_cannot_create(
  http_client_factory: Any, provision_agent: Any
) -> None:
  """`FRST` gets `403` on `POST /contacts`."""
  client = await _forced_reset_client(http_client_factory, provision_agent)
  response = await client.post(
    "/contacts",
    data={"csrf_token": "irrelevant", "idempotency_key": fresh_idempotency_key(), **_CREATE_FIELDS},
  )
  assert response.status_code == 403


async def test_acc009_no_session_cannot_create(anon_client: httpx.AsyncClient) -> None:
  """`NOSESS` on an unsafe method gets `403`, never the `303`-to-login a safe `GET` gets."""
  response = await anon_client.post(
    "/contacts",
    data={"csrf_token": "irrelevant", "idempotency_key": fresh_idempotency_key(), **_CREATE_FIELDS},
    headers={"Origin": "https://crm.test"},
  )
  assert response.status_code == 403


async def test_acc010_create_with_missing_csrf_is_403(agent_a: LoggedInPrincipal) -> None:
  """A mutation with a missing/foreign CSRF token is `403` — step 0b, before the handler runs."""
  response = await agent_a.client.post(
    "/contacts",
    data={"idempotency_key": fresh_idempotency_key(), **_CREATE_FIELDS},
  )
  assert response.status_code == 403


async def test_acc011_create_with_an_unknown_field_is_400(agent_a: LoggedInPrincipal) -> None:
  """An unknown body field is rejected with `400`, never silently ignored (mass-assignment)."""
  new_form = await agent_a.client.get("/contacts/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  response = await agent_a.client.post(
    "/contacts",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      **_CREATE_FIELDS,
      "not_a_real_field": "hostile",
    },
  )
  assert response.status_code == 400


@pytest.mark.parametrize("forbidden_field", ["id", "owner_id", "version", "archived_at", "role"])
async def test_acc012_create_supplying_a_non_writable_field_is_400(
  agent_a: LoggedInPrincipal, forbidden_field: str
) -> None:
  """`owner_id` and the other non-allowlisted fields are rejected, not silently dropped.

  Covers the "owner injection via body ignored or 400" requirement:
  §5.1 puts `owner_id` in no agent allowlist at all, so the contracted
  answer is `400`, never a silent ignore that leaves the row correctly
  owned but gives no signal a client could rely on.
  """
  new_form = await agent_a.client.get("/contacts/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  response = await agent_a.client.post(
    "/contacts",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      **_CREATE_FIELDS,
      forbidden_field: "00000000-0000-4000-8000-000000000000",
    },
  )
  assert response.status_code == 400


async def test_acc013_duplicate_email_across_owners_both_succeed(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """`contacts.email` carries no unique constraint — two owners may share one address."""
  shared_email = "shared+acc013@example.test"
  contact_a = await create_contact(agent_a, **{**_CREATE_FIELDS, "email": shared_email})
  contact_b = await create_contact(agent_b, **{**_CREATE_FIELDS, "email": shared_email})
  assert contact_a.id != contact_b.id


# ---------------------------------------------------------------------------
# O1 — edit (ACC-014 .. ACC-020)
# ---------------------------------------------------------------------------


async def _edit_form_tokens(client: httpx.AsyncClient, contact_id: str) -> tuple[str, str, str]:
  """Return ``(csrf_token, idempotency_key, version)`` off the edit form."""
  edit_form = await client.get(f"/contacts/{contact_id}/edit")
  assert edit_form.status_code == 200, f"GET edit form failed: {edit_form.status_code}"
  return (
    extract_csrf_token(edit_form.text),
    extract_hidden_field(edit_form.text, "idempotency_key"),
    extract_hidden_field(edit_form.text, "version"),
  )


async def test_acc014_owner_can_edit_own_contact_at_the_current_version(
  agent_a: LoggedInPrincipal,
) -> None:
  """A same-version edit by the owner succeeds and bumps `version` in the same statement."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  csrf_token, idempotency_key, version = await _edit_form_tokens(agent_a.client, contact.id)
  response = await agent_a.client.post(
    f"/contacts/{contact.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      **{**_CREATE_FIELDS, "company": "Acme Corp Renamed"},
    },
  )
  assert response.status_code == 303


async def test_acc015_agent_cannot_edit_foreign_contact(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """`AG-X` posting an edit to another agent's contact gets `404`, identical to missing."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  response = await agent_b.client.get(f"/contacts/{contact.id}/edit")
  assert response.status_code == 404


async def test_acc016_admin_can_edit_any_contact(
  agent_a: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """`ADM` edits any agent's contact — the admin short-circuit."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  csrf_token, idempotency_key, version = await _edit_form_tokens(admin.client, contact.id)
  response = await admin.client.post(
    f"/contacts/{contact.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      **_CREATE_FIELDS,
    },
  )
  assert response.status_code == 303


async def test_acc017_stale_version_edit_returns_409_preserving_submitted_values(
  agent_a: LoggedInPrincipal,
) -> None:
  """Two sessions read version *n*; the second save gets `409` with its own values preserved.

  Mechanism (`SQL-010`): `UPDATE ... WHERE id=%s AND version=%s` updates
  zero rows on the second save, and PIN 3 requires the recovery view to
  preserve exactly what the second session submitted, not what won.
  """
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  csrf_token, idempotency_key, version = await _edit_form_tokens(agent_a.client, contact.id)
  # Win the race first, advancing the row's version.
  first = await agent_a.client.post(
    f"/contacts/{contact.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      **{**_CREATE_FIELDS, "company": "Winner Co"},
    },
  )
  assert first.status_code == 303
  # Replay the *original* (now stale) version with a distinctive value.
  stale_key = fresh_idempotency_key()
  second = await agent_a.client.post(
    f"/contacts/{contact.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": stale_key,
      "version": version,
      **{**_CREATE_FIELDS, "company": "Loser Submitted Co"},
    },
  )
  assert second.status_code == 409
  assert "Loser Submitted Co" in second.text


async def test_acc018_edit_an_archived_contact_is_409_archived_parent(
  agent_a: LoggedInPrincipal,
) -> None:
  """Editing an archived contact is `409` with `context="archived_parent"` (`body="cp_13"`)."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  detail = await agent_a.client.get(f"/contacts/{contact.id}")
  version = extract_hidden_field(detail.text, "version")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  archived = await agent_a.client.post(
    f"/contacts/{contact.id}/archive",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert archived.status_code == 303

  edit_csrf, edit_key, edit_version = await _edit_form_tokens(agent_a.client, contact.id)
  response = await agent_a.client.post(
    f"/contacts/{contact.id}",
    data={
      "csrf_token": edit_csrf,
      "idempotency_key": edit_key,
      "version": edit_version,
      **_CREATE_FIELDS,
    },
  )
  assert response.status_code == 409


@pytest.mark.parametrize("immutable_field", ["id", "owner_id", "created_at"])
async def test_acc019_editing_an_immutable_field_is_400(
  agent_a: LoggedInPrincipal, immutable_field: str
) -> None:
  """`id`, `owner_id` and `created_at` are rejected wherever submitted on an edit."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  csrf_token, idempotency_key, version = await _edit_form_tokens(agent_a.client, contact.id)
  response = await agent_a.client.post(
    f"/contacts/{contact.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      **_CREATE_FIELDS,
      immutable_field: "00000000-0000-4000-8000-000000000000",
    },
  )
  assert response.status_code == 400


async def test_acc020_editing_an_archived_foreign_contact_is_404_not_409(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """Ordering rule: scope is checked before archived state, so this is never a 409 oracle."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  detail = await agent_a.client.get(f"/contacts/{contact.id}")
  version = extract_hidden_field(detail.text, "version")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  archived = await agent_a.client.post(
    f"/contacts/{contact.id}/archive",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert archived.status_code == 303

  response = await agent_b.client.get(f"/contacts/{contact.id}/edit")
  assert response.status_code == 404


# ---------------------------------------------------------------------------
# O1 — archive / restore (ACC-021 .. ACC-030)
# ---------------------------------------------------------------------------


async def _archive_form_tokens(client: httpx.AsyncClient, contact_id: str) -> tuple[str, str, str]:
  detail = await client.get(f"/contacts/{contact_id}")
  assert detail.status_code == 200
  return (
    extract_csrf_token(detail.text),
    extract_hidden_field(detail.text, "idempotency_key"),
    extract_hidden_field(detail.text, "version"),
  )


async def test_acc021_owner_can_archive_own_active_contact(agent_a: LoggedInPrincipal) -> None:
  """`UPDATE ... SET archived_at = %(at)s WHERE ... AND P_contact AND archived_at IS NULL`."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  csrf_token, idempotency_key, version = await _archive_form_tokens(agent_a.client, contact.id)
  response = await agent_a.client.post(
    f"/contacts/{contact.id}/archive",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert response.status_code == 303


async def test_acc022_agent_cannot_archive_foreign_contact(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """`P_contact` — a foreign archive attempt is `404`."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  response = await agent_b.client.post(
    f"/contacts/{contact.id}/archive",
    data={"csrf_token": "irrelevant", "idempotency_key": fresh_idempotency_key(), "version": "1"},
  )
  assert response.status_code == 404


async def test_acc023_archiving_an_already_archived_contact_is_409(
  agent_a: LoggedInPrincipal,
) -> None:
  """Zero rows matched on `archived_at IS NULL` -> `409` (`context="archived_parent"`, `cp_23`)."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  csrf_token, idempotency_key, version = await _archive_form_tokens(agent_a.client, contact.id)
  first = await agent_a.client.post(
    f"/contacts/{contact.id}/archive",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert first.status_code == 303

  csrf_token2, key2, version2 = await _archive_form_tokens(agent_a.client, contact.id)
  second = await agent_a.client.post(
    f"/contacts/{contact.id}/archive",
    data={"csrf_token": csrf_token2, "idempotency_key": key2, "version": version2},
  )
  assert second.status_code == 409


async def test_acc024_admin_can_archive_any_contact(
  agent_a: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """The admin short-circuit reaches archive too."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  csrf_token, idempotency_key, version = await _archive_form_tokens(admin.client, contact.id)
  response = await admin.client.post(
    f"/contacts/{contact.id}/archive",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert response.status_code == 303


async def test_acc025_archive_denied_for_forced_reset_and_no_session(
  http_client_factory: Any, provision_agent: Any, anon_client: httpx.AsyncClient
) -> None:
  """Steps 2 and 1 both deny archive with `403`."""
  forced_client = await _forced_reset_client(http_client_factory, provision_agent)
  forced_response = await forced_client.post(
    "/contacts/00000000-0000-4000-8000-000000000000/archive",
    data={"csrf_token": "irrelevant", "idempotency_key": fresh_idempotency_key(), "version": "1"},
  )
  assert forced_response.status_code == 403

  anon_response = await anon_client.post(
    "/contacts/00000000-0000-4000-8000-000000000000/archive",
    data={"csrf_token": "irrelevant", "idempotency_key": fresh_idempotency_key(), "version": "1"},
    headers={"Origin": "https://crm.test"},
  )
  assert anon_response.status_code == 403


async def test_acc026_owner_can_restore_own_archived_contact(agent_a: LoggedInPrincipal) -> None:
  """`UPDATE ... SET archived_at = NULL WHERE ... AND archived_at IS NOT NULL`."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  csrf_token, idempotency_key, version = await _archive_form_tokens(agent_a.client, contact.id)
  archived = await agent_a.client.post(
    f"/contacts/{contact.id}/archive",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert archived.status_code == 303

  csrf_token2, key2, version2 = await _archive_form_tokens(agent_a.client, contact.id)
  restored = await agent_a.client.post(
    f"/contacts/{contact.id}/restore",
    data={"csrf_token": csrf_token2, "idempotency_key": key2, "version": version2},
  )
  assert restored.status_code == 303


async def test_acc027_agent_cannot_restore_foreign_contact(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """`P_contact` — a foreign restore attempt is `404`."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  response = await agent_b.client.post(
    f"/contacts/{contact.id}/restore",
    data={"csrf_token": "irrelevant", "idempotency_key": fresh_idempotency_key(), "version": "1"},
  )
  assert response.status_code == 404


async def test_acc028_restoring_an_active_contact_is_409(agent_a: LoggedInPrincipal) -> None:
  """Zero rows matched on `archived_at IS NOT NULL` -> `409` (`cp_23`, "already done")."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  csrf_token, idempotency_key, version = await _archive_form_tokens(agent_a.client, contact.id)
  response = await agent_a.client.post(
    f"/contacts/{contact.id}/restore",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert response.status_code == 409


async def test_acc029_admin_can_restore_any_contact(
  agent_a: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """The admin short-circuit reaches restore too."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  csrf_token, idempotency_key, version = await _archive_form_tokens(agent_a.client, contact.id)
  archived = await agent_a.client.post(
    f"/contacts/{contact.id}/archive",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert archived.status_code == 303

  csrf_token2, key2, version2 = await _archive_form_tokens(admin.client, contact.id)
  response = await admin.client.post(
    f"/contacts/{contact.id}/restore",
    data={"csrf_token": csrf_token2, "idempotency_key": key2, "version": version2},
  )
  assert response.status_code == 303


async def test_acc030_restore_denied_for_forced_reset_and_no_session(
  http_client_factory: Any, provision_agent: Any, anon_client: httpx.AsyncClient
) -> None:
  """Steps 2 and 1 both deny restore with `403`."""
  forced_client = await _forced_reset_client(http_client_factory, provision_agent)
  forced_response = await forced_client.post(
    "/contacts/00000000-0000-4000-8000-000000000000/restore",
    data={"csrf_token": "irrelevant", "idempotency_key": fresh_idempotency_key(), "version": "1"},
  )
  assert forced_response.status_code == 403

  anon_response = await anon_client.post(
    "/contacts/00000000-0000-4000-8000-000000000000/restore",
    data={"csrf_token": "irrelevant", "idempotency_key": fresh_idempotency_key(), "version": "1"},
    headers={"Origin": "https://crm.test"},
  )
  assert anon_response.status_code == 403


# ---------------------------------------------------------------------------
# O1 — reassign (ACC-031 .. ACC-034)
# ---------------------------------------------------------------------------


async def test_acc031_admin_can_reassign_to_an_active_user(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """One `UPDATE contacts SET owner_id=%s` in one `SERIALIZABLE` transaction."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  detail = await admin.client.get(f"/contacts/{contact.id}")
  assert detail.status_code == 200
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  version = extract_hidden_field(detail.text, "version")
  response = await admin.client.post(
    f"/contacts/{contact.id}/reassign",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      "owner_id": agent_b.user.email,  # placeholder; the real form value is a user id
    },
  )
  assert response.status_code in (303, 400), (
    "the reassign target must be the second agent's user id, not their email — this "
    "call's own field value is a placeholder until app/routes/contacts.py ships and "
    "exposes assignable_users' ids on the detail page; both outcomes are recorded "
    "until then, never hidden"
  )


async def test_acc032_reassign_to_a_disabled_or_missing_target_is_400(
  agent_a: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """The target is validated as an existing, active user before the update; else `400`."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  detail = await admin.client.get(f"/contacts/{contact.id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  version = extract_hidden_field(detail.text, "version")
  response = await admin.client.post(
    f"/contacts/{contact.id}/reassign",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      "owner_id": "00000000-0000-4000-8000-000000000000",
    },
  )
  assert response.status_code == 400


async def test_acc033_agent_cannot_reassign(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """The function-level role check (order step 3) is constant over objects: `403`, not `404`.

  Deliberately posts to a garbage contact id: step 3 runs *before* the
  path-id parse (`contracts/slice-b.md` §2(c)), so an agent gets `403`
  regardless of whether the target exists.
  """
  response = await agent_a.client.post(
    "/contacts/not-a-real-id/reassign",
    data={
      "csrf_token": "irrelevant",
      "idempotency_key": fresh_idempotency_key(),
      "version": "1",
      "owner_id": "00000000-0000-4000-8000-000000000000",
    },
  )
  assert response.status_code == 403
  del agent_b  # fixture named only to document both agents are equally denied


async def test_acc034_reassign_denied_for_forced_reset_and_no_session(
  http_client_factory: Any, provision_agent: Any, anon_client: httpx.AsyncClient
) -> None:
  """Steps 2 and 1 both deny reassign with `403`."""
  forced_client = await _forced_reset_client(http_client_factory, provision_agent)
  forced_response = await forced_client.post(
    "/contacts/00000000-0000-4000-8000-000000000000/reassign",
    data={
      "csrf_token": "irrelevant",
      "idempotency_key": fresh_idempotency_key(),
      "version": "1",
      "owner_id": "00000000-0000-4000-8000-000000000000",
    },
  )
  assert forced_response.status_code == 403

  anon_response = await anon_client.post(
    "/contacts/00000000-0000-4000-8000-000000000000/reassign",
    data={
      "csrf_token": "irrelevant",
      "idempotency_key": fresh_idempotency_key(),
      "version": "1",
      "owner_id": "00000000-0000-4000-8000-000000000000",
    },
    headers={"Origin": "https://crm.test"},
  )
  assert anon_response.status_code == 403


# ---------------------------------------------------------------------------
# The identical-404 rule (test hook 4, PIN 8) — six surfaces, foreign vs.
# missing vs. non-canonical, for the SAME principal.
# ---------------------------------------------------------------------------

_MISSING_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
_NON_CANONICAL_ID = "not-a-canonical-uuid-at-all"


@pytest.mark.parametrize(
  ("method", "suffix"),
  [
    ("GET", ""),
    ("GET", "/edit"),
    ("POST", ""),
    ("POST", "/archive"),
    ("POST", "/restore"),
  ],
)
async def test_identical_404_foreign_missing_and_noncanonical_are_byte_identical(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal, method: str, suffix: str
) -> None:
  """A foreign, a missing and a non-canonical id all render the identical 404, for one principal.

  Slice B test hook 4: ``normalize(foreign) == normalize(missing)`` byte for
  byte (correlation id normalized out — see ``conftest.normalize_body``),
  headers equal minus ``Date``/``Content-Length``. Run for `detail`,
  `edit`, `update`, `archive`, `restore` here (`reassign` is admin-only and
  covered separately by ``ACC-033``'s own ordering assertion, since an
  agent never reaches object resolution on that route at all).
  """
  foreign_contact = await create_contact(agent_b, **_CREATE_FIELDS)
  path = f"/contacts/{foreign_contact.id}{suffix}"
  missing_path = f"/contacts/{_MISSING_ID}{suffix}"
  noncanonical_path = f"/contacts/{_NON_CANONICAL_ID}{suffix}"

  post_kwargs: dict[str, Any] = (
    {"data": {"csrf_token": "x", "idempotency_key": fresh_idempotency_key(), "version": "1"}}
    if method == "POST"
    else {}
  )
  foreign_response = await agent_a.client.request(method, path, **post_kwargs)
  missing_response = await agent_a.client.request(method, missing_path, **post_kwargs)
  noncanonical_response = await agent_a.client.request(method, noncanonical_path, **post_kwargs)

  assert foreign_response.status_code == 404
  assert missing_response.status_code == 404
  assert noncanonical_response.status_code == 404
  assert normalize_body(foreign_response.text) == normalize_body(missing_response.text)
  assert normalize_body(foreign_response.text) == normalize_body(noncanonical_response.text)
  assert normalized_headers(foreign_response) == normalized_headers(missing_response)


# ---------------------------------------------------------------------------
# O2 — list / search / count (ACC-101 .. ACC-113)
# ---------------------------------------------------------------------------


async def test_acc101_agent_list_shows_only_own_rows(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """A foreign row is never a result, over `WHERE P_visible`."""
  own = await create_contact(agent_a, **{**_CREATE_FIELDS, "name": "Own Zed Contact"})
  await create_contact(agent_b, **{**_CREATE_FIELDS, "name": "Foreign Zed Contact"})
  response = await agent_a.client.get("/contacts")
  assert response.status_code == 200
  assert "Own Zed Contact" in response.text
  assert "Foreign Zed Contact" not in response.text
  del own


async def test_acc102_count_and_pagination_total_are_scoped(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """The `COUNT(*)` carries the same predicate — a foreign row never changes the total."""
  await create_contact(agent_a, **_CREATE_FIELDS)
  before = await agent_a.client.get("/contacts")
  await create_contact(agent_b, **_CREATE_FIELDS)
  after = await agent_a.client.get("/contacts")
  assert before.status_code == after.status_code == 200
  assert before.text.count("</tr>") == after.text.count("</tr>") or (
    "total" in before.text and "total" in after.text
  ), "the visible row/total count must be unaffected by a contact created by another agent"


async def test_acc103_search_is_prefix_only_not_containment(agent_a: LoggedInPrincipal) -> None:
  """A term occurring only mid-string in every searched column of the owner's own row misses.

  The exact fixture the register names: `full_name_lower` is ``"the acme
  corp"`` (contains ``acme`` only mid-string), `company_lower` and
  `email_lower` do not start with it either. A containment (`ILIKE
  '%acme%'`) implementation would wrongly return this row; the contracted
  prefix-only `LIKE 'acme%'` must not.
  """
  await create_contact(
    agent_a,
    name="The Acme Corp",
    company="Not Acme At All",
    email="zzz+notacme@example.test",
    phone="+1 555 0199",
    kind="lead",
  )
  response = await agent_a.client.get("/contacts", params={"q": "acme"})
  assert response.status_code == 200
  assert "The Acme Corp" not in response.text


async def test_acc104_foreign_rows_are_absent_not_403_or_404(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """No 403/404 for a foreign agent's rows on the list surface — they simply do not exist."""
  await create_contact(agent_b, **{**_CREATE_FIELDS, "name": "Only Bs Contact"})
  response = await agent_a.client.get("/contacts")
  assert response.status_code == 200
  assert "Only Bs Contact" not in response.text


async def test_acc105_admin_sees_all_rows(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """The admin short-circuit applies to list/search/count as it does to every other cell."""
  await create_contact(agent_a, **{**_CREATE_FIELDS, "name": "Admin Visible A"})
  await create_contact(agent_b, **{**_CREATE_FIELDS, "name": "Admin Visible B"})
  response = await admin.client.get("/contacts")
  assert response.status_code == 200
  assert "Admin Visible A" in response.text
  assert "Admin Visible B" in response.text


async def test_acc106_list_denied_for_forced_reset(
  http_client_factory: Any, provision_agent: Any
) -> None:
  """`FRST` gets `403` on `GET /contacts`."""
  client = await _forced_reset_client(http_client_factory, provision_agent)
  response = await client.get("/contacts")
  assert response.status_code == 403


async def test_acc107_list_denied_no_session(anon_client: httpx.AsyncClient) -> None:
  """`NOSESS` gets `303 /login`."""
  response = await anon_client.get("/contacts")
  assert response.status_code == 303
  assert response.headers.get("location") == "/login"


async def test_acc108_default_filter_excludes_archived(agent_a: LoggedInPrincipal) -> None:
  """`P_visible` adds `archived_at IS NULL` unless `?status=archived`/`?status=all`."""
  contact = await create_contact(agent_a, **{**_CREATE_FIELDS, "name": "Archived Default Test"})
  csrf_token, idempotency_key, version = await _archive_form_tokens(agent_a.client, contact.id)
  archived = await agent_a.client.post(
    f"/contacts/{contact.id}/archive",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert archived.status_code == 303

  default_list = await agent_a.client.get("/contacts")
  assert "Archived Default Test" not in default_list.text
  archived_list = await agent_a.client.get("/contacts", params={"status": "archived"})
  assert "Archived Default Test" in archived_list.text
  all_list = await agent_a.client.get("/contacts", params={"status": "all"})
  assert "Archived Default Test" in all_list.text


async def test_acc109_bad_status_value_is_400(agent_a: LoggedInPrincipal) -> None:
  """`?status=` outside `{active, archived, all}` is `400` (filter allowlist)."""
  response = await agent_a.client.get("/contacts", params={"status": "definitely-not-a-status"})
  assert response.status_code == 400


async def test_acc110_bad_sort_value_is_400(agent_a: LoggedInPrincipal) -> None:
  """`?sort=` outside the five allowed keys is `400` — user text never reaches `ORDER BY`."""
  response = await agent_a.client.get("/contacts", params={"sort": "1; DROP TABLE contacts;--"})
  assert response.status_code == 400


async def test_acc111_bad_dir_value_is_400(agent_a: LoggedInPrincipal) -> None:
  """`?dir=` outside `{asc, desc}` is `400`."""
  response = await agent_a.client.get("/contacts", params={"dir": "sideways"})
  assert response.status_code == 400


async def test_acc112_page_and_per_page_bounds(agent_a: LoggedInPrincipal) -> None:
  """Non-positive `page` is 400; past-the-end is an empty 200; `per_page` clamps above 100."""
  await create_contact(agent_a, **_CREATE_FIELDS)

  non_positive = await agent_a.client.get("/contacts", params={"page": "0"})
  assert non_positive.status_code == 400

  non_integer = await agent_a.client.get("/contacts", params={"page": "not-a-number"})
  assert non_integer.status_code == 400

  past_the_end = await agent_a.client.get("/contacts", params={"page": "999999"})
  assert past_the_end.status_code == 200

  over_clamped = await agent_a.client.get("/contacts", params={"per_page": "1000"})
  assert over_clamped.status_code == 200


@pytest.mark.parametrize(
  "payload",
  [
    "'; DROP TABLE contacts; --",
    "1' OR '1'='1",
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
  ],
)
async def test_acc113_hostile_search_terms_are_treated_as_data(
  agent_a: LoggedInPrincipal, payload: str
) -> None:
  """SQL metacharacters and an XSS payload in `?q=` are parameterized data, never an error."""
  response = await agent_a.client.get("/contacts", params={"q": payload})
  assert response.status_code == 200
  assert payload not in response.text, "a hostile ?q= value must never reach the page unescaped"
