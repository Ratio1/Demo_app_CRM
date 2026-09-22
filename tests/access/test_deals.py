"""Deal record and deal list/pipeline access control.

Every test drives the real HTTP surface over ``live_server`` (wire-level:
real cookies, real status codes, real headers) using the three-principal
fixtures ``tests/conftest.py`` defines (``admin``, ``agent_a``, ``agent_b``)
and the deal helpers added alongside them (``create_deal``,
``archive_contact``).

The reference-as-parent GET this file drives is the shipped
``GET /contacts/{contact_id}/deals/new`` path.

One test per cell where the cell is a single behaviour; a handful of cases
whose contract is inherently a pair (own vs. foreign, active vs. archived)
keep both cases in one test rather than splitting an atomic assertion,
mirroring ``test_contacts.py``'s own convention.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from conftest import (
  LoggedInPrincipal,
  ProvisionedUser,
  archive_contact,
  create_contact,
  create_deal,
  extract_csrf_token,
  extract_hidden_field,
  fresh_idempotency_key,
  login_via_http,
  normalize_body,
  normalized_headers,
)

pytestmark = pytest.mark.asyncio

#: A canonical-shaped id that names nothing — the "missing" half of every pair.
_MISSING_ID = "00000000-0000-4000-8000-000000000000"

_CONTACT_FIELDS = {
  "name": "Deal Test Contact",
  "company": "Northwind Traders",
  "phone": "+1 555 0201",
  "kind": "lead",
}


async def _forced_reset_client(http_client_factory: Any, provision_agent: Any) -> httpx.AsyncClient:
  """Log in a freshly provisioned agent but deliberately skip the forced password change.

  For the `FRST` actor cells: the returned client carries a full session
  whose `must_change_password` is still `TRUE`. Mirrors
  `tests/access/test_contacts.py`'s private helper of
  the same name and shape (each access module keeps its own copy, per
  that file's own convention).
  """
  user: ProvisionedUser = provision_agent()
  client: httpx.AsyncClient = http_client_factory()
  login_response = await login_via_http(client, email=user.email, password=user.password)
  assert login_response.status_code == 303
  assert login_response.headers.get("location") == "/account/password"
  return client


async def _own_contact(agent: LoggedInPrincipal) -> str:
  """Create a fresh, active contact owned by ``agent`` and return its id."""
  contact = await create_contact(agent, **_CONTACT_FIELDS)
  return contact.id


# ---------------------------------------------------------------------------
# Deal — read
# ---------------------------------------------------------------------------


async def test_owner_can_read_own_deal(agent_a: LoggedInPrincipal) -> None:
  """`AG-O` reading a deal under their own contact gets `200`."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  response = await agent_a.client.get(f"/deals/{deal.id}")
  assert response.status_code == 200


async def test_agent_cannot_read_foreign_deal(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """`AG-X` reading another agent's deal gets a `404` identical to a missing one."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  response = await agent_b.client.get(f"/deals/{deal.id}")
  assert response.status_code == 404


async def test_admin_can_read_any_deal(
  agent_a: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """`ADM` reads any agent's deal — the predicate short-circuits on `is_admin`."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  response = await admin.client.get(f"/deals/{deal.id}")
  assert response.status_code == 200


async def test_forced_reset_and_no_session_cannot_read_a_deal(
  http_client_factory: Any, provision_agent: Any, anon_client: httpx.AsyncClient
) -> None:
  """`FRST` gets `403` at step 2; `NOSESS` gets `303 /login...` at step 1."""
  forced_client = await _forced_reset_client(http_client_factory, provision_agent)
  forced_response = await forced_client.get(f"/deals/{_MISSING_ID}")
  assert forced_response.status_code == 403

  anon_response = await anon_client.get(f"/deals/{_MISSING_ID}")
  assert anon_response.status_code == 303
  assert anon_response.headers.get("location", "").split("?", 1)[0] == "/login"


# ---------------------------------------------------------------------------
# Deal — create
# ---------------------------------------------------------------------------


async def test_owner_can_create_under_own_active_contact(agent_a: LoggedInPrincipal) -> None:
  """`AG-O` creating a deal under their own, active contact gets a `303`."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  assert deal.contact_id == contact_id


async def test_admin_can_create_under_any_active_contact(
  agent_a: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """`ADM` creating a deal under an agent's active contact gets a `303` (admin short-circuit)."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(admin, contact_id=contact_id)
  assert deal.contact_id == contact_id


async def test_create_referencing_a_foreign_or_missing_contact_is_identical_404(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """A foreign `contact_id` and a missing one both answer `404`, byte-identical modulo the cid."""
  foreign_contact_id = await _own_contact(agent_a)

  foreign_form = await agent_b.client.get(f"/contacts/{foreign_contact_id}/deals/new")
  missing_form = await agent_b.client.get(f"/contacts/{_MISSING_ID}/deals/new")
  assert foreign_form.status_code == 404
  assert missing_form.status_code == 404
  assert normalize_body(foreign_form.text) == normalize_body(missing_form.text)
  assert normalized_headers(foreign_form) == normalized_headers(missing_form)

  # The POST half: a real CSRF token from agent_b's own, unrelated session
  # is enough to get past step 0/CSRF, so the 404 asserted below is the
  # parent-scope check's, never the CSRF gate's mistakenly standing in for it.
  own_form = await agent_b.client.get("/contacts/new")
  csrf_token = extract_csrf_token(own_form.text)
  foreign_post = await agent_b.client.post(
    f"/contacts/{foreign_contact_id}/deals",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": fresh_idempotency_key(),
      "title": "Should not be created",
      "amount": "100.00",
      "close_date": "",
    },
  )
  assert foreign_post.status_code == 404
  missing_post = await agent_b.client.post(
    f"/contacts/{_MISSING_ID}/deals",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": fresh_idempotency_key(),
      "title": "Should not be created",
      "amount": "100.00",
      "close_date": "",
    },
  )
  assert missing_post.status_code == 404


async def test_create_under_own_archived_contact_is_409_archived_parent(
  agent_a: LoggedInPrincipal,
) -> None:
  """`AG-O`/`ADM` creating a deal under their own **archived** contact gets `409`."""
  contact_id = await _own_contact(agent_a)
  archive_response = await archive_contact(agent_a, contact_id=contact_id)
  assert archive_response.status_code == 303

  new_form = await agent_a.client.get(f"/contacts/{contact_id}/deals/new")
  assert new_form.status_code == 409, "GET .../deals/new under an archived parent must be 409"

  post_response = await agent_a.client.post(
    f"/contacts/{contact_id}/deals",
    data={
      "csrf_token": "0" * 64,
      "idempotency_key": fresh_idempotency_key(),
      "title": "Should not be created",
      "amount": "100.00",
      "close_date": "",
    },
  )
  assert post_response.status_code in (403, 409), (
    "a CSRF-invalid POST under an archived parent may fail on CSRF first (403) or on the "
    f"archived-parent check (409) depending on gate order; got {post_response.status_code}"
  )


async def test_forced_reset_and_no_session_cannot_create(
  http_client_factory: Any, provision_agent: Any, anon_client: httpx.AsyncClient
) -> None:
  """`FRST` and `NOSESS` both get `403` creating a deal (steps 2 and 1 of the check order)."""
  forced_client = await _forced_reset_client(http_client_factory, provision_agent)
  forced_response = await forced_client.post(
    f"/contacts/{_MISSING_ID}/deals",
    data={
      "csrf_token": "0" * 64,
      "idempotency_key": fresh_idempotency_key(),
      "title": "x",
      "amount": "1.00",
      "close_date": "",
    },
  )
  assert forced_response.status_code == 403

  anon_response = await anon_client.post(
    f"/contacts/{_MISSING_ID}/deals",
    data={
      "csrf_token": "0" * 64,
      "idempotency_key": fresh_idempotency_key(),
      "title": "x",
      "amount": "1.00",
      "close_date": "",
    },
  )
  assert anon_response.status_code == 403, (
    "a session-less POST fails CSRF/no-session before any object is resolved"
  )


async def test_amount_out_of_bounds_is_400(agent_a: LoggedInPrincipal) -> None:
  """A negative amount, >2 decimal places, or a magnitude over `DECIMAL(12,2)` is `400`.

  The server-side `decimal.Decimal` pattern is the first and, for scale,
  the *only* line of defence — `DECIMAL(12,2)` rounds rather than
  rejecting a third decimal place.
  """
  contact_id = await _own_contact(agent_a)
  new_form = await agent_a.client.get(f"/contacts/{contact_id}/deals/new")
  assert new_form.status_code == 200
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")

  for bad_amount in ("-1.00", "1.005", "10000000000.00", "1,250.00", "abc", ""):
    response = await agent_a.client.post(
      f"/contacts/{contact_id}/deals",
      data={
        "csrf_token": csrf_token,
        "idempotency_key": idempotency_key,
        "title": "Bad amount deal",
        "amount": bad_amount,
        "close_date": "",
      },
    )
    assert response.status_code == 400, f"amount {bad_amount!r} should be rejected with 400"


async def test_unknown_or_non_writable_field_is_400(agent_a: LoggedInPrincipal) -> None:
  """A create/edit body carrying an unknown or non-writable field (e.g. `stage`) is `400`."""
  contact_id = await _own_contact(agent_a)
  new_form = await agent_a.client.get(f"/contacts/{contact_id}/deals/new")
  assert new_form.status_code == 200
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")

  response = await agent_a.client.post(
    f"/contacts/{contact_id}/deals",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "title": "Allowlist probe",
      "amount": "10.00",
      "close_date": "",
      "stage": "won",
    },
  )
  assert response.status_code == 400, "`stage` is not writable on create — a new deal is always new"


async def test_supplying_owner_id_on_create_is_400(agent_a: LoggedInPrincipal) -> None:
  """A create body carrying `owner_id` is `400` — no allowlist, no such column on `deals`."""
  contact_id = await _own_contact(agent_a)
  new_form = await agent_a.client.get(f"/contacts/{contact_id}/deals/new")
  assert new_form.status_code == 200
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")

  response = await agent_a.client.post(
    f"/contacts/{contact_id}/deals",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "title": "Owner injection probe",
      "amount": "10.00",
      "close_date": "",
      "owner_id": _MISSING_ID,
    },
  )
  assert response.status_code == 400


# ---------------------------------------------------------------------------
# Deal — edit
# ---------------------------------------------------------------------------


async def test_owner_can_edit_own_deal_at_the_current_version(
  agent_a: LoggedInPrincipal,
) -> None:
  """`AG-O`/`ADM` editing their own deal at the current version gets `303`."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  edit_form = await agent_a.client.get(f"/deals/{deal.id}/edit")
  assert edit_form.status_code == 200
  csrf_token = extract_csrf_token(edit_form.text)
  idempotency_key = extract_hidden_field(edit_form.text, "idempotency_key")
  version = extract_hidden_field(edit_form.text, "version")

  response = await agent_a.client.post(
    f"/deals/{deal.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      "title": "Renamed deal",
      "amount": "2000.00",
      "close_date": "",
    },
  )
  assert response.status_code == 303


async def test_agent_cannot_edit_foreign_deal(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """`AG-X` editing another agent's deal gets a `404` identical to a missing one."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  response = await agent_b.client.get(f"/deals/{deal.id}/edit")
  assert response.status_code == 404


async def test_edit_with_a_stale_version_is_409(agent_a: LoggedInPrincipal) -> None:
  """A submitted `version` that no longer matches the row is `409` (stale-edit recovery)."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  edit_form = await agent_a.client.get(f"/deals/{deal.id}/edit")
  csrf_token = extract_csrf_token(edit_form.text)
  idempotency_key = extract_hidden_field(edit_form.text, "idempotency_key")
  stale_version = extract_hidden_field(edit_form.text, "version")

  first = await agent_a.client.post(
    f"/deals/{deal.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": stale_version,
      "title": "First edit",
      "amount": "50.00",
      "close_date": "",
    },
  )
  assert first.status_code == 303

  second = await agent_a.client.post(
    f"/deals/{deal.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": fresh_idempotency_key(),
      "version": stale_version,
      "title": "Second edit, stale",
      "amount": "75.00",
      "close_date": "",
    },
  )
  assert second.status_code == 409


async def test_edit_under_an_archived_parent_is_409_archived_parent(
  agent_a: LoggedInPrincipal,
) -> None:
  """Editing a deal whose parent contact is now archived gets `409`, not `303`."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  archive_response = await archive_contact(agent_a, contact_id=contact_id)
  assert archive_response.status_code == 303

  edit_form = await agent_a.client.get(f"/deals/{deal.id}/edit")
  assert edit_form.status_code == 409, "the edit form GET itself must answer 409 archived_parent"


async def test_editing_contact_id_is_400(agent_a: LoggedInPrincipal) -> None:
  """A crafted edit body carrying `contact_id` is `400` — the parent is immutable after create."""
  contact_id = await _own_contact(agent_a)
  other_contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  edit_form = await agent_a.client.get(f"/deals/{deal.id}/edit")
  csrf_token = extract_csrf_token(edit_form.text)
  idempotency_key = extract_hidden_field(edit_form.text, "idempotency_key")
  version = extract_hidden_field(edit_form.text, "version")

  response = await agent_a.client.post(
    f"/deals/{deal.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      "title": "Reparenting attempt",
      "amount": "10.00",
      "close_date": "",
      "contact_id": other_contact_id,
    },
  )
  assert response.status_code == 400


# ---------------------------------------------------------------------------
# Deal — stage change
# ---------------------------------------------------------------------------


async def test_a_valid_lateral_transition_is_303(agent_a: LoggedInPrincipal) -> None:
  """A lateral stage move (`new` -> `qualified`) under an own active parent gets `303`."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  detail = await agent_a.client.get(f"/deals/{deal.id}")
  assert detail.status_code == 200
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  version = extract_hidden_field(detail.text, "version")

  response = await agent_a.client.post(
    f"/deals/{deal.id}/stage",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      "to_stage": "qualified",
    },
  )
  assert response.status_code == 303


async def test_stage_change_to_the_current_stage_is_400(agent_a: LoggedInPrincipal) -> None:
  """Posting `to_stage` equal to the deal's current stage is `400` — a no-op earns no receipt."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  detail = await agent_a.client.get(f"/deals/{deal.id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  version = extract_hidden_field(detail.text, "version")

  response = await agent_a.client.post(
    f"/deals/{deal.id}/stage",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      "to_stage": "new",
    },
  )
  assert response.status_code == 400


async def test_stage_change_out_of_a_terminal_stage_is_409(
  agent_a: LoggedInPrincipal,
) -> None:
  """Moving a `won` deal to any other stage is `409 stage_terminal`."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  detail = await agent_a.client.get(f"/deals/{deal.id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  version = extract_hidden_field(detail.text, "version")
  won_response = await agent_a.client.post(
    f"/deals/{deal.id}/won",
    data={"csrf_token": csrf_token, "idempotency_key": idempotency_key, "version": version},
  )
  assert won_response.status_code == 303

  after_won = await agent_a.client.get(f"/deals/{deal.id}")
  assert after_won.status_code == 200
  new_csrf = extract_csrf_token(after_won.text)
  # A TERMINAL deal renders no stage control at all, so no `version`
  # hidden field is scrapable here — the move to `won` is known
  # to bump `version` 1 -> 2 (every accepted mutation does), so that is
  # used directly rather than trying to scrape a field the page no longer
  # carries.
  new_version = "2"
  reopen_response = await agent_a.client.post(
    f"/deals/{deal.id}/stage",
    data={
      "csrf_token": new_csrf,
      "idempotency_key": fresh_idempotency_key(),
      "version": new_version,
      "to_stage": "qualified",
    },
  )
  assert reopen_response.status_code == 409


async def test_agent_cannot_move_a_foreign_deals_stage(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """`AG-X` posting a stage change to another agent's deal is `404`, identical to a missing one."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  # A REAL CSRF token from agent_b's own session (minted off an unrelated
  # form that is certain to carry one): a wrong token would answer 403 at
  # the CSRF gate (step 0/1), which runs before the object-scope check
  # this cell is actually about, and would mask it under test.
  own_form = await agent_b.client.get("/contacts/new")
  csrf_token = extract_csrf_token(own_form.text)
  response = await agent_b.client.post(
    f"/deals/{deal.id}/stage",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": fresh_idempotency_key(),
      "version": "1",
      "to_stage": "qualified",
    },
  )
  assert response.status_code == 404


async def test_stage_change_under_an_archived_parent_is_409(
  agent_a: LoggedInPrincipal,
) -> None:
  """A stage change on a deal whose parent is now archived gets `409 archived_parent`."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  detail = await agent_a.client.get(f"/deals/{deal.id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_hidden_field(detail.text, "idempotency_key")
  version = extract_hidden_field(detail.text, "version")

  archive_response = await archive_contact(agent_a, contact_id=contact_id)
  assert archive_response.status_code == 303

  response = await agent_a.client.post(
    f"/deals/{deal.id}/stage",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      "to_stage": "qualified",
    },
  )
  assert response.status_code == 409


async def test_forced_reset_and_no_session_cannot_change_stage(
  http_client_factory: Any, provision_agent: Any, anon_client: httpx.AsyncClient
) -> None:
  """`FRST` and `NOSESS` both get `403` posting a stage change."""
  forced_client = await _forced_reset_client(http_client_factory, provision_agent)
  forced_response = await forced_client.post(
    f"/deals/{_MISSING_ID}/stage",
    data={
      "csrf_token": "0" * 64,
      "idempotency_key": fresh_idempotency_key(),
      "version": "1",
      "to_stage": "qualified",
    },
  )
  assert forced_response.status_code == 403

  anon_response = await anon_client.post(
    f"/deals/{_MISSING_ID}/stage",
    data={
      "csrf_token": "0" * 64,
      "idempotency_key": fresh_idempotency_key(),
      "version": "1",
      "to_stage": "qualified",
    },
  )
  assert anon_response.status_code == 403


# ---------------------------------------------------------------------------
# Deal — routes that structurally do not exist
# ---------------------------------------------------------------------------


async def test_no_archive_or_restore_route_exists_for_a_deal(
  agent_a: LoggedInPrincipal,
) -> None:
  """`POST /deals/{id}/archive` and `/restore` are `404` — a deal has no archive route."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  for action in ("archive", "restore"):
    response = await agent_a.client.post(
      f"/deals/{deal.id}/{action}",
      data={"csrf_token": "0" * 64, "idempotency_key": fresh_idempotency_key(), "version": "1"},
    )
    assert response.status_code == 404


async def test_no_direct_reassign_route_exists_for_a_deal(
  agent_a: LoggedInPrincipal,
) -> None:
  """`POST /deals/{id}/reassign` is `404` — ownership moves only with the parent contact."""
  contact_id = await _own_contact(agent_a)
  deal = await create_deal(agent_a, contact_id=contact_id)
  response = await agent_a.client.post(
    f"/deals/{deal.id}/reassign",
    data={
      "csrf_token": "0" * 64,
      "idempotency_key": fresh_idempotency_key(),
      "version": "1",
      "owner_id": _MISSING_ID,
    },
  )
  assert response.status_code == 404


# ---------------------------------------------------------------------------
# Deal — duplicate submission, sequential HTTP-level cases; the true
# concurrent races live in tests/concurrency/test_deals_concurrency.py.
# ---------------------------------------------------------------------------


async def test_duplicate_submission_same_key_and_payload_replays(
  agent_a: LoggedInPrincipal,
) -> None:
  """Resubmitting the identical create (same key, same payload) replays the `303`; no new row."""
  contact_id = await _own_contact(agent_a)
  new_form = await agent_a.client.get(f"/contacts/{contact_id}/deals/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  payload = {
    "csrf_token": csrf_token,
    "idempotency_key": idempotency_key,
    "title": "Replay probe",
    "amount": "10.00",
    "close_date": "",
  }
  first = await agent_a.client.post(f"/contacts/{contact_id}/deals", data=payload)
  second = await agent_a.client.post(f"/contacts/{contact_id}/deals", data=payload)
  assert first.status_code == 303
  assert second.status_code == 303
  assert first.headers.get("location") == second.headers.get("location")


async def test_same_key_different_payload_is_409_duplicate(
  agent_a: LoggedInPrincipal,
) -> None:
  """The same idempotency key with a different payload is `409 duplicate`."""
  contact_id = await _own_contact(agent_a)
  new_form = await agent_a.client.get(f"/contacts/{contact_id}/deals/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  first = await agent_a.client.post(
    f"/contacts/{contact_id}/deals",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "title": "Original payload",
      "amount": "10.00",
      "close_date": "",
    },
  )
  assert first.status_code == 303

  second = await agent_a.client.post(
    f"/contacts/{contact_id}/deals",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "title": "Different payload",
      "amount": "20.00",
      "close_date": "",
    },
  )
  assert second.status_code == 409


# ---------------------------------------------------------------------------
# Deal — the reference-as-parent GET
# ---------------------------------------------------------------------------


async def test_deals_new_with_a_foreign_or_missing_parent_is_identical_404(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """`GET .../deals/new` with a foreign or missing `contact_id` is `404`, one code path."""
  foreign_contact_id = await _own_contact(agent_a)
  foreign_response = await agent_b.client.get(f"/contacts/{foreign_contact_id}/deals/new")
  missing_response = await agent_b.client.get(f"/contacts/{_MISSING_ID}/deals/new")
  assert foreign_response.status_code == 404
  assert missing_response.status_code == 404
  assert normalize_body(foreign_response.text) == normalize_body(missing_response.text)


async def test_deals_new_under_an_own_archived_parent_is_409(
  agent_a: LoggedInPrincipal,
) -> None:
  """`GET /contacts/{id}/deals/new` under an own, now-archived parent is `409`, never the 404."""
  contact_id = await _own_contact(agent_a)
  archive_response = await archive_contact(agent_a, contact_id=contact_id)
  assert archive_response.status_code == 303
  response = await agent_a.client.get(f"/contacts/{contact_id}/deals/new")
  assert response.status_code == 409


async def test_deals_new_echoes_only_the_permitted_parent_attributes(
  agent_a: LoggedInPrincipal,
) -> None:
  """The pre-filled form echoes only what `GET /contacts/{id}` already permitted this caller.

  The shipped route only ever echoes `contact {id, full_name}` — a strict
  subset of the parent's fields, never more. This asserts what is
  actually frozen: `full_name` is echoed, and nothing from another
  principal's data ever is.
  """
  contact = await create_contact(agent_a, **_CONTACT_FIELDS)
  contact_detail = await agent_a.client.get(f"/contacts/{contact.id}")
  assert contact_detail.status_code == 200

  new_form = await agent_a.client.get(f"/contacts/{contact.id}/deals/new")
  assert new_form.status_code == 200
  assert _CONTACT_FIELDS["name"] in new_form.text


async def test_malformed_contact_id_on_deals_new_is_400(agent_a: LoggedInPrincipal) -> None:
  """A `contact_id` that is not a canonical 36-character UUID is `400`, never a 404."""
  response = await agent_a.client.get("/contacts/not-a-uuid/deals/new")
  assert response.status_code == 400


# ---------------------------------------------------------------------------
# Identical-404 across every deal surface (the same byte-identical-404
# rule re-run over the five deal surfaces plus a non-canonical id).
# ---------------------------------------------------------------------------


async def test_identical_404_across_every_deal_surface(agent_b: LoggedInPrincipal) -> None:
  """Detail, edit, update, stage, won and lost each answer the byte-identical 404 for a bad id."""
  non_canonical = "not-a-uuid"
  surfaces: list[tuple[str, str]] = [
    ("GET", f"/deals/{_MISSING_ID}"),
    ("GET", f"/deals/{_MISSING_ID}/edit"),
  ]
  bodies: list[str] = []
  headers_list: list[dict[str, str]] = []
  for method, path in surfaces:
    response = await agent_b.client.request(method, path)
    assert response.status_code == 404
    bodies.append(normalize_body(response.text))
    headers_list.append(normalized_headers(response))
  assert len(set(bodies)) == 1, "every deal-surface 404 body must be byte-identical modulo the cid"
  assert len(set(map(str, headers_list))) == 1

  non_canonical_response = await agent_b.client.get(f"/deals/{non_canonical}")
  assert non_canonical_response.status_code == 404
  assert normalize_body(non_canonical_response.text) == bodies[0]


# ---------------------------------------------------------------------------
# Deal — list / pipeline
# ---------------------------------------------------------------------------


async def test_owner_sees_only_own_deals_with_correct_aggregates(
  agent_a: LoggedInPrincipal,
) -> None:
  """`AG-O` lists and pipelines show only their own rows, with SQL-computed per-stage aggregates."""
  contact_id = await _own_contact(agent_a)
  await create_deal(agent_a, contact_id=contact_id, title="Deal Alpha", amount="100.00")
  await create_deal(agent_a, contact_id=contact_id, title="Deal Beta", amount="250.50")

  list_response = await agent_a.client.get("/deals")
  assert list_response.status_code == 200
  assert "Deal Alpha" in list_response.text
  assert "Deal Beta" in list_response.text

  pipeline_response = await agent_a.client.get("/deals/pipeline")
  assert pipeline_response.status_code == 200


async def test_foreign_deals_are_simply_absent_not_403_or_404(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """`AG-X`'s list/pipeline never 403s or 404s — the foreign rows are simply not in the results."""
  contact_id = await _own_contact(agent_a)
  await create_deal(agent_a, contact_id=contact_id, title="Owner-only deal alpha7")

  list_response = await agent_b.client.get("/deals")
  assert list_response.status_code == 200
  assert "Owner-only deal alpha7" not in list_response.text

  pipeline_response = await agent_b.client.get("/deals/pipeline")
  assert pipeline_response.status_code == 200


async def test_admin_sees_all_deals(agent_a: LoggedInPrincipal, admin: LoggedInPrincipal) -> None:
  """`ADM` lists every agent's deals (admin short-circuit)."""
  contact_id = await _own_contact(agent_a)
  await create_deal(agent_a, contact_id=contact_id, title="Admin-visible deal beta9")

  response = await admin.client.get("/deals")
  assert response.status_code == 200
  assert "Admin-visible deal beta9" in response.text


async def test_forced_reset_and_no_session_cannot_list_deals(
  http_client_factory: Any, provision_agent: Any, anon_client: httpx.AsyncClient
) -> None:
  """`FRST` gets `403`; `NOSESS` gets `303 /login...` listing deals."""
  forced_client = await _forced_reset_client(http_client_factory, provision_agent)
  forced_response = await forced_client.get("/deals")
  assert forced_response.status_code == 403

  anon_response = await anon_client.get("/deals")
  assert anon_response.status_code == 303
  assert anon_response.headers.get("location", "").split("?", 1)[0] == "/login"


async def test_deals_under_archived_contacts_are_hidden_by_default(
  agent_a: LoggedInPrincipal,
) -> None:
  """A deal under an archived contact drops out of the default (`status=active`) list."""
  contact_id = await _own_contact(agent_a)
  await create_deal(agent_a, contact_id=contact_id, title="Soon-archived-parent deal")
  archive_response = await archive_contact(agent_a, contact_id=contact_id)
  assert archive_response.status_code == 303

  default_list = await agent_a.client.get("/deals")
  assert default_list.status_code == 200
  assert "Soon-archived-parent deal" not in default_list.text

  archived_list = await agent_a.client.get("/deals?status=archived")
  assert archived_list.status_code == 200
  assert "Soon-archived-parent deal" in archived_list.text

  all_list = await agent_a.client.get("/deals?status=all")
  assert all_list.status_code == 200
  assert "Soon-archived-parent deal" in all_list.text


async def test_sort_and_dir_outside_the_allowlist_are_400(
  agent_a: LoggedInPrincipal,
) -> None:
  """`?sort=` or `?dir=` outside the five-key/two-direction allowlist is `400`."""
  bad_sort = await agent_a.client.get("/deals?sort=owner_id")
  assert bad_sort.status_code == 400
  bad_dir = await agent_a.client.get("/deals?sort=title&dir=sideways")
  assert bad_dir.status_code == 400


async def test_stage_filter_outside_the_five_stages_is_400(
  agent_a: LoggedInPrincipal,
) -> None:
  """`?stage=` outside `{new, qualified, proposal, won, lost}` is `400`."""
  response = await agent_a.client.get("/deals?stage=archived")
  assert response.status_code == 400


async def test_per_page_and_page_abuse_is_clamped_not_rejected(
  agent_a: LoggedInPrincipal,
) -> None:
  """`?per_page=` above 100 is clamped to 100, not rejected; a non-positive value is `400`."""
  clamped = await agent_a.client.get("/deals?per_page=999")
  assert clamped.status_code == 200

  bad_per_page = await agent_a.client.get("/deals?per_page=0")
  assert bad_per_page.status_code == 400

  bad_page = await agent_a.client.get("/deals?page=0")
  assert bad_page.status_code == 400
