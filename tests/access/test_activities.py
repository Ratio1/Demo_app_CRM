"""``POST /activities`` and the ``#timeline`` region.

Every test drives the real HTTP surface over ``live_server`` using the
three-principal fixtures ``tests/conftest.py`` defines (``admin``,
``agent_a``, ``agent_b``) and the activity helper added alongside them
(``create_activity``). Ownership lives on the **parent** contact (there is
no ``owner_id`` on ``activities`` at all), so every "own vs foreign" case
below is really "own vs foreign *contact*".
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import pytest
from conftest import (
  LoggedInPrincipal,
  ProvisionedUser,
  archive_contact,
  create_activity,
  create_contact,
  extract_csrf_token,
  extract_scoped_hidden_field,
  fresh_idempotency_key,
  login_via_http,
  normalize_body,
  normalized_headers,
)

from app.services.activities import (
  ACTIVITY_KIND_REQUIRED_MESSAGE,
  DATE_MALFORMED_MESSAGE,
  KIND_LABELS,
  SUMMARY_MAX,
  SUMMARY_REQUIRED_MESSAGE,
  SUMMARY_TOO_LONG_MESSAGE,
)

pytestmark = pytest.mark.asyncio

#: A canonical-shaped id that names nothing — the "missing" half of every pair.
_MISSING_ID = "00000000-0000-4000-8000-000000000000"

_CONTACT_FIELDS = {
  "name": "Activity Test Contact",
  "company": "Northwind Traders",
  "phone": "+1 555 0301",
  "kind": "lead",
}


async def _forced_reset_client(http_client_factory: Any, provision_agent: Any) -> httpx.AsyncClient:
  """Log in a freshly provisioned agent but skip the forced password change.

  Mirrors ``tests/access/test_contacts.py``'s and ``tests/access/test_deals.py``'s
  private helper of the same name and shape.
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


def _activity_post_body(
  *,
  csrf_token: str,
  idempotency_key: str,
  contact_id: str,
  kind: str,
  occurred_on: str,
  summary: str,
) -> dict[str, str]:
  return {
    "csrf_token": csrf_token,
    "idempotency_key": idempotency_key,
    "contact_id": contact_id,
    "kind": kind,
    "occurred_on": occurred_on,
    "summary": summary,
  }


# ---------------------------------------------------------------------------
# own / foreign / missing / archived parent.
# ---------------------------------------------------------------------------


async def test_own_active_contact_gets_303_to_the_timeline(agent_a: LoggedInPrincipal) -> None:
  """`AG-O` logging an activity against their own, active contact gets `303 #timeline`."""
  contact_id = await _own_contact(agent_a)
  activity = await create_activity(agent_a, contact_id=contact_id, summary="First contact call.")
  assert activity.contact_id == contact_id


async def test_admin_can_log_activity_on_any_active_contact(
  agent_a: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """`ADM` logging against an agent's active contact succeeds (admin short-circuit)."""
  contact_id = await _own_contact(agent_a)
  activity = await create_activity(admin, contact_id=contact_id, summary="Admin follow-up note.")
  assert activity.contact_id == contact_id


async def test_foreign_and_missing_contact_are_identical_404(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """A foreign `contact_id` and a missing one both answer `404`, byte-identical modulo the cid."""
  foreign_contact_id = await _own_contact(agent_a)

  own_form = await agent_b.client.get("/contacts/new")
  csrf_token = extract_csrf_token(own_form.text)

  foreign_post = await agent_b.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=fresh_idempotency_key(),
      contact_id=foreign_contact_id,
      kind="note",
      occurred_on="2026-09-15",
      summary="Should not be created.",
    ),
  )
  missing_post = await agent_b.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=fresh_idempotency_key(),
      contact_id=_MISSING_ID,
      kind="note",
      occurred_on="2026-09-15",
      summary="Should not be created.",
    ),
  )
  assert foreign_post.status_code == 404
  assert missing_post.status_code == 404
  assert normalize_body(foreign_post.text) == normalize_body(missing_post.text)
  assert normalized_headers(foreign_post) == normalized_headers(missing_post)


async def test_archived_parent_is_409_archived_parent(agent_a: LoggedInPrincipal) -> None:
  """Logging an activity under an own, now-archived contact gets `409 archived_parent`."""
  contact_id = await _own_contact(agent_a)
  archive_response = await archive_contact(agent_a, contact_id=contact_id)
  assert archive_response.status_code == 303

  own_form = await agent_a.client.get("/contacts/new")
  csrf_token = extract_csrf_token(own_form.text)
  response = await agent_a.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=fresh_idempotency_key(),
      contact_id=contact_id,
      kind="note",
      occurred_on="2026-09-15",
      summary="Should not be created.",
    ),
  )
  assert response.status_code == 409


async def test_non_canonical_contact_id_in_body_is_400(agent_a: LoggedInPrincipal) -> None:
  """A `contact_id` that is not a canonical 36-character UUID is `400` — a crafted body."""
  own_form = await agent_a.client.get("/contacts/new")
  csrf_token = extract_csrf_token(own_form.text)
  response = await agent_a.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=fresh_idempotency_key(),
      contact_id="not-a-uuid",
      kind="note",
      occurred_on="2026-09-15",
      summary="Should not be created.",
    ),
  )
  assert response.status_code == 400


async def test_forced_reset_and_no_session_cannot_log_activity(
  http_client_factory: Any, provision_agent: Any, anon_client: httpx.AsyncClient
) -> None:
  """`FRST` gets `403`; a session-less `POST` also gets `403` (CSRF/no-session first)."""
  forced_client = await _forced_reset_client(http_client_factory, provision_agent)
  forced_response = await forced_client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token="0" * 64,
      idempotency_key=fresh_idempotency_key(),
      contact_id=_MISSING_ID,
      kind="note",
      occurred_on="2026-09-15",
      summary="x",
    ),
  )
  assert forced_response.status_code == 403

  anon_response = await anon_client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token="0" * 64,
      idempotency_key=fresh_idempotency_key(),
      contact_id=_MISSING_ID,
      kind="note",
      occurred_on="2026-09-15",
      summary="x",
    ),
  )
  assert anon_response.status_code == 403


# ---------------------------------------------------------------------------
# CSRF (checked before the body allowlist, per app/routes/pipeline.py).
# ---------------------------------------------------------------------------


async def test_wrong_csrf_token_is_403(agent_a: LoggedInPrincipal) -> None:
  """A well-formed but wrong CSRF token is refused with `403`, never a field 400."""
  contact_id = await _own_contact(agent_a)
  response = await agent_a.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token="f" * 64,
      idempotency_key=fresh_idempotency_key(),
      contact_id=contact_id,
      kind="note",
      occurred_on="2026-09-15",
      summary="Should not be created.",
    ),
  )
  assert response.status_code == 403


async def test_missing_csrf_field_is_403(agent_a: LoggedInPrincipal) -> None:
  """A body carrying no `csrf_token` at all is `403` (CSRF runs before the field allowlist)."""
  contact_id = await _own_contact(agent_a)
  body = _activity_post_body(
    csrf_token="irrelevant",
    idempotency_key=fresh_idempotency_key(),
    contact_id=contact_id,
    kind="note",
    occurred_on="2026-09-15",
    summary="Should not be created.",
  )
  del body["csrf_token"]
  response = await agent_a.client.post("/activities", data=body)
  assert response.status_code == 403


# ---------------------------------------------------------------------------
# summary bounds: 0 / 1 / 1000 / 1001 (ck_activities_summary is 1..1000).
# ---------------------------------------------------------------------------


async def test_summary_bounds_0_1_1000_1001(agent_a: LoggedInPrincipal) -> None:
  """An empty summary and one over 1000 characters are `400`; 1 and 1000 are `303`."""
  contact_id = await _own_contact(agent_a)
  detail = await agent_a.client.get(f"/contacts/{contact_id}")
  csrf_token = extract_csrf_token(detail.text)

  empty = await agent_a.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=fresh_idempotency_key(),
      contact_id=contact_id,
      kind="note",
      occurred_on="2026-09-15",
      summary="",
    ),
  )
  assert empty.status_code == 400
  assert SUMMARY_REQUIRED_MESSAGE in empty.text

  over = await agent_a.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=fresh_idempotency_key(),
      contact_id=contact_id,
      kind="note",
      occurred_on="2026-09-15",
      summary="a" * (SUMMARY_MAX + 1),
    ),
  )
  assert over.status_code == 400
  assert SUMMARY_TOO_LONG_MESSAGE in over.text

  one_char = await agent_a.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=fresh_idempotency_key(),
      contact_id=contact_id,
      kind="note",
      occurred_on="2026-09-15",
      summary="x",
    ),
  )
  assert one_char.status_code == 303

  exactly_max = await agent_a.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=fresh_idempotency_key(),
      contact_id=contact_id,
      kind="note",
      occurred_on="2026-09-15",
      summary="a" * SUMMARY_MAX,
    ),
  )
  assert exactly_max.status_code == 303


async def test_whitespace_only_summary_is_400_empty(agent_a: LoggedInPrincipal) -> None:
  """A summary of nothing but whitespace strips to empty — `400`, not a row of blanks."""
  contact_id = await _own_contact(agent_a)
  detail = await agent_a.client.get(f"/contacts/{contact_id}")
  csrf_token = extract_csrf_token(detail.text)
  response = await agent_a.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=fresh_idempotency_key(),
      contact_id=contact_id,
      kind="note",
      occurred_on="2026-09-15",
      summary="   \n\t  ",
    ),
  )
  assert response.status_code == 400
  assert SUMMARY_REQUIRED_MESSAGE in response.text


async def test_malformed_date_is_400(agent_a: LoggedInPrincipal) -> None:
  """An `occurred_on` that is not `yyyy-mm-dd` is `400`, never coerced."""
  contact_id = await _own_contact(agent_a)
  detail = await agent_a.client.get(f"/contacts/{contact_id}")
  csrf_token = extract_csrf_token(detail.text)
  response = await agent_a.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=fresh_idempotency_key(),
      contact_id=contact_id,
      kind="note",
      occurred_on="15/09/2026",
      summary="Malformed date probe.",
    ),
  )
  assert response.status_code == 400
  assert DATE_MALFORMED_MESSAGE in response.text


# ---------------------------------------------------------------------------
# kind allowlist: exactly note/call/email/meeting.
# ---------------------------------------------------------------------------


async def test_kind_outside_the_allowlist_is_400(agent_a: LoggedInPrincipal) -> None:
  """A `kind` outside the four allowed values is `400`."""
  contact_id = await _own_contact(agent_a)
  detail = await agent_a.client.get(f"/contacts/{contact_id}")
  csrf_token = extract_csrf_token(detail.text)
  for bad_kind in ("visit", "Note", "NOTE", "", "call;drop table activities"):
    response = await agent_a.client.post(
      "/activities",
      data=_activity_post_body(
        csrf_token=csrf_token,
        idempotency_key=fresh_idempotency_key(),
        contact_id=contact_id,
        kind=bad_kind,
        occurred_on="2026-09-15",
        summary="Kind allowlist probe.",
      ),
    )
    assert response.status_code == 400, f"kind {bad_kind!r} should be rejected with 400"
    assert ACTIVITY_KIND_REQUIRED_MESSAGE in response.text


@pytest.mark.parametrize("kind", sorted(KIND_LABELS))
async def test_every_allowlisted_kind_is_accepted(agent_a: LoggedInPrincipal, kind: str) -> None:
  """Each of the four allowlisted kinds is accepted with `303`."""
  contact_id = await _own_contact(agent_a)
  activity = await create_activity(
    agent_a, contact_id=contact_id, kind=kind, summary=f"A fictional {kind} entry."
  )
  assert activity.contact_id == contact_id


# ---------------------------------------------------------------------------
# duplicate submission (sequential HTTP-level).
# ---------------------------------------------------------------------------


async def test_duplicate_submission_same_key_and_payload_replays(
  agent_a: LoggedInPrincipal,
) -> None:
  """Resubmitting the identical create (same key, same payload) replays the `303`."""
  contact_id = await _own_contact(agent_a)
  detail = await agent_a.client.get(f"/contacts/{contact_id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_scoped_hidden_field(
    detail.text, form_action="/activities", name="idempotency_key"
  )
  payload = _activity_post_body(
    csrf_token=csrf_token,
    idempotency_key=idempotency_key,
    contact_id=contact_id,
    kind="call",
    occurred_on="2026-09-15",
    summary="Replay probe.",
  )
  first = await agent_a.client.post("/activities", data=payload)
  second = await agent_a.client.post("/activities", data=payload)
  assert first.status_code == 303
  assert second.status_code == 303
  assert first.headers.get("location") == second.headers.get("location")


async def test_same_key_different_payload_is_409_duplicate(agent_a: LoggedInPrincipal) -> None:
  """The same idempotency key with a different payload is `409 duplicate`."""
  contact_id = await _own_contact(agent_a)
  detail = await agent_a.client.get(f"/contacts/{contact_id}")
  csrf_token = extract_csrf_token(detail.text)
  idempotency_key = extract_scoped_hidden_field(
    detail.text, form_action="/activities", name="idempotency_key"
  )
  first = await agent_a.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=idempotency_key,
      contact_id=contact_id,
      kind="call",
      occurred_on="2026-09-15",
      summary="Original payload.",
    ),
  )
  assert first.status_code == 303

  second = await agent_a.client.post(
    "/activities",
    data=_activity_post_body(
      csrf_token=csrf_token,
      idempotency_key=idempotency_key,
      contact_id=contact_id,
      kind="call",
      occurred_on="2026-09-15",
      summary="Different payload.",
    ),
  )
  assert second.status_code == 409


# ---------------------------------------------------------------------------
# timeline: scoped, paginated, and dual-rendered (fragment vs. whole page).
# ---------------------------------------------------------------------------


async def test_timeline_is_scoped_like_every_other_contact_surface(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal, admin: LoggedInPrincipal
) -> None:
  """`AG-X` gets `404` on another agent's timeline; `ADM` gets `200`; own gets `200`."""
  contact_id = await _own_contact(agent_a)
  await create_activity(agent_a, contact_id=contact_id, summary="Owner-only activity delta1.")

  own_response = await agent_a.client.get(f"/contacts/{contact_id}/timeline")
  assert own_response.status_code == 200
  assert "Owner-only activity delta1." in own_response.text

  foreign_response = await agent_b.client.get(f"/contacts/{contact_id}/timeline")
  assert foreign_response.status_code == 404

  admin_response = await admin.client.get(f"/contacts/{contact_id}/timeline")
  assert admin_response.status_code == 200
  assert "Owner-only activity delta1." in admin_response.text


async def test_timeline_shows_only_its_own_contacts_activities(agent_a: LoggedInPrincipal) -> None:
  """Two contacts owned by the same agent never leak activities into each other's timeline."""
  first_contact = await _own_contact(agent_a)
  second_contact = await create_contact(
    agent_a, **{**_CONTACT_FIELDS, "name": "Second Activity Contact"}
  )
  await create_activity(agent_a, contact_id=first_contact, summary="Only on the first contact.")
  await create_activity(
    agent_a, contact_id=second_contact.id, summary="Only on the second contact."
  )

  first_timeline = await agent_a.client.get(f"/contacts/{first_contact}/timeline")
  assert "Only on the first contact." in first_timeline.text
  assert "Only on the second contact." not in first_timeline.text

  second_timeline = await agent_a.client.get(f"/contacts/{second_contact.id}/timeline")
  assert "Only on the second contact." in second_timeline.text
  assert "Only on the first contact." not in second_timeline.text


#: `partials/pagination.html`'s exact literal text, en dash and all — built
#: from its code point rather than typed as a glyph, so ruff's `RUF001`
#: (ambiguous unicode character) never flags this file.
_EN_DASH = chr(0x2013)
_PAGINATION_SUMMARY_PATTERN = re.compile(r"Showing (\d+)" + _EN_DASH + r"(\d+) of (\d+)")


def _pagination_summary(html: str) -> str | None:
  match = _PAGINATION_SUMMARY_PATTERN.search(html)
  return None if match is None else match.group(0)


async def test_timeline_pagination_ten_per_page(agent_a: LoggedInPrincipal) -> None:
  """Eleven activities page at ten per page, newest first, with a second page of one."""
  contact_id = await _own_contact(agent_a)
  for index in range(11):
    await create_activity(
      agent_a,
      contact_id=contact_id,
      summary=f"Timeline pagination entry {index:02d}.",
      occurred_on=f"2026-09-{(index % 27) + 1:02d}",
    )

  page_one = await agent_a.client.get(f"/contacts/{contact_id}/timeline")
  assert page_one.status_code == 200
  assert _pagination_summary(page_one.text) == f"Showing 1{_EN_DASH}10 of 11"

  page_two = await agent_a.client.get(f"/contacts/{contact_id}/timeline", params={"page": "2"})
  assert page_two.status_code == 200
  assert _pagination_summary(page_two.text) == f"Showing 11{_EN_DASH}11 of 11"

  bad_zero = await agent_a.client.get(f"/contacts/{contact_id}/timeline", params={"page": "0"})
  assert bad_zero.status_code == 400

  bad_text = await agent_a.client.get(f"/contacts/{contact_id}/timeline", params={"page": "abc"})
  assert bad_text.status_code == 400

  bad_repeated = await agent_a.client.get(f"/contacts/{contact_id}/timeline?page=1&page=2")
  assert bad_repeated.status_code == 400


async def test_timeline_fragment_vs_full_render(agent_a: LoggedInPrincipal) -> None:
  """`HX-Request: true` gets the bare `#timeline` fragment; anything else gets the whole page."""
  contact_id = await _own_contact(agent_a)
  await create_activity(agent_a, contact_id=contact_id, summary="Dual-render probe.")

  full = await agent_a.client.get(f"/contacts/{contact_id}/timeline")
  assert full.status_code == 200
  assert "<!doctype html>" in full.text.lower()
  assert 'id="timeline"' in full.text

  fragment = await agent_a.client.get(
    f"/contacts/{contact_id}/timeline", headers={"HX-Request": "true"}
  )
  assert fragment.status_code == 200
  assert "<!doctype html>" not in fragment.text.lower()
  assert 'id="timeline"' in fragment.text

  history_restore = await agent_a.client.get(
    f"/contacts/{contact_id}/timeline",
    headers={"HX-Request": "true", "HX-History-Restore-Request": "true"},
  )
  assert history_restore.status_code == 200
  assert "<!doctype html>" in history_restore.text.lower()
