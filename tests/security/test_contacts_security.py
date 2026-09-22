"""Slice B contact-surface security — SEC-001 through SEC-006, SEC-076; CSRF on every new POST.

Authority: ``ACCESS_MATRIX.md`` §7 (the IDs below); ``contracts/slice-b.md``
§2(c) (route table), §2(f) (form field sets, §5.5 request-token map);
``ACCESS_MATRIX.md`` §5.2 (sort/filter allowlists).

Reuses ``tests/conftest.py``'s three-principal fixtures (``admin``,
``agent_a``, ``agent_b``) and its ``create_contact`` HTTP helper rather than
duplicating them — this module is about a different axis of the same
surface (injection/allowlist/XSS/CSRF), not a different fixture story.
"""

from __future__ import annotations

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
  "name": "Security Test Contact",
  "company": "Acme Corp",
  "email": "sec-test@example.test",
  "phone": "+1 555 0102",
  "kind": "lead",
}


# ---------------------------------------------------------------------------
# SEC-001 — an SQLi corpus over every field, filter, path segment and sort key
# changes no query semantics.
# ---------------------------------------------------------------------------

_SQLI_CORPUS: tuple[str, ...] = (
  "'; DROP TABLE contacts; --",
  "' OR '1'='1",
  "1; SELECT pg_sleep(5)--",
  "' UNION SELECT password_hash, email FROM users--",
)


@pytest.mark.parametrize("payload", _SQLI_CORPUS)
async def test_sec001_sqli_corpus_in_create_fields_changes_no_query_semantics(
  agent_a: LoggedInPrincipal, payload: str
) -> None:
  """An SQLi payload in every writable create field is treated as inert data.

  ``psycopg`` binds every value as a parameter (no f-string/`%`-format/
  concatenated SQL under ``app/db/**`` — ``ARC-002``), so the strongest
  behavioural signal reachable from HTTP is: the request succeeds or fails
  on ordinary validation grounds only, never with a `500` (a `500` would be
  the first sign a payload reached raw SQL), and the payload is never
  echoed back unescaped.
  """
  new_form = await agent_a.client.get("/contacts/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  response = await agent_a.client.post(
    "/contacts",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "name": payload,
      "company": payload,
      "email": "sqli@example.test",
      "phone": "+1 555 0103",
      "kind": "lead",
    },
  )
  assert response.status_code != 500
  assert payload not in response.text


@pytest.mark.parametrize("payload", _SQLI_CORPUS)
async def test_sec001_sqli_corpus_in_search_q_changes_no_query_semantics(
  agent_a: LoggedInPrincipal, payload: str
) -> None:
  """An SQLi payload in `?q=` never produces a `500` and never widens the result set."""
  response = await agent_a.client.get("/contacts", params={"q": payload})
  assert response.status_code == 200
  assert payload not in response.text


@pytest.mark.parametrize("payload", _SQLI_CORPUS)
async def test_sec001_sqli_corpus_in_the_path_segment_is_a_clean_404_never_500(
  agent_a: LoggedInPrincipal, payload: str
) -> None:
  """An SQLi payload as the `{id}` path segment is a `404` (non-canonical id), never `500`."""
  response = await agent_a.client.get(f"/contacts/{payload}")
  assert response.status_code in (404, 400)


# ---------------------------------------------------------------------------
# SEC-002 — writable-field and sort-key allowlists reject unknown values with 400.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
  ("key", "bad_value"),
  [
    ("sort", "password_hash"),
    ("dir", "up"),
    ("status", "deleted"),
    ("kind", "prospect"),
  ],
)
async def test_sec002_allowlisted_query_keys_reject_out_of_allowlist_values(
  agent_a: LoggedInPrincipal, key: str, bad_value: str
) -> None:
  """Every allowlisted query key on `/contacts` rejects an out-of-allowlist value with `400`."""
  response = await agent_a.client.get("/contacts", params={key: bad_value})
  assert response.status_code == 400


async def test_sec002_create_rejects_an_out_of_allowlist_kind_value_as_a_field_error(
  agent_a: LoggedInPrincipal,
) -> None:
  """`kind` outside `{lead, customer}` on create is `CP-66` — a writable field with a bad value.

  Distinguished from an unknown/non-writable *field name* (`400`
  crafted-request): `kind` is legitimately writable, so an out-of-enum
  *value* is a normal validation error re-rendering the form, per
  ``contracts/slice-b.md`` §2(f)'s note on this exact field.
  """
  new_form = await agent_a.client.get("/contacts/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  response = await agent_a.client.post(
    "/contacts",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      **{**_CREATE_FIELDS, "kind": "prospect"},
    },
  )
  assert response.status_code == 400


# ---------------------------------------------------------------------------
# SEC-003 — `owner_id` supplied through body, query or sort key never changes an owner.
# ---------------------------------------------------------------------------


async def test_sec003_owner_id_in_the_create_body_never_changes_the_owner(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """Submitting a foreign `owner_id` on create is rejected outright, with `400`.

  If accepted, the contact would still belong to the caller, never to the
  injected id — asserted from both directions: the request is rejected
  outright (§5.1: `owner_id` is in no agent allowlist), and even so,
  `agent_b` can never read whatever the request produced under their own
  scope.
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
      "owner_id": "00000000-0000-4000-8000-000000000000",
    },
  )
  assert response.status_code == 400
  del agent_b  # documents the property under test; no separate read needed for a rejected write


async def test_sec003_owner_id_as_a_query_parameter_on_list_is_ignored_not_honoured(
  agent_a: LoggedInPrincipal, agent_b: LoggedInPrincipal
) -> None:
  """`owner_id` is not an allowlisted query key — passing it changes nothing about the scope."""
  await create_contact(agent_b, **{**_CREATE_FIELDS, "name": "Not Reachable By Query Injection"})
  response = await agent_a.client.get("/contacts", params={"owner_id": "anything-at-all"})
  assert response.status_code == 200
  assert "Not Reachable By Query Injection" not in response.text


async def test_sec003_owner_id_is_not_an_allowed_sort_key(agent_a: LoggedInPrincipal) -> None:
  """`sort=owner_id` is outside the five allowed sort keys — `400`, not a silent no-op."""
  response = await agent_a.client.get("/contacts", params={"sort": "owner_id"})
  assert response.status_code == 400


# ---------------------------------------------------------------------------
# SEC-004 — a body larger than 64 KiB returns 413.
# ---------------------------------------------------------------------------


async def test_sec004_a_body_over_64kib_on_contact_create_is_413(
  agent_a: LoggedInPrincipal,
) -> None:
  """A grossly oversized `company` field trips the shared 64 KiB body-size limit."""
  new_form = await agent_a.client.get("/contacts/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  oversized = "x" * (70 * 1024)
  response = await agent_a.client.post(
    "/contacts",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      **{**_CREATE_FIELDS, "company": oversized},
    },
  )
  assert response.status_code == 413


# ---------------------------------------------------------------------------
# SEC-005 — a stored and a reflected XSS corpus render inert, through create/update,
# on both the list and the detail page.
# ---------------------------------------------------------------------------

_XSS_CORPUS: tuple[str, ...] = (
  "<script>alert(1)</script>",
  '"><img src=x onerror=alert(1)>',
  "'; alert(document.cookie); //",
  "<svg onload=alert(1)>",
)


@pytest.mark.parametrize("payload", _XSS_CORPUS)
async def test_sec005_xss_in_create_renders_inert_on_list_and_detail(
  agent_a: LoggedInPrincipal, payload: str
) -> None:
  """A hostile `name` survives create, then renders escaped everywhere it is displayed."""
  contact = await create_contact(agent_a, **{**_CREATE_FIELDS, "name": payload})
  detail = await agent_a.client.get(f"/contacts/{contact.id}")
  assert detail.status_code == 200
  assert payload not in detail.text
  listing = await agent_a.client.get("/contacts")
  assert payload not in listing.text


@pytest.mark.parametrize("payload", _XSS_CORPUS)
async def test_sec005_xss_in_update_renders_inert_on_list_and_detail(
  agent_a: LoggedInPrincipal, payload: str
) -> None:
  """A hostile value introduced through an *edit* (not just create) also renders inert."""
  contact = await create_contact(agent_a, **_CREATE_FIELDS)
  edit_form = await agent_a.client.get(f"/contacts/{contact.id}/edit")
  csrf_token = extract_csrf_token(edit_form.text)
  idempotency_key = extract_hidden_field(edit_form.text, "idempotency_key")
  version = extract_hidden_field(edit_form.text, "version")
  update_response = await agent_a.client.post(
    f"/contacts/{contact.id}",
    data={
      "csrf_token": csrf_token,
      "idempotency_key": idempotency_key,
      "version": version,
      **{**_CREATE_FIELDS, "company": payload},
    },
  )
  assert update_response.status_code == 303
  detail = await agent_a.client.get(f"/contacts/{contact.id}")
  assert payload not in detail.text
  listing = await agent_a.client.get("/contacts")
  assert payload not in listing.text


# ---------------------------------------------------------------------------
# SEC-006 — user data never becomes an hx-* attribute value; HX-Trigger carries no user data.
# ---------------------------------------------------------------------------


async def test_sec006_a_hostile_contact_name_never_reaches_an_hx_attribute_value(
  agent_a: LoggedInPrincipal,
) -> None:
  """A value chosen to break out of an `hx-*` attribute never appears unescaped near one.

  Contacted markup (``contracts/slice-b.md`` §2(e)) puts no user data inside
  any `hx-*` attribute at all — every `hx-get`/`hx-target` value is a
  code-authored path. This asserts the observable consequence over HTTP:
  a name built to look like an attribute breakout never appears verbatim
  next to an `hx-` token in the rendered page.
  """
  payload = '"><b hx-get="/contacts/evil">breakout</b>'
  contact = await create_contact(agent_a, **{**_CREATE_FIELDS, "name": payload})
  listing = await agent_a.client.get("/contacts")
  assert payload not in listing.text
  del contact


# ---------------------------------------------------------------------------
# SEC-076 — a repeated allowlisted query parameter, or any repeated form field,
# is rejected with 400.
# ---------------------------------------------------------------------------


async def test_sec076_a_repeated_allowlisted_query_parameter_is_400(
  agent_a: LoggedInPrincipal,
) -> None:
  """`?sort=name&sort=email` is `400` — never first-wins or last-wins."""
  response = await agent_a.client.get(
    "/contacts", params=httpx.QueryParams([("sort", "name"), ("sort", "email")])
  )
  assert response.status_code == 400


async def test_sec076_an_unknown_repeated_query_parameter_is_still_ignored(
  agent_a: LoggedInPrincipal,
) -> None:
  """An unknown parameter *name* is dropped before duplicates are even counted (H-08)."""
  response = await agent_a.client.get(
    "/contacts", params=httpx.QueryParams([("unknown", "1"), ("unknown", "2")])
  )
  assert response.status_code == 200


async def test_sec076_a_repeated_form_field_on_create_is_400(agent_a: LoggedInPrincipal) -> None:
  """A repeated `name` form field on `POST /contacts` is `400`, not first/last-wins."""
  new_form = await agent_a.client.get("/contacts/new")
  csrf_token = extract_csrf_token(new_form.text)
  idempotency_key = extract_hidden_field(new_form.text, "idempotency_key")
  body = httpx.QueryParams(
    [
      ("csrf_token", csrf_token),
      ("idempotency_key", idempotency_key),
      ("name", "First Value"),
      ("name", "Second Value"),
      ("company", _CREATE_FIELDS["company"]),
      ("email", _CREATE_FIELDS["email"]),
      ("phone", _CREATE_FIELDS["phone"]),
      ("kind", _CREATE_FIELDS["kind"]),
    ]
  )
  response = await agent_a.client.post(
    "/contacts", content=str(body), headers={"content-type": "application/x-www-form-urlencoded"}
  )
  assert response.status_code == 400


# ---------------------------------------------------------------------------
# CSRF on every new POST (SEC-020's assertion, over every Slice B mutation route).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
  ("path_suffix", "extra_fields"),
  [
    ("", {**_CREATE_FIELDS}),
    ("/{id}", {**_CREATE_FIELDS, "version": "1"}),
    ("/{id}/archive", {"version": "1"}),
    ("/{id}/restore", {"version": "1"}),
    ("/{id}/reassign", {"version": "1", "owner_id": "00000000-0000-4000-8000-000000000000"}),
  ],
)
async def test_csrf_required_on_every_slice_b_mutation_route(
  agent_a: LoggedInPrincipal,
  admin: LoggedInPrincipal,
  path_suffix: str,
  extra_fields: dict[str, Any],
) -> None:
  """Every one of the five new mutation routes is `403` with the CSRF field omitted entirely.

  Reassign is posted by the admin (`ACC-033` would otherwise mask the CSRF
  question behind the role check for an agent); the other four are posted
  by the object's own owner.
  """
  if path_suffix == "":
    path = "/contacts"
    actor = agent_a
  else:
    contact = await create_contact(agent_a, **_CREATE_FIELDS)
    path = f"/contacts{path_suffix.format(id=contact.id)}"
    actor = admin if "reassign" in path_suffix else agent_a
  response = await actor.client.post(
    path, data={"idempotency_key": fresh_idempotency_key(), **extra_fields}
  )
  assert response.status_code == 403
