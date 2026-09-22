"""The runtime role's live grant set, table by table.

The runtime role's grant set matches the data contract **exactly**, table
by table, read from `information_schema.table_privileges` — every expected
privilege present and **no unexpected one**, so an over-grant fails the
test — plus the live negatives: no `UPDATE`/`DELETE` on `audit_events`, no
write to `app_settings`, no `INSERT` into `users`, no `DELETE` on
`contacts` or `mutation_receipts`.

Runs entirely through ``db_connection`` — the suite process's own runtime
role (``crm_test_app``, per ``tests/README.md``) — so every assertion below
is the **live** grant this role actually holds today, never a value this
suite reads or prints from an env file. Every table this migration chain
has created is asserted against its expected grant row.
"""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

pytestmark = pytest.mark.asyncio

#: The expected grant set, restricted to the tables that exist in
#: `crm_test`. `activities` holds **SELECT and INSERT only**: immutability
#: is the absence of `UPDATE` and `DELETE` on the runtime role, not a
#: missing route. `deals`'s three privileges and no `DELETE` are the exact
#: grant its migration applies — "a deal is never deleted by the
#: application" is what makes the *absence* of the privilege load-bearing,
#: not a convention.
_EXPECTED_TABLE_GRANTS: dict[str, frozenset[str]] = {
  "users": frozenset({"SELECT", "UPDATE"}),
  "sessions": frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"}),
  "login_throttle": frozenset({"SELECT", "INSERT", "UPDATE"}),
  "rate_budget": frozenset({"SELECT", "INSERT", "UPDATE"}),
  "audit_events": frozenset({"INSERT", "SELECT"}),
  "app_settings": frozenset({"SELECT"}),
  "schema_migrations": frozenset({"SELECT"}),
  "mutation_receipts": frozenset({"SELECT", "INSERT"}),
  "contacts": frozenset({"SELECT", "INSERT", "UPDATE"}),
  "deals": frozenset({"SELECT", "INSERT", "UPDATE"}),
  "activities": frozenset({"SELECT", "INSERT"}),
}

#: Tables the data contract describes that this migration chain has not
#: created. Empty today: every table in the contract now exists, so there
#: is nothing left to assert absent.
_NOT_YET_SHIPPED_TABLES: frozenset[str] = frozenset()


async def _live_table_grants(db_connection: Any) -> dict[str, frozenset[str]]:
  """Return ``{table_name: {privilege_type, ...}}`` for the connected role, `public` schema only."""
  cursor = await db_connection.execute(
    "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
    "WHERE grantee = current_user AND table_schema = 'public'"
  )
  rows = await cursor.fetchall()
  grants: dict[str, set[str]] = {}
  for table_name, privilege_type in rows:
    grants.setdefault(str(table_name), set()).add(str(privilege_type))
  return {table: frozenset(privileges) for table, privileges in grants.items()}


async def test_live_grant_set_for_crm_test_app_equals_the_data_contract(
  db_connection: Any,
) -> None:
  """The runtime role's live table-level grants equal the data contract, table by table.

  Both directions: every expected privilege is present, and no unexpected
  one is — an over-grant (e.g. a stray `DELETE` on `contacts`) fails this
  exactly as a missing one would.
  """
  live = await _live_table_grants(db_connection)

  for table in _NOT_YET_SHIPPED_TABLES:
    assert table not in live, (
      f"{table!r} must not exist (or be granted) in crm_test yet; got grants {live.get(table)}"
    )

  for table, expected in _EXPECTED_TABLE_GRANTS.items():
    actual = live.get(table, frozenset())
    assert actual == expected, (
      f"table {table!r}: expected exactly {sorted(expected)}, got {sorted(actual)} "
      f"(missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)})"
    )

  # Not vacuous: the live set must not be missing a whole table's row —
  # information_schema returns nothing for a table this role cannot see at
  # all, which would otherwise read as "zero privileges, zero expected"
  # for a table that was silently dropped from the schema.
  assert set(_EXPECTED_TABLE_GRANTS) <= set(live), (
    f"table(s) with no information_schema.role_table_grants row at all: "
    f"{sorted(set(_EXPECTED_TABLE_GRANTS) - set(live))}"
  )


async def test_schema_public_usage_only_never_create(db_connection: Any) -> None:
  """`schema public` grants `USAGE` only — never `CREATE`."""
  cursor = await db_connection.execute(
    "SELECT has_schema_privilege(current_user, 'public', 'USAGE'), "
    "has_schema_privilege(current_user, 'public', 'CREATE')"
  )
  row = await cursor.fetchone()
  assert row is not None
  has_usage, has_create = row
  assert has_usage is True, "the runtime role must hold USAGE on schema public"
  assert has_create is False, "the runtime role must never hold CREATE on schema public"


async def _assert_refused_with_42501(db_connection: Any, sql: str) -> None:
  """Run ``sql`` and assert it fails with exactly `insufficient_privilege` (`42501`).

  Wrapped in its own transaction/savepoint (`conn.transaction()`) so one
  refused probe does not poison the connection for the next: PostgreSQL
  aborts the surrounding transaction on any error, and this module runs
  several probes over the one function-scoped `db_connection`.
  """
  with pytest.raises(psycopg.Error) as exc_info:
    async with db_connection.transaction():
      await db_connection.execute(sql)
  assert exc_info.value.sqlstate == "42501", (
    f"expected insufficient_privilege (42501) for {sql!r}, got {exc_info.value.sqlstate!r}: "
    f"{exc_info.value}"
  )


async def test_no_delete_on_contacts(db_connection: Any) -> None:
  """The runtime role holds no `DELETE` on `contacts` — archive is the only removal."""
  await _assert_refused_with_42501(
    db_connection, "DELETE FROM contacts WHERE id = '00000000-0000-4000-8000-000000000000'"
  )


async def test_no_delete_on_mutation_receipts(db_connection: Any) -> None:
  """No `DELETE` on `mutation_receipts` — write-once, cleanup is maintenance-only."""
  await _assert_refused_with_42501(
    db_connection,
    "DELETE FROM mutation_receipts WHERE id = '00000000-0000-4000-8000-000000000000'",
  )


async def test_no_update_on_mutation_receipts(db_connection: Any) -> None:
  """No `UPDATE` on `mutation_receipts` — a stored outcome is never rewritten."""
  await _assert_refused_with_42501(
    db_connection,
    "UPDATE mutation_receipts SET result_status = 'updated' "
    "WHERE id = '00000000-0000-4000-8000-000000000000'",
  )


async def test_no_update_or_delete_on_audit_events(db_connection: Any) -> None:
  """`INSERT`/`SELECT` on `audit_events` only — never `UPDATE`/`DELETE`."""
  await _assert_refused_with_42501(
    db_connection,
    "UPDATE audit_events SET outcome = 'success' WHERE id = '00000000-0000-4000-8000-000000000000'",
  )
  await _assert_refused_with_42501(
    db_connection, "DELETE FROM audit_events WHERE id = '00000000-0000-4000-8000-000000000000'"
  )


async def test_no_write_to_app_settings(db_connection: Any) -> None:
  """The runtime role holds `SELECT` on `app_settings` only — the origin is read, never written."""
  await _assert_refused_with_42501(
    db_connection, "UPDATE app_settings SET value = 'https://evil.example.test' WHERE key = 'x'"
  )
  await _assert_refused_with_42501(
    db_connection, "INSERT INTO app_settings (key, value) VALUES ('x', 'y')"
  )


async def test_no_insert_into_users(db_connection: Any) -> None:
  """The runtime role holds no `INSERT` on `users` — account creation is CLI-only."""
  await _assert_refused_with_42501(
    db_connection, "INSERT INTO users (id) VALUES ('00000000-0000-4000-8000-000000000000')"
  )


async def test_no_delete_on_deals(db_connection: Any) -> None:
  """The runtime role holds no `DELETE` on `deals` — a deal is never deleted by the application.

  Deletion exists only in `reset-demo` and `erase-subject`, under the
  maintenance role — the absence of the privilege here is what makes "no
  deal disappears" structural.
  """
  await _assert_refused_with_42501(
    db_connection, "DELETE FROM deals WHERE id = '00000000-0000-4000-8000-000000000000'"
  )


async def test_no_update_on_activities(db_connection: Any) -> None:
  """The runtime role holds no `UPDATE` on `activities` — a live negative probe, not a grant read.

  The activities migration grants `SELECT, INSERT` only — this is what
  makes "once logged, an activity cannot be edited" a privilege of the
  database, exercised here with an actual `UPDATE` rather than only read
  from `information_schema` as the table-grant test above already does.
  """
  await _assert_refused_with_42501(
    db_connection,
    "UPDATE activities SET summary = 'tampered' WHERE id = '00000000-0000-4000-8000-000000000000'",
  )


async def test_no_delete_on_activities(db_connection: Any) -> None:
  """The runtime role holds no `DELETE` on `activities` — a live negative probe.

  The append-only history is enforced by the grant set, never by a missing
  route: `42501` fires even though the target row does not exist, because
  the engine refuses the privilege before it ever looks for the row.
  """
  await _assert_refused_with_42501(
    db_connection, "DELETE FROM activities WHERE id = '00000000-0000-4000-8000-000000000000'"
  )
