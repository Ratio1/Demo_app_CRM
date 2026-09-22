"""R48 — pre-auth cleanup deletes up to 100 expired rows on every pre-auth insert.

Authority: ``contracts/slice-b.md`` §1(a) ("What this migration does **not**
add": *"the whole of R48 is therefore a statement-level delta in
`app/db/repositories/sessions.py`"*), §2(g) hook 1 (Slice A ruling R48
itself); ``ACCESS_MATRIX.md`` §1.2 row 26 (the pre-auth `INSERT` bounds).

**ID note.** `contracts/slice-b.md` §2(i) ask A-4 proposes **`SEC-077`**
for this behaviour ("R48 has no test id anywhere in `ACCESS_MATRIX.md`
§7"), but under ruling **R11** no lane may allocate a test id outside that
section's own register, and `ACCESS_MATRIX.md` §7 does not carry `SEC-077`
as of this write. This test is therefore written and run against the R48
*pin* directly; it is not yet citable by that number, and this file's name
avoids the ID for the same reason.

Why this lives in ``tests/inprocess``, not ``tests/concurrency``
-------------------------------------------------------------------
Proving "≥101 expired rows -> reclaims exactly 100, a live row survives"
needs many *already-expired* `sessions` rows in one batch: `PREAUTH_TTL` is
10 minutes, and — as the seeding half of this test demonstrates by
necessity — a *sequence* of real `GET /login` calls each advancing the
clock past that TTL cannot accumulate expired rows at all, because R48's
own cleanup fires on every single one of those inserts and sweeps the
prior (by-then-expired) row before the next call ever sees it. The only
way to observe the "up to 100" cap is to seed many expired rows directly
(as `insert_test_user_row` seeds `users`, ``tests/conftest.py``'s own
established pattern) and then trigger *one* real insert to watch the cap
apply. That direct seeding is DB-connection work, not HTTP-concurrency
work, and the one HTTP call this test makes needs a clock it can set to an
exact instant — which is `tests/inprocess`'s whole reason to exist, not
``tests/concurrency``'s.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import httpx
import pytest

if TYPE_CHECKING:
  from app.security.clock import ManualClock

pytestmark = pytest.mark.asyncio

#: Deliberately well past the "up to 100" cap, so the test proves the cap
#: itself rather than merely "cleanup deletes something".
_EXPIRED_ROW_COUNT = 150
_RECLAIM_CAP = 100


async def _seed_preauth_row(db_connection: Any, *, expires_at: Any, created_at: Any) -> None:
  """Insert one raw `sessions` row of `kind='pre_auth'`, `user_id IS NULL`.

  Mirrors ``conftest.insert_test_user_row``'s "raw SQL, test-only seeding"
  shape, at the repository boundary this suite already uses `db_connection`
  (the runtime role) for. `token_sha256`/`csrf_sha256` are unrelated random
  64-hex-character values — nothing here is ever a real credential, and
  the pre-auth row's CSRF state is not what this test exercises.

  Parameters
  ----------
  db_connection : psycopg.AsyncConnection
    The runtime-role connection (root ``conftest.py``'s `db_connection`).
  expires_at, created_at : datetime
    Bound directly; for a pre-auth row `idle_expires_at == absolute_expires_at`
    (`ACCESS_MATRIX.md` §1.2 row 26).
  """
  await db_connection.execute(
    "INSERT INTO sessions "
    "(id, token_sha256, csrf_sha256, kind, user_id, created_at, last_seen_at, "
    " idle_expires_at, absolute_expires_at) "
    "VALUES (%(id)s, %(token)s, %(csrf)s, 'pre_auth', NULL, %(created)s, %(created)s, "
    " %(expires)s, %(expires)s)",
    {
      "id": str(uuid.uuid4()),
      "token": secrets.token_hex(32),
      "csrf": secrets.token_hex(32),
      "created": created_at,
      "expires": expires_at,
    },
  )
  await db_connection.commit()


async def _count_preauth_rows(db_connection: Any) -> int:
  cursor = await db_connection.execute("SELECT count(*) FROM sessions WHERE kind = 'pre_auth'")
  row = await cursor.fetchone()
  assert row is not None
  return int(row[0])


async def test_r48_a_login_page_fetch_reclaims_up_to_100_expired_preauth_rows(
  in_process_client: httpx.AsyncClient, clock: ManualClock, db_connection: Any
) -> None:
  """150 pre-seeded expired rows + 1 live one; one `GET /login` reclaims exactly 100.

  Asserts three things together, because any one alone would be a weaker
  claim than the pin: (1) the total pre-auth row count drops by exactly
  ``100 - 1`` (100 reclaimed, 1 new row inserted) rather than "some";
  (2) a **live** (not-yet-expired) pre-auth row survives untouched — R48
  never reclaims a row that has not actually expired; (3) the response
  itself is an ordinary `200`, so cleanup riding along in the same
  transaction as the insert costs nothing visible to the caller.
  """
  now = clock.now()
  expired_at = now - timedelta(minutes=11)  # past PREAUTH_TTL (10 min)
  for _ in range(_EXPIRED_ROW_COUNT):
    await _seed_preauth_row(db_connection, expires_at=expired_at, created_at=expired_at)

  live_expires_at = now + timedelta(minutes=5)  # still well within PREAUTH_TTL
  await _seed_preauth_row(db_connection, expires_at=live_expires_at, created_at=now)

  before = await _count_preauth_rows(db_connection)
  assert before == _EXPIRED_ROW_COUNT + 1, (
    f"seeding must produce exactly {_EXPIRED_ROW_COUNT + 1} rows before the probed request, "
    f"got {before}"
  )

  # No cookie at all: this must be a genuine INSERT, never a reuse of the
  # seeded live row (ACCESS_MATRIX.md §1.2 row 26's reuse clause only
  # applies to a cookie the client actually presents).
  response = await in_process_client.get("/login")
  assert response.status_code == 200

  after = await _count_preauth_rows(db_connection)
  assert after == before - _RECLAIM_CAP + 1, (
    f"expected {before} - {_RECLAIM_CAP} reclaimed + 1 newly inserted = "
    f"{before - _RECLAIM_CAP + 1}, got {after}"
  )

  live_row_cursor = await db_connection.execute(
    "SELECT count(*) FROM sessions WHERE kind = 'pre_auth' AND absolute_expires_at = %(expires)s",
    {"expires": live_expires_at},
  )
  live_row = await live_row_cursor.fetchone()
  assert live_row is not None and live_row[0] == 1, (
    "the seeded LIVE pre-auth row must survive cleanup untouched"
  )
