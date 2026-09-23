# Demo_App_CRM test suite

## Canonical invocation

From `Demo_app_CRM`:

```bash
scripts/with-env .env.test.local -- .venv/bin/python -B -m pytest tests -p no:cacheprovider -q
```

This is the **only supported invocation**; a bare `pytest` is not. The suite process itself
runs as `crm_test_app` (the runtime role) so that `tests/security/test_sessions.py`'s
in-process, `ManualClock`-driven expiry tests, `tests/inprocess`'s whole-app in-process tests,
and every other test that requests the `db_connection` fixture can call
`app.config.load_config()` and get real credentials from the environment `scripts/with-env`
populated — never from a value this suite reads or prints itself. `-p no:cacheprovider` avoids
writing a `.pytest_cache/` the suite does not need.

`crm_test` is reset and migrated by one session-scoped, **autouse** fixture
(`conftest.crm_test_schema`) that runs before the first test in the session,
whichever test that is — this invocation is equally runnable starting from a freshly created,
unmigrated `crm_test` or from one left dirty by a previous run.

Owner-role steps inside the suite (schema reset and migration, `scripts/manage bootstrap` /
`create-user` / `disable-user` / `set-origin`, and both throttle/budget-clearing autouse
fixtures) are each their own subprocess under `.env.test.owner.local`, started by the test
process — never by hand, and never by exporting that role's credentials into the suite's own
environment.

Credentials for both roles reach any process only through `scripts/with-env <env-file> --
<command>`; nothing under `tests/` ever opens `.env.test.local` or
`.env.test.owner.local` itself, and no fixture prints or asserts on a credential value.

## What each database role is for

| Env file | Role | Used for |
|---|---|---|
| `.env.test.local` | `crm_test_app` (runtime) | The suite process itself; `live_server`; `db_connection`; `tests/inprocess`'s `in_process_app`. |
| `.env.test.owner.local` | `crm_test_owner` | Schema reset/migration, every `scripts/manage` maintenance command, and both throttle/budget-clearing autouse fixtures (`test_throttle_and_budget.py`, `tests/inprocess`). |

Both point at the scratch database `crm_test`. `crm` (the real application database) is never
touched by this suite.

## Test isolation for throttle and budget

`tests/security/test_throttle_and_budget.py` and `tests/inprocess/test_throttle_and_budget_windows.py`
exercise the DB-shared, global login-throttle and rate-budget counters without
weakening them: every test in either module targets a freshly provisioned, dedicated
`example.test` identifier — never the shared session admin — and each module's own `autouse`
fixture clears `login_throttle` and `rate_budget` (owner role, via
`conftest.clear_throttle_and_budget_state`) both before and after every test, so a budget one
test trips can never leak into another.

## Three transports

- **In-process, repository-level** (`db_connection` + `clock`): drives `app.db.repositories.*`
  directly with an injected `ManualClock`, for expiry/revocation behaviour a test can drive by
  an explicit `now` parameter without needing a request at all.
- **In-process, through the whole ASGI app** (`tests/inprocess`, `in_process_app` /
  `in_process_client`): `create_app` takes a `clock`/`password_hasher` injection
  seam, so a test can drive the real route table — middleware, CSRF, sessions, throttle, the
  lot — through `httpx.ASGITransport` with a `ManualClock` it advances by hand, entering the
  lifespan with `async with app.router.lifespan_context(app):`. This is the transport every
  clock-dependent, wire-observable assertion belongs on: pre-auth/idle/absolute session expiry,
  the login lock's recovery, and the global pre-auth budget's trip-and-recovery all live here
  now, because none of them can be proved over a real wall clock without either sleeping or
  risking a `:00`-boundary flake. Its origin is the fixed
  `https://crm.test` (never `live_server`'s ephemeral port) — see
  `tests/inprocess/conftest.py`'s module docstring for why, and why `tests/inprocess` is
  collected **first** in the session (`conftest.py`'s `pytest_collection_modifyitems`). The
  process itself always serves plain HTTP; it is the *stored* origin's scheme, and nothing
  else, that decides the session cookie's name/`Secure` flag and whether
  `Strict-Transport-Security` is sent (`app.security.sessions`, `app.security.headers`). Since
  `live_server` below now serves the `http://` half of that contract, `tests/inprocess` is also
  the one remaining place in this suite with an `https://` origin, and is where that half
  (`Secure`, the `__Host-` cookie name, HSTS) is proved — `in_process_client`
  (`https://crm.test`, the default above) alongside a second, independent client,
  `http_mode_in_process_client` (`http://crm.test`), both exercised in
  `tests/inprocess/test_origin_scheme.py`.
- **Out-of-process, one uvicorn subprocess per *session*** (`live_server`):
  every test that needs genuinely wire-level behaviour (real cookie attributes, real header
  casing, `tests/e2e`) shares **one** server for the whole session, in plain HTTP on an
  ephemeral `127.0.0.1` port; port `3002` (the human dev-run assignment) is never used by a
  test. The process serves plain HTTP — no certificate of any kind, dev or otherwise, the same
  as the shipped application, which never terminates TLS itself (a Cloudflare, or equivalent,
  terminator in front of it does in production). `live_server`'s clock is the real, production
  `SystemClock` and cannot be swapped — nothing driven through it can be clock-tested; that is
  what `tests/inprocess` exists for. Isolation between the tests that share it is by data
  (dedicated `example.test` identities, never the shared `bootstrap_admin`, for anything that
  mutates account-scoped or global state) and by targeted owner-role cleanup, not by a fresh
  process per test.

## Collection order (`conftest.py`'s `pytest_collection_modifyitems`)

```
[tests/inprocess]  ->  [everything else]  ->  [tests/e2e]  ->  [test_demo_seed_and_reset.py]
  ->  [test_last_admin_race.py]  ->  [test_migration_journal.py]
```

Six buckets, for these reasons, in that order:

1. `tests/inprocess` first, so its `manage set-origin --origin https://crm.test` always runs
   before `live_server` is ever constructed and repoints the same stored origin to its own
   ephemeral port — no toggling back and forth is needed either way.
2. Everything else, unordered relative to itself except as the entries below pull specific
   items out of it.
3. `tests/e2e` after everything else: at least one of its items sets up pytest-playwright's
   session-scoped fixtures, and once that has happened in a session, `pytest-asyncio`'s
   `asyncio.Runner.run()` can fail or silently drop a coroutine for every *later* async test.
   Ordering it last among the async buckets removes the corruption for the single, literal
   `pytest tests` invocation.
4. `tests/concurrency/test_demo_seed_and_reset.py` after `tests/e2e`: its `reset-demo --yes`
   deletes every contact, deal, activity, receipt, session and throttle/budget row in the shared
   `crm_test`, other modules' fixture data included, so nothing that still expects that data may
   run after it.
5. `tests/concurrency/test_last_admin_race.py` after `test_demo_seed_and_reset.py`: its own
   module-scoped fixture resets and re-migrates `crm_test` from scratch and bootstraps two
   admins of its own, which would otherwise wipe the shared `bootstrap_admin`/`crm_test_schema`
   state every other module's `live_server`/`db_connection` fixture depends on. Placing it this
   late means nothing else in *this* session needs that state afterward; the *next* session's
   `crm_test_schema` (autouse) absorbs whatever it leaves behind.
6. `tests/concurrency/test_migration_journal.py` absolute last, after even
   `test_last_admin_race.py`: its from-empty-migrate test drops and recreates the whole `public` schema
   directly to prove a from-empty `migrate`, one wipe further out than reason 5's. A
   module-scoped, autouse fixture there also runs one more `migrate` at teardown as a second
   line of defence, and the *next* session's `crm_test_schema` absorbs whatever is left either
   way.

## `tests/e2e`

Needs Playwright's Chromium browser installed once: `.venv/bin/python -m playwright install
chromium`. Automatically collected and run after everything else except the three data-wiping
modules that follow it in a single `pytest tests` invocation — see "Collection order" above —
which avoids a known `pytest-asyncio`/`pytest-playwright` event-loop interaction; it can also be
run as its own, separate invocation if a browser-less leg is wanted.
