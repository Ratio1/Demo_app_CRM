# Demo_App_CRM test suite

## Canonical invocation (ruling R52)

From `Demo_app_CRM`:

```bash
scripts/with-env .env.test.local -- .venv/bin/python -B -m pytest tests -p no:cacheprovider -q
```

This is the **only supported invocation**; a bare `pytest` is not. The suite process itself
runs as `crm_test_app` (the runtime role) so that `tests/security/test_sessions.py`'s
in-process, `ManualClock`-driven expiry tests (and every other test that requests the
`db_connection` fixture) can call `app.config.load_config()` and get real credentials from the
environment `scripts/with-env` populated — never from a value this suite reads or prints
itself. `-p no:cacheprovider` avoids writing a `.pytest_cache/` the suite does not need.

Owner-role steps inside the suite (schema reset and migration, `scripts/manage bootstrap` /
`create-user` / `disable-user`, and the throttle/budget table cleanup in
`tests/security/test_throttle_and_budget.py`) are each their own subprocess under
`.env.test.owner.local`, started by the test process — never by hand, and never by exporting
that role's credentials into the suite's own environment.

Credentials for both roles reach any process only through `scripts/with-env <env-file> --
<command>` (`AGENTS.md`); nothing under `tests/` ever opens `.env.test.local` or
`.env.test.owner.local` itself, and no fixture prints or asserts on a credential value.

## What each database role is for

| Env file | Role | Used for |
|---|---|---|
| `.env.test.local` | `crm_test_app` (runtime) | The suite process itself; every `live_server` subprocess; `db_connection`. |
| `.env.test.owner.local` | `crm_test_owner` | Schema reset/migration, every `scripts/manage` maintenance command, and this module's throttle/budget cleanup. |

Both point at the scratch database `crm_test`. `crm` (the real application database) is never
touched by this suite.

## Test isolation for throttle and budget (ruling R52)

`tests/security/test_throttle_and_budget.py` exercises the DB-shared, global login-throttle
and rate-budget counters (spec §6 S6) without weakening them: every test in that module targets
a freshly provisioned, dedicated `example.test` identifier — never the shared session admin —
and an `autouse` fixture clears `login_throttle` and `rate_budget` (owner role) both before and
after every test in the module, so a budget one test trips can never leak into another.

## Two transports (ruling R46)

- **In-process, repository-level** (`db_connection` + `clock`): drives `app.db.repositories.*`
  directly with an injected `ManualClock`, for expiry/revocation behaviour that would otherwise
  need a live wall-clock wait. `create_app`/`lifespan` have no clock or service injection point
  today, so this is the level at which Slice A's tests can actually be clock-driven; a full
  in-process `httpx.ASGITransport` fixture against the constructed app is `NOT VERIFIED` /
  blocked on that seam shipping in `app/main.py` (Backend lane), not something this directory
  can add on its own.
- **Out-of-process, one uvicorn subprocess per test** (`live_server`): every test that needs
  real HTTP/TLS behaviour (cookies, headers, redirects, CSRF, throttle/budget over the wire,
  `tests/e2e`) starts its own server on an ephemeral `127.0.0.1` port with a throwaway
  self-signed certificate; port `3002` (the human dev-run assignment) is never used by a test.

## `tests/e2e`

Needs Playwright's Chromium browser installed once: `.venv/bin/python -m playwright install
chromium`. `tests/e2e` is automatically collected and run **last** in a single `pytest tests`
invocation (see `conftest.py`'s `pytest_collection_modifyitems`), which avoids a known
`pytest-asyncio`/`pytest-playwright` event-loop interaction; it can also be run as its own,
separate invocation if a browser-less leg is wanted.
