# Demo_App_CRM

A minimalistic CRM MVP: contacts, a five-stage deal pipeline, per-contact activity timelines, and
ownership-scoped dashboard totals. It runs as one Docker image, `demo-crm-app:local`, against the
shared local PostgreSQL over `verify-full` TLS — no compose file, no sidecar, no volumes. Stack:
FastAPI + Jinja2, server-rendered (htmx 2.0.10 only enhances idempotent `GET` reads — every
mutation is a plain form `POST`), psycopg3 + psycopg-pool, uvicorn.

## Prerequisites

- Docker Desktop running. The container reaches the database at `host.docker.internal`, which
  Docker Desktop resolves automatically; not guaranteed on plain Linux Docker.
- Shared local PostgreSQL: `_tools/pgsql/pg ensure`, then once (idempotent) `_tools/pgsql/pg
  create-app crm`.
- `uv` — for local development only (see Development below); the image itself never invokes it.

Commands below assume a working directory that contains `_tools/pgsql` (see Prerequisites)
unless a section says otherwise.

## 1. Credentials

Two env files, five variables in force (`DB_SERVER`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`;
`DB_PORT` is the optional fifth and is not written by `pg env` — the port travels inside
`DB_SERVER` as `host:port`). Both are git-ignored: never commit, print, or read them with
`cat`/`grep`.

```
_tools/pgsql/pg env crm --server host.docker.internal:5432 --write Demo_app_CRM/.env.docker.local
_tools/pgsql/pg env crm --role owner --server host.docker.internal:5432 --write Demo_app_CRM/.env.docker.owner.local
```

The first (`crm_app`, runtime role) is what `scripts/run-local` (see Run below) hands the
served container; the second (`crm_owner`, maintenance role) is what every `scripts/manage`
command below needs.

## 2. Build

```
Demo_app_CRM/scripts/build-image
```

Copies the shared PostgreSQL CA's certificate to `app/certs/ca-bundle.pem` (the `verify-full`
trust anchor), generates a self-signed `127.0.0.1` development certificate once (git-ignored,
reused on later builds), then `docker build -t demo-crm-app:local --target runtime .`. The image
holds no `.env*` file, no `.git`, and no source outside `app/`, `migrations/`, `scripts/`. When
`../_tools/pgsql/pg` is not present (a standalone clone, outside the meta-repo checkout), pass a
CA certificate PEM path as the script's first argument, or set `CA_CERT`, instead.

## 3. Provision, from the same image

Every `scripts/manage` command is maintenance-only and runs as the owner role — use the **owner**
env file for all three below:

```
docker run --rm --env-file Demo_app_CRM/.env.docker.owner.local demo-crm-app:local scripts/manage migrate
```

Create the first administrator. `--email`/`--name`/`--origin` are flags, not prompts; only the
password is asked for, hidden — add `-it` for a real terminal (`--password-stdin` reads one
stdin line instead, for scripting):

```
docker run --rm -it --env-file Demo_app_CRM/.env.docker.owner.local demo-crm-app:local scripts/manage bootstrap \
  --email admin@example.test --name "Ada Admin" --origin https://127.0.0.1:3002
```

This also stores the public origin — `https://127.0.0.1:3002`, not `localhost`: the app
exact-matches `Origin`/`Host` against it. `set-origin` only changes it later; `bootstrap` already
sets it and refuses (exit 3) if an administrator already exists, so it is safe to repeat. The
administrator's own password is not flagged for a forced change; only accounts created *for*
someone else are.

Then the demo data set — creates the two demo agents (`agent.one@example.test`,
`agent.two@example.test`) if absent, sharing one password chosen at the prompt, then writes 20
contacts, 20 deals and 100 activities on fictional `example.test` data:

```
docker run --rm -it --env-file Demo_app_CRM/.env.docker.owner.local demo-crm-app:local scripts/manage seed-demo --scale small
```

Idempotent: a second run writes nothing against unchanged seed data.

## 4. Run

```
Demo_app_CRM/scripts/run-local
```

Serves `https://127.0.0.1:3002`, capped at 0.5 CPU / 1 GiB, read-only root filesystem, no
volumes. `Demo_app_CRM/scripts/run-local stop` stops and removes the container.

The self-signed certificate from step 2 earns one browser warning per host and port ("Advanced" →
"Proceed"); it will not reappear until the certificate (`-days 30`) expires, at which point
delete `Demo_app_CRM/app/certs/dev-server.{crt,key}` and rerun `build-image`. `/health/ready`
answers `503` until step 3's `bootstrap` has run — correct beforehand, not a broken run.

## 5. The journey

Sign in at `/login` as the administrator from step 3, or as one of the two seeded agents (the
shared password chosen at `seed-demo`). A successful login lands on `/dashboard` — `/` and the
nav wordmark resolve there too.

- **Contact** — "New contact": name, email, company, phone, kind (Lead / Customer radio). Saving
  opens the contact workspace.
- **Deal** — from the workspace, "New deal": title, amount (plain decimal text, e.g. `1250.00`,
  shown elsewhere as `€ 1,250.00`), optional close date. New deals always start at the **New**
  stage — no stage field on create.
- **Activity** — still on the workspace, "Log activity" (kind: note / call / email / meeting,
  date, summary up to 1000 characters) posts into the timeline right below. Once logged, an
  activity cannot be edited or deleted — append-only by design.
- **Won** — on the deal, move it laterally with the stage dropdown + "Move", or open the "Mark as
  won…" (or "…lost") disclosure and confirm. Won and Lost are terminal: no drag-and-drop, no
  JavaScript.
- **Dashboard totals** — three tiles (visible contacts, open deal count/value, won deal
  count/value) plus recent activity. As an **agent** every number is that agent's own records
  only; as **admin** the same tiles are unfiltered. Switch to the other seeded agent to see the
  scope actually change, not just repeat.

Worth trying — each is a real server response, not a client-side guess:

- Sign in as `agent.one`, open a contact owned by `agent.two` by guessing its URL — an identical
  `404` either way; ownership is never revealed.
- Archive a contact, then try to add a deal or activity to it — `409` "This contact is archived.
  Restore it before adding or changing anything under it," not a silent success.
- Edit the same contact in two tabs, submit both — the second gets `409` "This record changed
  while you were editing," a side-by-side diff, and your input preserved, not a lost update.

## 6. Re-run

Start the demo data over without touching accounts or the schema:

```
docker run --rm --env-file Demo_app_CRM/.env.docker.owner.local demo-crm-app:local scripts/manage reset-demo --yes
docker run --rm -it --env-file Demo_app_CRM/.env.docker.owner.local demo-crm-app:local scripts/manage seed-demo --scale small
```

`reset-demo` deletes every contact, deal, activity, idempotency receipt, session and
throttle/rate-limit row — every signed-in browser is logged out — but keeps `users`,
`app_settings`, `schema_migrations` and the audit log. It refuses without `--yes`, the only
confirmation, so read before running it against `crm`.

## 7. Development

From `Demo_app_CRM/` (not the container path):

```
uv sync
scripts/dev-run.sh
```

Serves the app on the host at `https://127.0.0.1:3002` over a self-signed certificate, for
editing. Not the container entrypoint — `scripts/start` is that, binds `0.0.0.0:3000`, and adds
TLS only when the certificate pair is present in the image.

Canonical test invocation, against the scratch database `crm_test`, never `crm`:

```
scripts/with-env .env.test.local -- .venv/bin/python -B -m pytest tests -p no:cacheprovider -q
```

A bare `pytest` is not a supported invocation — credentials only ever reach a process through
`scripts/with-env`. Lint and types:

```
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy
```

Each step's `.sql` file under `migrations/` is checksummed byte-for-byte, and that checksum is
verified against the journal at startup and again by every `/health/ready` check. Never edit an
already-applied step's `.sql` file — not even its comments — once its checksum has been
recorded; add a new step instead.

## 8. Deferred

This build ships the journey above and defers the rest, by decision of the operator: the
20-minute resource-profile gate, the two-replica test, `manage cleanup`/`export-subject`/
`erase-subject`, a standalone `SECURITY.md`, `DEPLOY.md`, administrator MFA, and a broader
multi-pass review beyond the one review recorded here. None of it has run here and none is
claimed as passing — the full list, with what is actually true for each item, is in
`REVIEW.md`. This build holds only fictional `example.test` data and must not hold real data
until the deferred privacy and MFA items close.

## 9. Assets

- `app/templates/**` — Jinja2, `autoescape=True`, `StrictUndefined`, no auto-reload.
- `app/static/css/app.css` — the one local stylesheet; no build step, no CDN.
- `app/static/vendor/htmx-2.0.10.min.js` — vendored from
  `https://cdn.jsdelivr.net/npm/htmx.org@2.0.10/dist/htmx.min.js`, served locally only; the app
  makes no third-party network request. SHA-256:
  `71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de`.
- `app/static/img/**` — icon sprite and illustrations.
