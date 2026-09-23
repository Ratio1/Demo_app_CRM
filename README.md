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

## Configuration

Five environment variables are the whole runtime configuration (`.env.example`). Serving and
maintenance use the same five names, with different database roles.

| Variable | Required | Value |
|---|---|---|
| `DB_SERVER` | yes | PostgreSQL host or `host:port`; an IPv6 literal is bracketed (`[2001:db8::1]`, `[2001:db8::1]:5432`). No URL, query string or connection option. |
| `DB_PORT` | no | Decimal port 1–65535, default `5432`. If `DB_SERVER` also carries a port, the two must be identical or startup fails. |
| `DB_USER` | yes | Serving: the DML-only runtime role. `scripts/manage`: the owner role. |
| `DB_PASSWORD` | yes | That role's password, used verbatim. |
| `DB_NAME` | yes | An existing, dedicated database; never created at startup. |

There is no `PORT`, `APP_URL`, `DATABASE_URL` or secret. The container always listens on plain
HTTP `0.0.0.0:3000` (`scripts/start`). The public origin — in production the `https://` hostname
Cloudflare serves — is stored in the database by `scripts/manage bootstrap --origin …` (changed
later with `set-origin`); its scheme alone decides the session cookie's name and `Secure` flag
and whether `Strict-Transport-Security` is sent. The database connection is always
`sslmode=verify-full` and trusts only `app/certs/ca-bundle.pem`, a file rather than a variable
(§2, §10).

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
trust anchor for the database connection), then `docker build -t demo-crm-app:local --target
runtime .`. The image holds no `.env*` file, no `.git`, no private key of any kind, and no
source outside `app/`, `migrations/`, `scripts/`. When
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
  --email admin@example.test --name "Ada Admin" --origin http://127.0.0.1:3002
```

This also stores the public origin — `http://127.0.0.1:3002`, not `localhost`: the app
exact-matches `Origin`/`Host` against it. `set-origin` only changes it later; `bootstrap` already
sets it and refuses (exit 3) if an administrator already exists, so it is safe to repeat. The
administrator's own password is not flagged for a forced change; only accounts created *for*
someone else are.

The container itself always speaks plain HTTP on port 3000; in production Cloudflare terminates
TLS in front of it and forwards to that port, so the origin given here is the `https://…`
hostname users type. Locally there is nothing in front of the container, so the origin is
`http://127.0.0.1:3002` — and that stored scheme, not a setting, is what decides the session
cookie's name and `Secure` flag and whether `Strict-Transport-Security` is sent.

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

Serves `http://127.0.0.1:3002`, capped at 0.5 CPU / 1 GiB, read-only root filesystem, no
volumes. `Demo_app_CRM/scripts/run-local stop` stops and removes the container.

`/health/ready` answers `503` until step 3's `bootstrap` has run — correct beforehand, not a
broken run.

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

Serves the app on the host at `http://127.0.0.1:3002`, for editing. Not the container
entrypoint — `scripts/start` is that, and binds `0.0.0.0:3000`; both speak plain HTTP.

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

## 10. Production deployment (Ratio1 WAR)

Reference only: nothing in this section has been run against a Ratio1 node from this repository.
A Worker App Runner (WAR) deploys from source and does not use the `Dockerfile`: it clones the
repository into a stock base container and runs a list of commands there. Field names are those
of `create_worker_web_app` in the `ratio1` Python SDK (3.5.57) and of the edge node's
`extensions/business/container_apps/worker_app_runner.py`; re-verify them against the SDK and
node version you deploy with.

**Base image.** `Dockerfile`:
`python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9`.
WAR: the tag `python:3.12-slim`, which floats. Python 3.12 is required either way
(`pyproject.toml`: `requires-python = "==3.12.*"`).

### Before the first deploy

1. **Trust anchor.** `app/certs/ca-bundle.pem` is git-ignored and not in the repository —
   `scripts/build-image` writes it locally (in this checkout, from the development CA) — so a
   fresh clone does not have it. The production database's CA certificate (public certificate
   only) must be at that path in the checkout the runner builds from: commit it on the
   deployment branch (`git add -f app/certs/ca-bundle.pem`, because the path is ignored), or
   write it in a build step from a file you supply. The development CA must never be the one
   used in production. Without the right certificate the process still starts and
   `/health/live` still answers `200`, but every database connection fails and `/health/ready`
   stays `503`.

2. **Migrate and bootstrap, once, as the owner role**, from a machine that can reach the
   production database; the serving container never migrates, provisions or seeds. Put the
   owner-role values (the same five names) in a git-ignored env file such as
   `.env.prod.owner.local`, then, from `Demo_app_CRM/`:

   ```
   cp <production-ca.pem> app/certs/ca-bundle.pem
   docker build -t demo-crm-app:prod --target runtime .
   docker run --rm --env-file .env.prod.owner.local demo-crm-app:prod scripts/manage migrate
   docker run --rm -it --env-file .env.prod.owner.local demo-crm-app:prod scripts/manage bootstrap \
     --email <admin-email> --name "<admin name>" --origin https://<public-host>
   ```

   Not `scripts/build-image`: while `../_tools/pgsql/pg` exists it copies the development CA and
   ignores its argument. Run it again afterwards to put the development CA back for local use.
   `migrate` grants the runtime role `<DB_NAME>_app`; add `--grant-to <role>` if the production
   runtime role is named otherwise. `<public-host>` is the hostname the WAR's tunnel serves (the
   SDK's default `tunnel_engine` is `cloudflare`, with `cloudflare_token`). `seed-demo` (§3), if
   wanted, runs the same way.

3. **Later migrations.** Before pushing a commit that adds a migration step, run `migrate` the
   same way. `/health/ready` compares the code's migration steps with the database's exactly, so
   a replica on either side of a mismatch answers `503`.

### WAR fields

| Field | Value |
|---|---|
| `vcs_data` | `{"PROVIDER": "github", "REPO_OWNER": …, "REPO_NAME": …, "BRANCH": <deployment branch>}`; add `USERNAME` and `TOKEN` for a private repository |
| `image` | `"python:3.12-slim"` (the SDK default is `node:22`) |
| `build_and_run_commands` | `["pip install --no-cache-dir --require-hashes -r requirements.lock.txt", "scripts/start"]` |
| `port` | `3000` |
| `endpoint_url` | `"/health/live"` |
| `container_resources` | `{"cpu": 0.5, "gpu": 0, "memory": "1024m", "ports": []}` — the SDK default's shape with CPU and memory changed |
| `env` | `DB_SERVER`, `DB_PORT` (optional), `DB_USER`, `DB_PASSWORD`, `DB_NAME` with the **runtime-role** values; nothing else |
| `volumes`, `file_volumes` | omitted |

There is no separate build or run field: the list runs in order and its last command is the
server. The runner clones `BRANCH` into `/app`, installs git with `apt-get` when the image lacks
it (`python:3.12-slim` does), then runs every command as `cd /app && <command>`, all chained
with `&&` in one `sh -c`. It checks the branch every `vcs_poll_interval` seconds (default 60)
and restarts on a new commit, so every push to that branch is a redeploy: a fresh clone, then
the command list again.

- **Probe.** `/health/live` answers `200` whenever the process runs; `/health/ready` answers
  `503` until `bootstrap` has run, so it cannot be the probe for a first start. The SDK sends
  `endpoint_url`, but the runner plugin named above has no `ENDPOINT_URL` setting and takes its
  HTTP probe path from `HEALTH_CHECK: {"PATH": "/health/live"}`; check which one your node
  honours.
- **`scripts/start`** must keep its executable bit in git (`git ls-files -s scripts/start`
  shows mode `100755`). It unsets every `PG*` variable, then `exec`s uvicorn on `0.0.0.0:3000`.
- **Not carried over from the `Dockerfile`:** the runner runs the commands as root (its
  `CONTAINER_USER` default), not as `10001:10001`; the root filesystem is writable; the
  `Dockerfile`'s `ENV` lines do not apply; and the node must reach GitHub, the Debian package
  mirrors and PyPI for the clone and install steps. The 0.5 CPU / 1 GiB cap and the absence of
  volumes do carry over, through the fields above.
- **Not verified here:** whether `image` accepts the `Dockerfile`'s digest form, and whether
  `container_resources.ports` must also list `3000`.
