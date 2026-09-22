# REVIEW — Demo_App_CRM

**App:** Demo_App_CRM — minimalistic CRM MVP (submodule `Demo_app_CRM`). **Date:** 2026-09-22. **Commit reviewed:** `f12e159` (this file's own commit lands on top of it, on `main`).
**Reproduce:** from the meta-repo root, `_tools/pgsql/pg ensure` then (once) `_tools/pgsql/pg create-app crm_test`; canonical suite from `Demo_app_CRM/`: `scripts/with-env .env.test.local -- .venv/bin/python -B -m pytest tests -p no:cacheprovider -q`; container path: `scripts/build-image`, then `docker run` with `--env-file .env.docker.test.local` on an ephemeral host port using the `--cpus=0.5 --memory=1g --memory-swap=1g --read-only --stop-timeout 25` flags of `scripts/run-local`, provisioned via `scripts/manage migrate|bootstrap|set-origin|seed-demo` using `.env.docker.test.owner.local`.

## Models actually used

- **Orchestrator** — Claude Fable 5.1, coordination only (`AGENTS.md` model policy; never a builder or reviewer).
- **Builder** (backend-security; plan §4 tasks 1–5, 7, 9, and the F1 fix below) — Opus 5. Trailers: `Agent-Role: backend-security (opus)` on `4a5c6e6..d1a9297,55fa487`; `Agent-Role: backend-security (Opus 5 (1M context))` on `f12e159`; self-reported "Opus 5 (1M context)" in the build/fix reports.
- **Builder** (frontend; plan §4 task 8, README) — Sonnet 5. Trailer `Agent-Role: frontend (sonnet)` on `06a171f`, `a555f3d`.
- **Test-engineer** (plan §4 tasks 6 and 11/this report) — Sonnet 5. Trailer `Agent-Role: test-engineer (sonnet)` on `3d8e540..9c1f19b` and this commit.
- **Reviewer** (plan §4 task 10; independent, non-authoring, read-only, one pass) — Opus 5 (1M context), `claude-opus-5[1m]`, self-reported below.
- **Council seats**: cut to the one reviewer pass above by operator decision 4 (`SIMPLIFICATION_PLAN.md` §5 #4); the spec's P4/P5/P6 councils and the further design council did not run this push, so D-A closes as moot and the UX-architect seat's D2 substitution (`gpt-5.6-sol`/`opus`) was not exercised — recorded here per `BRIEF.md` in case a future push revives it.

## Independent review — filed VERBATIM (plan §4 task 10)

> Below is the reviewer's report exactly as delivered, mechanically unwrapped to one line per paragraph (line-wrap position is not content; no word was added, removed or changed). My own annotations, added after the fact, are set off as `> Disposition —` / `> Reconfirmed —` blockquote lines immediately following the paragraph or list item they respond to, never merged into the reviewer's sentences.

# REVIEW — Slice D and the container run path (independent security/privacy pass)

**Reviewer model:** Opus 5 (1M context), `claude-opus-5[1m]`. Fresh, non-authoring, read-only; no file in this repository was created or edited by this pass. One independent review, one pass (simplification plan §4 task 10; the P4/P5/P6 councils are cut by operator decision 4).

**Scope:** `ae95ac2..9c1f19b` — 17 commits, `4a5c6e6` (conditional TLS in `scripts/start`) through `9c1f19b`, submodule tree clean. Image `demo-crm-app:local` id `ac7618e17e8a`, built by the builder; **not** rebuilt by this review. Every live check ran against `crm_test`; `crm` was never written.

> Reconfirmed — this task rebuilt the image (`scripts/build-image`) so it reflects `f12e159`; the new id is `sha256:98f733be…10c46e`, 235,290,372 bytes. See Container evidence below.

## Verdict — approve with fixes

No critical and no high finding. **F1 (medium)** needs either a code change or a justification recorded here. F2–F6 are low; none blocks the operator's acceptance session.

## Findings

**F1 · medium · S1 · `scripts/manage:128` + `app/services/accounts.py:609`** — *seed-demo's shared agent password never meets the blocklist and is permanent.* `_read_password` enforces only the 15–128 length bound and justifies skipping `PasswordService.validate` (`app/security/passwords.py:386`) with "every password set here is a hand-over credential that `create-user` and `reset-password` both mark `must_change_password`". `ensure_demo_agent` sets `must_change_password=False`, so that compensator is gone: `seed-demo` creates two permanent, login-capable agent accounts sharing **one** operator-chosen password the blocklist never saw, and `README.md:69` points the command at `crm`. `PasswordService.hash()` (`:270`) does not validate. `bootstrap` (`accounts.py:218`) already had this shape — pre-existing; this diff extends it to two more accounts and makes the credential shared. **Fix:** call `passwords.validate(password, context=(email, display_name))` in `_seed_demo` before hashing, exit 2 on any returned message, with a test that a blocklisted ≥15-character password is refused — or record accept-with-justification here and correct `_read_password`'s docstring.

> Disposition — **FIXED in `f12e159`, not disputed.** `_check_demo_password` now calls exactly `passwords.validate(password, context=(email, display_name))` for each `DEMO_AGENTS` entry inside `_seed_demo`, before hashing and before the pool opens; a refusal is `UsageError` (exit 2) carrying only the policy copy, never the password. `_read_password`'s docstring no longer states the false justification. Regression test confirmed present on `HEAD`: `tests/concurrency/test_demo_seed_and_reset.py::test_seed_demo_refuses_a_blocklisted_agent_password`. Reconfirmed live in this task: `seed-demo --scale small` against the running container succeeded with a compliant fictional password and wrote 20/20/100 (Container evidence below). `bootstrap`'s first administrator remains the documented pre-existing gap, untouched (shipped code, no-refactor rule).

**F2 · low · `tests/arch/test_gates.py:480`** — *no mechanical gate keeps the maintenance path off the web.* `maintenance` joins `_SCOPE_EXEMPT_REPOSITORY_MODULES`, so the ARC-001 gate now permits unscoped `DELETE` statements there without asserting the boundary that makes them safe. Verified by grep: nothing under `app/routes/` imports `app.services.demo` or `app.db.repositories.maintenance` (only `app/services/demo.py:35` imports the repository, only `scripts/manage` the service), and the runtime role holds no `DELETE`. But nothing fails if a future route imports either. **Fix:** one gate asserting no module under `app/routes/`, and nothing reachable from `create_app`, imports those two modules.

> Disposition — **accepted low, not fixed.** No new gate was added this push (outside plan §4 tasks 6/11's scope; the plan permits no new tests unless a fix requires one). Re-verified in this task by the same grep against `HEAD` (`f12e159`): still true.

**F3 · low · `README.md:40`** — *the image embeds a private TLS key and the README does not say it must never be published.* Confirmed inside the image: `/app/app/certs/dev-server.key`, `-rw-------`, owner `10001`. Intended (D-L, no mounts), but §2 lists only what the image lacks. **Fix:** one line — `demo-crm-app:local` is local-only because it embeds a development TLS private key; never push or share it.

> Disposition — **accepted low, not fixed.** The README commits (`06a171f`, `a555f3d`) predate this review pass (both inside the reviewed range `ae95ac2..9c1f19b`); no later README commit added the line. Reconfirmed on the freshly rebuilt image: the key is still `-rw-------`, owner `10001`.

**F4 · low · `scripts/build-image:44`** — *the `verify-full` trust anchor is a build-time copy of the local dev CA*, git-ignored, not spec §4's "explicit, reviewed CA bundle … for both approved database targets"; no R1DB root. `.gitignore:19` still references a committed `app/certs/roots/` that does not exist. **Fix:** no code change; state it beside the §5 R1DB `BLOCKED` row.

> Disposition — **accepted, stated below** in the §6 table's R1DB row (the finding itself asks for no code change).

**F5 · low · `app/services/activities.py:442`** — *a reused idempotency key answers 409 before the parent scope check.* `decide()` precedes `_parent_state()`, so replaying one's own key with a different payload returns `Duplicate` for any `contact_id`, foreign or absent — the one path where the identical 404 does not hold. **Not an oracle:** the outcome and the rendered `record_url` are functions of the actor's own receipt and their own submitted id and never vary with the target's existence or ownership. Same ordering as the shipped deal create. **Fix:** record the exception.

> Disposition — **accepted low, not fixed** (the fix asked only to record the exception, which this line does). Unchanged on `HEAD`.

**F6 · low · `app/db/repositories/maintenance.py:58`** — *`reset-demo` is broader than "demo rows"*: it deletes **every** row of contacts, deals, activities, receipts, sessions, `login_throttle` and `rate_budget`, so on `crm` it also removes the operator's hand-made walk records and clears S6 throttle state. Maintenance-role only, `--yes` gated, `demo_reset` in the same transaction, and `users`/`app_settings`/`schema_migrations`/`audit_events` untouched. **Fix:** name `login_throttle`/`rate_budget` here so "never touches accounts/audit" is not read as "seeded rows only".

> Disposition — **accepted low; named here as asked.** `reset-demo --yes`, run live against `crm_test` in this task, removed exactly `activities`, `deals`, `contacts`, `mutation_receipts`, `sessions`, `login_throttle` and `rate_budget` (all seven; exact counts in Container evidence below) and left `users`/`app_settings`/`schema_migrations`/`audit_events` untouched except one new `demo_reset` audit row. The same is true on `crm` — never run there by anyone in this project to date.

## The six required checks

1. **Activities authorization — PASS.** The parent is re-resolved inside the `SERIALIZABLE` transaction by `deals.parent_state` (`deals.py:312`), whose scope conjunct is in the `WHERE`; a foreign and a missing contact collapse to one `"missing"` → `ContactNotFound` → identical 404, audited via `record_denial` (`routes/errors.py:772`). Archived → 409 `archived_parent` (`services/activities.py:454`). `insert_activity` re-checks the same statement as a transaction-local guard. No `owner_id`/`created_by_user_id` parameter exists; the author is the session. No `UPDATE`/`DELETE` statement in `activities.py` and no edit/delete route. Grants proven **live** as `crm_test_app`: exact `{SELECT, INSERT}` plus `42501` on a real `UPDATE` and `DELETE` (`tests/concurrency/test_grants.py`, 11 passed on its own run).
2. **Dashboard aggregate — PASS.** Three statements, one `SERIALIZABLE, READ ONLY` snapshot (`services/dashboard.py:106`). Each carries the ownership conjunct on the parent (`contacts._COUNT_VISIBLE_SQL`, `deals._DASHBOARD_TOTALS_SQL`, `activities._RECENT_SQL`); admin gets the *absence* of a conjunct, never a widened one. `c.archived_at IS NULL` is written into all three. Sums are `SUM(CASE …)` in SQL, crossed into Python through `_as_decimal` (`TypeError` on anything but `Decimal`); nothing is summed, counted or filtered in Python. `is_empty` is derived from the engine's own numbers.
3. **Seed/reset — PASS except F1.** Maintenance-only (`repositories/maintenance.py`), reachable only from `scripts/manage`, and the runtime role holds no `DELETE`. Deterministic (`uuid5` + seeded `random.Random`) and idempotent by row-id probe; FK-ordered delete; `users`/`app_settings`/`schema_migrations`/`audit_events` never in the order. The demo password is read from `getpass` or one stdin line, never argv, never logged.
4. **Container path — PASS.** `scripts/start` adds `--ssl-certfile/--ssl-keyfile` only when both files exist, scrubs every `PG*` name, `exec`s one worker as PID 1 with `python -B`, `--no-server-header/--no-proxy-headers/--no-access-log`. Live, with `run-local`'s exact flags: `ReadonlyRootfs=true Mounts=0 Binds=<none> Memory=1073741824 NanoCpus=500000000 User=10001:10001`, credentials only via `--env-file`. From inside the image, runtime role `crm_test_app` connected with `sslmode=verify-full`, `sslrootcert=/app/app/certs/ca-bundle.pem`, `pg_stat_ssl = (True, 'TLSv1.3')`; the same connect_kwargs against the gateway IP is refused with *"server certificate for \"localhost\" (and 4 other names) does not match host name"* — hostname verification is genuinely in force, not `require`. `/health/live` 200 `live`; `/health/ready` 503 `not ready` with `Retry-After: 5` and `users` empty, i.e. unprovisioned, not unreachable; `/dashboard` and `/` 503 while unprovisioned. All responses carry `no-store`, the full CSP with `frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'`, HSTS, nosniff, Referrer-Policy, Permissions-Policy, and no `Server` header. Image holds no `.env*`, `.git`, `tests/` or `roots.dev/` (`find` inside the container); `docker history` shows zero `VOLUME` and no `DB_*` value; `Config.Volumes = null`; `.dockerignore` excludes `.env*`, `.git`, `tests/`. Request logs are JSON with `path` only — zero matches for password/DSN/SQL/role text.
5. **Scans — PASS.** `pip-audit` re-run by me against `requirements.lock.txt`: *No known vulnerabilities found*, exit 0. `bandit`: 0 high, 0 medium, 2 low, both `B311` on non-security PRNG (retry jitter, fixture seed) with matching `noqa`. SBOM `sbom/demo-app-crm.cdx.json`, CycloneDX 1.6, 24 components matching the 24 lockfile pins — the app closure, not the tool's. No unaddressed critical/high.
6. **Tests — PASS.** New coverage exists for 1–3: `tests/access/test_activities.py` (identical 404, 409 archived, CSRF, forced reset, bounds, kind allowlist, replay, 409 duplicate, timeline scoping and paging), `tests/access/test_dashboard.py` (independently computed per-agent fixtures, admin as a delta, archived exclusion, recent scoping, anonymous/forced-reset denial), `tests/concurrency/test_activities_concurrency.py`, `test_demo_seed_and_reset.py`, `test_grants.py`, `tests/unit/test_config.py`. Canonical invocation run by me: **451 passed in 256.69s**, exit 0.

> Reconfirmed in this task (checks 1–4, 6): live re-check as `agent.one`, live `docker inspect`/`find`/header dump, and two fresh canonical suite runs — see Test evidence and Container evidence below. Check 5 (scans) was **not re-run** this task; its artefacts (`sbom/`, dated 2026-09-22) are unchanged by `f12e159`.

## §6 controls S1–S7

- **S1** — F1 (medium): the CLI password path skips the blocklist and `seed-demo` removes the forced reset. Argon2id parameters, bounds, generic failures and the forced-reset gate are unchanged here.

> Reconfirmed — F1 is now fixed in `f12e159` (above). Residual gap, unchanged by the fix: `bootstrap`'s first-administrator password still bypasses the blocklist, per `_read_password`'s own docstring.

- **S2** — unchanged by this diff; `__Host-` cookies and rotation exercised by the shipped suite. The container's live responses confirm `no-store` on private and health responses.
- **S3** — PASS: `POST /activities` goes through `start_mutation` (session → CSRF → content type → budget → forced-reset → exact body allowlist); `_CREATE_FIELDS` is the frozen form's set and any extra, repeated or non-textual part is a 400. Both `GET`s mutate nothing.
- **S4** — PASS: every new statement is parameterized, scope fragments are one of exactly two literals, `ACTIVITY_FIELDS`/`ActivityFields` are the write allowlist, `?page=` is allowlisted and digit-matched, per-page clamped to 100, offset clamped. Templates autoescape; no `|safe`.
- **S5** — unchanged; headers confirmed live on the container (above). Port 3000 private, published to loopback only by `run-local`.
- **S6** — unchanged; note F6, that `reset-demo` clears `login_throttle`/`rate_budget` — maintenance role only, never reachable over HTTP. Logs carry no secrets, SQL or record bodies.
- **S7** — PASS: `activity_created` rides the same `SERIALIZABLE` transaction as the append; the vocabulary has no `activity_updated`/`activity_deleted` because the role has neither privilege. `demo_seeded`/`demo_reset` are written by the maintenance role with `actor_id` NULL. Deny paths are audited. The maintenance half of S7 (`cleanup`/`export-subject`/`erase-subject`) remains deferred.

> Reconfirmed — the schema's actual column is `actor_user_id` (not `actor_id`); its value on the one live `demo_reset` row produced in this task is `NULL`, `outcome='success'`, matching the claim.

**OWASP ASVS 5.0.0 L2:** *not claimed — deferred per simplification plan §6.* No per-ID map exists and none is fabricated here; S1–S7 are implemented and covered by `tests/`.

## NOT VERIFIED (never reported as passed)

§8 resource gate, `RESOURCE_TESTS.md`, profile-scale seed · two replicas · image scan, hadolint, authenticated DAST, secret-scan fidelity (B3–B6) · R1DB compatibility (B1, BLOCKED) · hostile `PG*` env on the `scripts/manage` path (`scripts/start` scrubs; `manage` was not probed) · invalid-CA and wrong-hostname behaviour beyond the one live hostname-mismatch probe recorded above. The `docker stats` reading taken during this review — **49.88 MiB / 1 GiB, CPU 0.22%** — is an **idle** snapshot of the capped container and is not the §8 gate.

**[PRIVACY] fence stands:** fictional `example.test` data only; no real personal data until subject export, erasure, retention pruning and verified administrator MFA exist.

*(End of the reviewer's report, filed verbatim above.)*

## Test evidence (this task, test-engineer, Sonnet 5)

- **Static:** `ruff check .` → *All checks passed!* `ruff format --check .` → *97 files already formatted*. `mypy` (pyproject `files=["app"]`, strict) → *Success: no issues found in 55 source files*. `mypy --strict tests` → *Success: no issues found in 40 source files*. `mypy --strict scripts/manage` → *Success: no issues found in 1 source file*.
- **Canonical suite, twice, each from a clean `crm_test`** (the session-scoped autouse fixture drops and recreates `public` + migrates before any test runs — `tests/conftest.py:435`): `scripts/with-env .env.test.local -- .venv/bin/python -B -m pytest tests -p no:cacheprovider -q`. Run 1: **452 passed in 264.84s**. Run 2: **452 passed in 273.65s**. Both exit 0, zero failures, zero skips (the +1 over the reviewer's 451 is the new F1 blocklist-refusal regression test, added after the review).
- Versions: Python 3.12.13, pytest 9.1.1, ruff 0.16.8, mypy 2.3.1, Docker 29.8.0, Playwright 1.63.0.

## Container evidence (this task, against `crm_test` only; `crm` was never written)

`scripts/build-image` rebuilt the image (it now reflects `f12e159`, which the reviewer's `ac7618e17e8a` did not): **id `sha256:98f733be…10c46e`, 235,290,372 bytes (≈224 MiB)**. `Config.Volumes = null`; `docker history --no-trunc` has zero `VOLUME` lines. Container `demo-crm-verify`, `--env-file .env.docker.test.local`, `-p 127.0.0.1:3097:3000` (ephemeral — never the operator's `3002`), `--cpus=0.5 --memory=1g --memory-swap=1g --read-only --stop-timeout 25`. Live `docker inspect`: `User=10001:10001 ReadonlyRootfs=true Memory=1073741824 NanoCpus=500000000 Binds=<none> Mounts=0`. Cold start (`docker run` → `/health/live` 200): **2170 ms**. `find` inside the image for `.env*`/`.git`/`tests`/`roots.dev`: no matches. `app/certs/dev-server.key`: `-rw-------`, owner `crm` (10001).

Provisioned from the image against `crm_test`, owner env only: `migrate` → **41 steps**; `bootstrap` (fictional admin, `--password-stdin` from a 0600 tmp file, deleted after) → created; `set-origin` (idempotent, re-run) → stored; `seed-demo --scale small` (fictional agent password on stdin, ≥15 chars, clears the S1 blocklist per the F1 fix) → **wrote 20 contact(s), 20 deal(s), 100 activity(ies); now 20/20/100**. `/health/ready` flipped 503→200; `/login` 200 with `__Host-crm_session`, full CSP/HSTS/nosniff/Referrer-Policy/Permissions-Policy, `cache-control: no-store`, no `Server` header.

Headless Chromium walk (login → dashboard → contact → deal → activity/timeline → won → dashboard), as `agent.one@example.test`: dashboard **before** any mutation matched a hand-computed SQL query (read-only, `.env.test.owner.local`) exactly — Contacts **10**, Open deals **6** (**€ 19,850.00**), Won deals **2** (**€ 9,550.00**). Created one contact, one €500.00 deal, logged one activity (visible in `#timeline`), marked the deal **won**. Dashboard **after**: Contacts **11**, Open deals **6** (**€ 19,850.00**, unchanged — the new deal opened and closed within the same walk), Won deals **3** (**€ 10,050.00**) — exact match to the independently recomputed expectation. `docker stats --no-stream` snapshot taken mid-walk (after real page loads, not idle): **CPU 0.24%, MEM 69.36 MiB / 1 GiB** — a snapshot only, not the deferred §8 gate.

`docker rm -f` then recreate with identical flags: the saved browser session (cookie only, no re-login) loaded `/dashboard` successfully and showed the same Contacts 11 / Won 3 (€ 10,050.00) and the same logged activity — proof all state lives in the database, not the container.

`reset-demo --yes` from the image, before/after read via `.env.test.owner.local`: removed **activities 101, deals 21, contacts 21, mutation_receipts 4, sessions 2, login_throttle 0, rate_budget 5** (script's own report matched the before-counts exactly); after: all seven at **0**; `users` **3**, `app_settings` **2**, `schema_migrations` **41** — all unchanged; `audit_events` **11→12**, the one new row `('demo_reset','success', actor_user_id NULL)`. Container removed; no leftover `demo-crm-verify`; password tmp files deleted; `crm_test` schema reset back to empty afterward for the next session.

## §6 deferred / NOT VERIFIED — copied verbatim from `SIMPLIFICATION_PLAN.md` §6

| Spec clause / §9 gate | Status | What is actually true |
|---|---|---|
| §8 Required resource gate; §9 Resources/state | **NOT VERIFIED — deferred by operator** | No 20-minute run, no p95 figure, no peak-memory number at profile scale. The container is genuinely run capped at 0.5 core / 1 GiB and a `docker stats` snapshot is recorded. |
| §8 two replicas; §9 Deploy | **NOT VERIFIED — deferred** | One replica by design; no shared-session/throttle-across-replicas claim is made. |
| §9 Deploy (invalid CA, wrong hostname, hostile `PG*` env) | **NOT VERIFIED** | `app/config.py` passes every libpq parameter explicitly; one unit test pins `sslmode=verify-full` + explicit `sslrootcert`. |
| §4 manage `cleanup`/`export-subject`/`erase-subject`; §6 S7 maintenance half | **NOT IMPLEMENTED — deferred** | No retention pruning, no subject export, no erasure path. |
| §6 [ASVS] | **NOT CLAIMED — deferred** | No per-ID map. S1–S7 are implemented and covered by `tests/security`. |
| §6 MFA (B8) | **Recorded gap** | Administrator MFA absent; required before real-data use. |
| §9 Quality (image scan, hadolint, DAST, secret-scan fidelity) | **NOT VERIFIED (B3–B6)** | Tools unavailable here; `pip-audit`, `bandit` and one SBOM run once, dated, with raw output committed. |
| §1 workflow; §9 Design/review | **PARTIAL — reduced by operator** | One fresh reviewer, one pass, instead of three reviewers plus a re-review round; no further design round. Council models actually run are recorded (this plan's three seats: Opus 5 (1M), per D2's substitution rule). |
| §5 R1DB leg (B1) | **BLOCKED** | No endpoint, fork/version or credentials; no compatibility claim is made. |
| §8 WAR source-build, `war-*.sh`, tunnel (B10) | **Out of scope per operator, 2026-09-21** | Never reported as passed. |
| §6 [PRIVACY] fence | **Binding** | This build is for fictional `example.test` data only and must not hold real personal data until subject export, erasure, retention pruning and verified administrator MFA exist. |

This task adds no new deferral beyond the table above. F2/F3/F5's "accepted low, not fixed" dispositions are recorded next to each finding above, not as new §6 rows; F4's is folded into the R1DB row: the shipped `verify-full` trust anchor is the local dev CA only, not an R1DB-reviewed bundle.

## Privacy fence (binding, restated)

This build (`demo-crm-app:local`, commit `f12e159` and this review commit) holds **fictional `example.test` data only** — every account, contact, deal and activity created or verified in this task used invented `example.test` identities and fictional passphrases. It must not hold real personal data until subject export, erasure, retention pruning and verified administrator MFA exist (§6 table above). The real `crm` database was touched only by `migrate` (by the builder, prior to this task) and was never bootstrapped, seeded or reset by anyone to date; this task ran `migrate`/`bootstrap`/`set-origin`/`seed-demo`/`reset-demo` against `crm_test` exclusively.
