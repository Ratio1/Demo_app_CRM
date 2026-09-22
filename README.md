# Demo_app_CRM
Simple CRM system deployable on any infrastructure but loving Ratio1

## Frontend assets (Slice A)

- `app/templates/**` — Jinja2 templates. Rendered with an explicit
  `jinja2.Environment(loader=FileSystemLoader("app/templates"),
  autoescape=True, undefined=StrictUndefined, auto_reload=False)` (D11).
- `app/static/css/app.css` — the one local stylesheet (tokens + components,
  no build step, no CDN).
- `app/static/vendor/htmx-2.0.10.min.js` — vendored from
  `https://cdn.jsdelivr.net/npm/htmx.org@2.0.10/dist/htmx.min.js` (R43).
  SHA-256: `71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de`.
  Served locally only; the app makes no third-party network request.
- `app/static/img/**` — icon sprite and illustrations (`design-artwork`
  lane); see `_agents/projects/CRM/design/ARTWORK_INVENTORY.md`.

Formatting/typing commands (per `pyproject.toml`):

```
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy
```

## Frontend assets (Slice B)

- `app/templates/contacts/list.html`, `partials/contact_results.html` —
  the contacts list, search/filter and the `#contact-results` fragment
  (`HX-Request` swap target).
- `app/templates/contacts/form.html` — the contact editor (new and edit).
- `app/templates/contacts/detail.html` — the contact workspace (S6):
  details, activity/timeline, deals, record and owner panels.
- `app/templates/errors/409.html` — the four conflict contexts (`stale`,
  `archived_parent`, `duplicate`, `stage_terminal`).
- `app/templates/partials/{badges,announce,pagination,field_errors,
  confirm}.html` — shared macros/fragments the pages above compose.

## Frontend assets (Slice C)

- `app/templates/deals/list.html`, `partials/deal_results.html` — the
  deals list, search/filter and the `#deal-results` fragment (`HX-Request`
  swap target).
- `app/templates/deals/pipeline.html`, `partials/pipeline.html` — the
  read-only pipeline (R22): five stage columns/sections and the
  `#pipeline-results` fragment.
- `app/templates/deals/form.html` — the deal editor (new and edit).
- `app/templates/deals/detail.html` — the deal detail (S10): amount,
  stage badge, the stage-change control, breadcrumb.
- `app/templates/partials/stage_control.html` — the non-drag stage
  control (R22): a lateral `<select>` + Move form, and the Won/Lost
  confirmations (via `partials/confirm.html`), shared by the deal detail
  and every contact-workspace deal card.
- `app/templates/contacts/detail.html`'s `#deals` region — real deal
  cards (title, amount, stage badge, close date, the stage control) and
  the "New deal" action, replacing Slice B's always-empty stub.
- `app/templates/partials/badges.html` gains `archived_contact_badge()`
  (CP-128 "Archived contact") — additive; the four macros
  `CONTRACTS.md` §8.3 freezes are unchanged.
- Money and date rendering use the `eur`/`day` Jinja filters
  (`app/services/money.py`, registered in `app/routes/rendering.py`) —
  `decimal.Decimal` end to end, never a float on a template money path
  (PIN C1 / `ARC-021`).

## Running the tests

Canonical invocation (`CONTRACTS.md` §5.1, R52) — runs the suite as the
runtime role against the scratch database `crm_test`, resetting and
migrating it first (session-scoped, autouse):

```
scripts/with-env .env.test.local -- .venv/bin/python -B -m pytest tests -p no:cacheprovider -q
```

A bare `pytest` is not a supported invocation and its result is not
evidence — credentials only ever reach the process through
`scripts/with-env`, never a shell variable or a command-line argument.

## Running locally

```
_tools/pgsql/pg ensure
_tools/pgsql/pg env crm --write Demo_app_CRM/.env
_tools/pgsql/pg env crm --role owner --write Demo_app_CRM/.env.owner.local
```

One-time, so the app's stored public origin matches the dev server
(`scripts/dev-run.sh`'s own header comment):

```
scripts/with-env .env.owner.local -- python -B scripts/manage \
  set-origin --origin https://127.0.0.1:3002
```

Then, from `Demo_app_CRM/`:

```
scripts/dev-run.sh
```

Serves `https://127.0.0.1:3002` over TLS with a self-signed development
certificate generated on first run (git-ignored). Port `3002` is this
app's dev assignment; the container entrypoint (`scripts/start`) is a
separate script and is not used here.
