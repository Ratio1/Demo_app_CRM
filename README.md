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
