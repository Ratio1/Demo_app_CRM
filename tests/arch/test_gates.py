"""Static architecture gates for Slice A.

Authority: ``ACCESS_MATRIX.md`` §7 — ``ARC-003``, ``ARC-006``, ``ARC-008``,
``ARC-009``, ``SEC-063``; ``slice-a.md`` §1.1 (middleware/module map),
ruling **R43** (the vendored htmx SHA-256).

Each gate below either runs for real against the code that already exists
(``ARC-006``, ``ARC-009``, the htmx SRI check) or fails loudly, naming the
missing prerequisite, rather than passing vacuously on an empty glob
(``ARC-003``, ``ARC-008``, ``SEC-063``, which need ``app/routes/**`` and
``app/main.py`` that the Backend lane has not shipped yet).
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

APP_ROOT = Path(__file__).resolve().parent.parent.parent
APP_DIR = APP_ROOT / "app"
TEMPLATES_DIR = APP_DIR / "templates"
ROUTES_DIR = APP_DIR / "routes"

#: R43 — the exact vendored file and the exact digest the ruling pins.
_VENDORED_HTMX = APP_DIR / "static" / "vendor" / "htmx-2.0.10.min.js"
_VENDORED_HTMX_SHA256 = "71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de"


# ---------------------------------------------------------------------------
# ARC-009 — app/config.py is the only module reading the environment.
# ---------------------------------------------------------------------------


def _python_files_under(root: Path) -> list[Path]:
  """Return every ``*.py`` file under ``root``, sorted for stable output."""
  if not root.is_dir():
    return []
  return sorted(root.rglob("*.py"))


def test_arc009_only_app_config_reads_the_environment() -> None:
  """No module under ``app/`` other than ``app/config.py`` reads ``os.environ``/``os.getenv``."""
  environment_pattern = re.compile(r"\bos\.environ\b|\bos\.getenv\s*\(")
  offenders: list[str] = []
  files = _python_files_under(APP_DIR)
  assert files, f"no Python files found under {APP_DIR} yet"
  config_path = APP_DIR / "config.py"
  for path in files:
    if path == config_path:
      continue
    if "__pycache__" in path.parts:
      continue
    text = path.read_text(encoding="utf-8")
    if environment_pattern.search(text):
      offenders.append(str(path.relative_to(APP_ROOT)))
  assert offenders == [], f"environment read outside app/config.py: {offenders}"


def test_arc009_env_names_is_exactly_the_five_contracted_names() -> None:
  """``app.config.ENV_NAMES`` is exactly the five-name contract, re-asserted at this layer."""
  from app.config import ENV_NAMES

  assert ENV_NAMES == ("DB_SERVER", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME")


# ---------------------------------------------------------------------------
# ARC-006 — no hx-on, js:, on*=, Jinja |safe or Markup( in any template.
# ---------------------------------------------------------------------------

_ARC006_PATTERNS: dict[str, re.Pattern[str]] = {
  "hx-on attribute": re.compile(r"\bhx-on\b"),
  "js: event handler prefix": re.compile(r"\bjs:"),
  "inline on*= handler": re.compile(r"\bon[a-zA-Z]+\s*="),
  "Jinja |safe filter": re.compile(r"\|\s*safe\b"),
  "Markup( call": re.compile(r"\bMarkup\s*\("),
}


def test_arc006_no_unsafe_pattern_in_any_shipped_template() -> None:
  """Every ``.html`` template under ``app/templates/`` is free of the five banned patterns."""
  templates = sorted(TEMPLATES_DIR.rglob("*.html")) if TEMPLATES_DIR.is_dir() else []
  assert templates, f"no templates found under {TEMPLATES_DIR} yet (frontend lane pending)"
  violations: list[str] = []
  for template in templates:
    text = template.read_text(encoding="utf-8")
    for label, pattern in _ARC006_PATTERNS.items():
      for match in pattern.finditer(text):
        line_number = text.count("\n", 0, match.start()) + 1
        violations.append(f"{template.relative_to(APP_ROOT)}:{line_number}: {label}")
  assert violations == [], "\n".join(violations)


# ---------------------------------------------------------------------------
# R43 — the vendored htmx file's SHA-256, independent of the download step.
# ---------------------------------------------------------------------------


def test_r43_vendored_htmx_sha256_matches_the_pinned_digest() -> None:
  """``app/static/vendor/htmx-2.0.10.min.js`` hashes to exactly R43's pinned SHA-256."""
  assert _VENDORED_HTMX.is_file(), f"{_VENDORED_HTMX} does not exist yet (frontend lane pending)"
  digest = hashlib.sha256(_VENDORED_HTMX.read_bytes()).hexdigest()
  assert digest == _VENDORED_HTMX_SHA256


# ---------------------------------------------------------------------------
# ARC-008 — app/routes/** never imports app/db/repositories/**.
# ---------------------------------------------------------------------------


def _module_imports(tree: ast.AST) -> set[str]:
  """Return every dotted module name a file imports, from both import forms."""
  imports: set[str] = set()
  for node in ast.walk(tree):
    if isinstance(node, ast.Import):
      for alias in node.names:
        imports.add(alias.name)
    elif isinstance(node, ast.ImportFrom) and node.module:
      imports.add(node.module)
  return imports


def test_arc008_routes_never_import_repositories() -> None:
  """No file under ``app/routes/`` imports anything from ``app.db.repositories``."""
  route_files = _python_files_under(ROUTES_DIR)
  assert route_files, f"{ROUTES_DIR} does not exist yet (Backend lane pending)"
  offenders: list[str] = []
  for path in route_files:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for module_name in _module_imports(tree):
      if module_name.startswith("app.db.repositories"):
        offenders.append(f"{path.relative_to(APP_ROOT)} imports {module_name}")
  assert offenders == [], "\n".join(offenders)


# ---------------------------------------------------------------------------
# ARC-003 — no GET/HEAD handler's direct calls reach app.services.* mutations.
# ---------------------------------------------------------------------------

_SAFE_METHODS = {"get", "head"}


def _route_method_decorators(function_def: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
  """Return the lower-cased HTTP verbs a function is registered for, from its decorators.

  Recognises the ``@router.get(...)`` / ``@app.get(...)`` shape the module
  map's ``app/routes/**`` is expected to use (FastAPI's own idiom); a
  decorator of a different shape is silently not counted, which is why this
  gate is a heuristic (documented on the test itself), not a proof.
  """
  verbs: set[str] = set()
  for decorator in function_def.decorator_list:
    if (
      isinstance(decorator, ast.Call)
      and isinstance(decorator.func, ast.Attribute)
      and decorator.func.attr.lower() in _SAFE_METHODS | {"post", "put", "patch", "delete"}
    ):
      verbs.add(decorator.func.attr.lower())
  return verbs


def _service_call_names(tree: ast.Module, module_path: Path) -> set[str]:
  """Return the local names this file bound to something imported from ``app.services``."""
  names: set[str] = set()
  for node in ast.walk(tree):
    if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app.services"):
      for alias in node.names:
        names.add(alias.asname or alias.name)
    elif isinstance(node, ast.Import):
      for alias in node.names:
        if alias.name.startswith("app.services"):
          names.add(alias.asname or alias.name.split(".")[0])
  del module_path
  return names


def test_arc003_no_get_or_head_handler_directly_calls_a_services_import() -> None:
  """No ``GET``/``HEAD`` handler's own body directly calls a name imported from ``app.services``.

  Heuristic, documented rather than overclaimed: this checks direct calls in
  the handler's own body, one level deep. It does not follow calls into a
  helper function defined elsewhere in the same file or in another module,
  so it cannot by itself prove the full transitive-call-graph claim
  ``ACCESS_MATRIX.md`` ARC-003 makes; it is the cheap static half that a
  route calling a service *directly* — the overwhelmingly common shape in
  this codebase's module map — is caught immediately.
  """
  route_files = _python_files_under(ROUTES_DIR)
  assert route_files, f"{ROUTES_DIR} does not exist yet (Backend lane pending)"
  offenders: list[str] = []
  for path in route_files:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    service_names = _service_call_names(tree, path)
    if not service_names:
      continue
    for node in ast.walk(tree):
      if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        continue
      verbs = _route_method_decorators(node)
      if not verbs & _SAFE_METHODS:
        continue
      for call in ast.walk(node):
        if not isinstance(call, ast.Call):
          continue
        called_name = None
        if isinstance(call.func, ast.Name):
          called_name = call.func.id
        elif isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
          called_name = call.func.value.id
        if called_name in service_names:
          offenders.append(
            f"{path.relative_to(APP_ROOT)}:{node.lineno}: "
            f"{node.name} (methods={sorted(verbs)}) calls {called_name}"
          )
  assert offenders == [], "\n".join(offenders)


# ---------------------------------------------------------------------------
# SEC-063 — /docs, /redoc and /openapi.json all 404.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_sec063_docs_routes_are_404_in_the_shipped_configuration(path: str) -> None:
  """The auto-docs routes are disabled at construction time (slice-a.md §1.1)."""
  # Deferred import: app/main.py is contracted (slice-a.md §1.1) but not
  # shipped yet. No DB is contacted: create_app() only builds the ASGI app.
  from app.main import create_app  # type: ignore[import-not-found]

  client = TestClient(create_app())
  response = client.get(path)
  assert response.status_code == 404
