"""Static architecture gates for Slice A.

Authority: ``ACCESS_MATRIX.md`` §7 — ``ARC-003``, ``ARC-006``, ``ARC-008``,
``ARC-009``, ``SEC-063``; ``slice-a.md`` §1.1 (middleware/module map),
ruling **R43** (the vendored htmx SHA-256).

Each gate below either runs for real against the code that already exists
(``ARC-006``, ``ARC-009``, the htmx SRI check) or fails loudly, naming the
missing prerequisite, rather than passing vacuously on an empty glob
(``ARC-003``, ``ARC-008``, ``SEC-063``, which need ``app/routes/**`` and
``app/main.py`` that the Backend lane has not shipped yet).

``ARC-018`` (**R51**/**R58**) is added at the bottom: (a) no ``UPDATE`` of
``users`` lives outside ``app/db/repositories/users.py``; (b) the
functions that write ``role`` or ``is_active`` — ``insert_user`` and
``set_active`` — are referenced only from ``app/services/accounts.py``.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Final

APP_ROOT = Path(__file__).resolve().parent.parent.parent
APP_DIR = APP_ROOT / "app"
SCRIPTS_DIR = APP_ROOT / "scripts"
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

#: ``ACCESS_MATRIX.md`` §7 ``ARC-003``: *"The mutating names are exactly
#: `create_contact`, `update_contact`, `archive_contact`, `restore_contact`,
#: `reassign_contact` — the gate can read that list."* The gate's scope
#: **is** the assertion (§7's own wording, echoing the P1 final fix round):
#: a GET/HEAD handler calling a **read** service function — `list_contacts`,
#: `get_for_detail`, `build_contact_query`, all of `app/services/contacts.py`
#: — is the ordinary, contracted shape of Slice B's own list/detail/edit-form
#: routes, not a violation. Extend this set, never widen it back to "every
#: name imported from `app.services`", as later slices add their own
#: mutations (`deal_*`, `activity_create`).
_SERVICE_MUTATION_NAMES: Final[frozenset[str]] = frozenset(
  {
    "create_contact",
    "update_contact",
    "archive_contact",
    "restore_contact",
    "reassign_contact",
  }
)


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
  """Return the local names this file bound to a service **mutation** import.

  Scoped to :data:`_SERVICE_MUTATION_NAMES` (``ACCESS_MATRIX.md`` §7
  ``ARC-003``'s own wording) — not every name imported from
  ``app.services``. A GET/HEAD route legitimately imports and calls a
  **read** service function (Slice B's `list_contacts`/`get_for_detail`,
  by contract); only a mutation import is this gate's business.
  """
  names: set[str] = set()
  for node in ast.walk(tree):
    if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app.services"):
      for alias in node.names:
        bound = alias.asname or alias.name
        if alias.name in _SERVICE_MUTATION_NAMES:
          names.add(bound)
    elif isinstance(node, ast.Import):
      for alias in node.names:
        if alias.name.startswith("app.services"):
          # A bare `import app.services.x` binds the module, not a function
          # name, so no individual mutation name can be resolved from the
          # import alone — the call-site check below still catches
          # `contacts.create_contact(...)` through the attribute form.
          names.add(alias.asname or alias.name.split(".")[0])
  del module_path
  return names


def test_arc003_no_get_or_head_handler_directly_calls_a_services_import() -> None:
  """No ``GET``/``HEAD`` handler's own body directly calls a service **mutation**.

  Heuristic, documented rather than overclaimed: this checks direct calls in
  the handler's own body, one level deep. It does not follow calls into a
  helper function defined elsewhere in the same file or in another module,
  so it cannot by itself prove the full transitive-call-graph claim
  ``ACCESS_MATRIX.md`` ARC-003 makes; it is the cheap static half that a
  route calling a service *mutation* **directly** — the overwhelmingly
  common shape in this codebase's module map — is caught immediately.
  Scoped to :data:`_SERVICE_MUTATION_NAMES`, exactly as ``ACCESS_MATRIX.md``
  §7 states the gate's own scope: a GET/HEAD handler calling a **read**
  service function is the ordinary, contracted shape of a list/detail/
  edit-form route, not a violation (Slice B's `list_contacts`/
  `get_for_detail`, called from `contacts_page`/`contact_detail`/
  `contact_edit`).
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

_DISABLED_DOC_PATHS: Final = frozenset({"/docs", "/redoc", "/openapi.json"})


def test_sec063_docs_routes_are_404_in_the_shipped_configuration() -> None:
  """The auto-docs routes are disabled at construction time (slice-a.md §1.1).

  Asserts directly on the constructed ``FastAPI`` object rather than making
  a live HTTP request through ``TestClient``: ``app.main.OriginHostMiddleware``
  (slice-a.md §2.1 step 0a) runs before routing on every non-health path and
  answers ``503`` — never ``404`` — whenever ``app.state.context`` is unset,
  which is exactly the state of an app built by ``create_app()`` and never
  given a running lifespan (no live server, no database, as this test's own
  original comment already required). A previous revision of this test drove
  a bare ``TestClient(create_app())`` (lifespan never entered) through that
  middleware expecting ``404`` and got ``503`` instead — not a backend
  defect, but this test asking a question the shipped, documented,
  fail-closed architecture cannot answer without a live database. The
  contract's own wording (slice-a.md §1.1, line 32) is exactly
  ``FastAPI(docs_url=None, redoc_url=None, openapi_url=None)``, which this
  now checks precisely, plus that no route answers any of the three paths
  either.
  """
  # Deferred import: keeps a missing module a single failing test rather
  # than a blank collection. No DB is contacted: create_app() only builds
  # the ASGI app. Shipped now, so no `type: ignore` is needed any more.
  from app.main import create_app

  app = create_app()
  assert app.docs_url is None
  assert app.redoc_url is None
  assert app.openapi_url is None

  routed_paths = {getattr(route, "path", None) for route in app.routes}
  assert not (routed_paths & _DISABLED_DOC_PATHS)


# ---------------------------------------------------------------------------
# ARC-018 — R51's reworded gate, mechanized per ruling R58.
#
# (a) No file other than app/db/repositories/users.py contains an UPDATE of
#     the users table (ARC-018(a) itself — "role" never in any SET list —
#     stays a human-reviewed invariant of that one file, not re-derived
#     here: a regex cannot tell a SET list's column names apart from an
#     UPDATE's mere presence).
# (b) The functions that write role or is_active — insert_user and
#     set_active — are referenced only from app/services/accounts.py.
# ---------------------------------------------------------------------------

_USERS_REPOSITORY: Final = APP_DIR / "db" / "repositories" / "users.py"
_ACCOUNTS_SERVICE: Final = APP_DIR / "services" / "accounts.py"

#: Matches both the schema-qualified form every statement in this codebase
#: actually uses (``UPDATE public.users``) and the bare form (``UPDATE
#: users``), case-insensitively: SQL keyword casing is not a security
#: property, and the gate must not pass vacuously just because a future
#: statement happens to spell the keyword differently. Deliberately does
#: **not** match ``UPDATE ... FROM users`` or a comment that merely
#: mentions both words with something else between them (confirmed against
#: every ``.py`` file under ``app/`` today: the only matches are the four
#: real statements and two docstring mentions, both inside ``users.py``
#: itself, the one file this gate exempts).
_UPDATE_USERS_PATTERN: Final = re.compile(r"\bUPDATE\s+(?:public\.)?users\b", re.IGNORECASE)

#: The two functions ``R51``/``R58`` name as writers of ``role`` or
#: ``is_active``. ``insert_user`` writes ``role`` (``H-07``: role is set at
#: INSERT and nowhere else); ``set_active`` writes ``is_active``.
_ROLE_OR_ACTIVE_WRITERS: Final[frozenset[str]] = frozenset({"insert_user", "set_active"})


def _files_scanned_for_arc018() -> list[Path]:
  """Every ``.py`` file under ``app/``, plus ``scripts/manage`` (extensionless).

  ``ARC-018``'s own wording ("no file … ") is not confined to ``app/``:
  the one CLI entrypoint that can reach account administration at all
  lives in ``scripts/manage``, so the gate scans it too, by explicit path
  since it carries no ``.py`` suffix for ``rglob`` to find.
  """
  files = _python_files_under(APP_DIR)
  manage_script = SCRIPTS_DIR / "manage"
  if manage_script.is_file():
    files = [*files, manage_script]
  return files


def test_arc018a_no_update_of_users_outside_its_one_repository_file() -> None:
  """No file other than ``app/db/repositories/users.py`` contains an ``UPDATE`` of ``users``."""
  files = _files_scanned_for_arc018()
  assert files, "no files found to scan (app/ is empty) yet"
  offenders: list[str] = []
  matches_in_the_one_allowed_file = 0
  for path in files:
    text = path.read_text(encoding="utf-8")
    matches = list(_UPDATE_USERS_PATTERN.finditer(text))
    if not matches:
      continue
    if path == _USERS_REPOSITORY:
      matches_in_the_one_allowed_file += len(matches)
      continue
    for match in matches:
      line_number = text.count("\n", 0, match.start()) + 1
      offenders.append(f"{path.relative_to(APP_ROOT)}:{line_number}: {match.group(0)!r}")
  assert offenders == [], "\n".join(offenders)
  # Not vacuous: users.py itself must actually contain the statement this
  # gate is confining, or the pattern (or the exemption) has drifted from
  # what the code does.
  assert matches_in_the_one_allowed_file > 0, (
    f"expected at least one UPDATE of users in {_USERS_REPOSITORY}; "
    "found none — the gate's own pattern may have drifted"
  )


def _ast_referenced_names(tree: ast.AST, names: frozenset[str]) -> set[str]:
  """Return which of ``names`` this file actually imports or attribute-accesses.

  Parameters
  ----------
  tree : ast.AST
    A parsed module.
  names : frozenset[str]
    The identifiers to look for.

  Returns
  -------
  set[str]
    The subset of ``names`` found as an ``ImportFrom`` alias (``from
    app.db.repositories.users import set_active``) or as an attribute
    access whose attribute name matches (``users.set_active(...)``) — real
    code references, never a docstring or comment mention. AST-based
    rather than a text/regex scan deliberately: ``app/services/auth.py``'s
    own docstring says, in prose, "It imports neither ``set_active`` nor
    ``insert_user`` …", which a text scan would flag as a false positive
    in the one file that most explicitly documents *not* doing the thing
    this gate forbids.
  """
  found: set[str] = set()
  for node in ast.walk(tree):
    if isinstance(node, ast.ImportFrom):
      for alias in node.names:
        if alias.name in names:
          found.add(alias.name)
    elif isinstance(node, ast.Attribute) and node.attr in names:
      found.add(node.attr)
  return found


def test_arc018b_role_and_active_writers_referenced_only_from_accounts_service() -> None:
  """The role/``is_active`` writers are referenced only from ``app/services/accounts.py``."""
  files = _files_scanned_for_arc018()
  assert files, "no files found to scan (app/ is empty) yet"
  offenders: list[str] = []
  accounts_references: set[str] = set()
  for path in files:
    if path == _USERS_REPOSITORY:
      # The definitions themselves, and this file's own docstring/__all__
      # naming them, live here and are not a "reference" this gate confines.
      continue
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    referenced = _ast_referenced_names(tree, _ROLE_OR_ACTIVE_WRITERS)
    if not referenced:
      continue
    if path == _ACCOUNTS_SERVICE:
      accounts_references |= referenced
      continue
    offenders.append(f"{path.relative_to(APP_ROOT)} references {sorted(referenced)}")
  assert offenders == [], "\n".join(offenders)
  # Not vacuous: accounts.py must actually reference both writers, or the
  # AST matcher (or the exemption) has drifted from what the code does.
  assert accounts_references == _ROLE_OR_ACTIVE_WRITERS, (
    f"expected {_ACCOUNTS_SERVICE} to reference both {sorted(_ROLE_OR_ACTIVE_WRITERS)}; "
    f"found {sorted(accounts_references)} — the gate's own matcher may have drifted"
  )
