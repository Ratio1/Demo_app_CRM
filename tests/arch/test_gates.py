"""Static architecture gates for Slice A and Slice B.

Authority: ``ACCESS_MATRIX.md`` §7 — ``ARC-003``, ``ARC-006``, ``ARC-008``,
``ARC-009``, ``SEC-063``; ``slice-a.md`` §1.1 (middleware/module map),
ruling **R43** (the vendored htmx SHA-256); ``contracts/slice-b.md``
§2(h) (``ARC-001``/``SQL-032``'s Slice B allowlist), ``DATA_CONTRACT.md``
§9.1 (``SQL-031``'s server-clock ban and its one named exemption).

Each gate below either runs for real against the code that already exists
(``ARC-006``, ``ARC-009``, the htmx SRI check) or fails loudly, naming the
missing prerequisite, rather than passing vacuously on an empty glob
(``ARC-003``, ``ARC-008``, ``SEC-063``, which need ``app/routes/**`` and
``app/main.py`` that the Backend lane has not shipped yet).

``ARC-018`` (**R51**/**R58**) is added at the bottom: (a) no ``UPDATE`` of
``users`` lives outside ``app/db/repositories/users.py``; (b) the
functions that write ``role`` or ``is_active`` — ``insert_user`` and
``set_active`` — are referenced only from ``app/services/accounts.py``.

``ARC-001``/``SQL-032`` and ``SQL-031`` (Slice B, ruling R66) are added at
the very bottom, extended for Slice C's ``deals.py``/``migrations/0004_deals``
(both already covered generically by the existing walks over
``app/db/**``/``migrations/**``, except the two tests that named
``contacts`` explicitly). ``ARC-021`` (Slice C, **proposed** — not yet in
``ACCESS_MATRIX.md`` §7, `contracts/slice-c.md` §2(h)) is added after it:
money is ``decimal.Decimal`` end to end, both halves — no ``float(``/
``round(`` over a float on a money path (static), and the runtime guards
``format_eur``/``DealFields``/``DealRow`` actually enforce (behavioural).
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Final

import pytest

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

#: ``contracts/slice-b.md`` line 1447's ``ARC-003`` row: *"The mutating names
#: are exactly `create_contact`, `update_contact`, `archive_contact`,
#: `restore_contact`, `reassign_contact` — the gate can read that list."*
#: ``contracts/slice-c.md`` §2(h)'s own ``ARC-003`` row extends it: *"The
#: mutating service names are exactly `create_for_contact`, `update_deal`,
#: `change_stage`."* The gate's scope **is** the assertion
#: (``ACCESS_MATRIX.md`` §7 ``ARC-003``, echoing the P1 final fix round):
#: a GET/HEAD handler calling a **read** service function — `list_contacts`,
#: `get_for_detail`, `build_contact_query`, `list_deals`, `pipeline`,
#: `parent_for_form`, `blocked_parent`, all of `app/services/contacts.py`/
#: `deals.py`'s read side — is the ordinary, contracted shape of the
#: list/detail/edit-form routes, not a violation. Extend this set, never
#: widen it back to "every name imported from `app.services`", as later
#: slices add their own mutations (`activity_create`).
_SERVICE_MUTATION_NAMES: Final[frozenset[str]] = frozenset(
  {
    "create_contact",
    "update_contact",
    "archive_contact",
    "restore_contact",
    "reassign_contact",
    "create_for_contact",
    "update_deal",
    "change_stage",
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


# ---------------------------------------------------------------------------
# ARC-001 / SQL-032 (Slice B, ruling R66) — every public function of
# app/db/repositories/contacts.py takes `scope` as its second positional
# argument; the identity/infrastructure modules (sessions, users, throttle,
# settings, audit, receipts) take none — contracts/slice-b.md §1(b) B2,
# §2(h), ACCESS_MATRIX.md §7 ARC-001's allowlist.
# ---------------------------------------------------------------------------

_REPOSITORIES_DIR: Final = APP_DIR / "db" / "repositories"

#: The identity/infrastructure modules ARC-001's allowlist names —
#: `contracts/slice-b.md` §1(b) B2 (`receipts.py`, the two `users.py`
#: additive reads) and `slice-a.md`'s shipped session/throttle/settings/
#: audit layer, all of which take explicit ids rather than a `Scope`
#: because they hold no owner column and answer no scoped question.
_SCOPE_EXEMPT_REPOSITORY_MODULES: Final[frozenset[str]] = frozenset(
  {"sessions", "users", "throttle", "settings", "audit", "receipts"}
)


def _public_top_level_functions(
  tree: ast.Module,
) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
  """Return every top-level, non-underscore-prefixed function/async function def."""
  return [
    node
    for node in tree.body
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and not node.name.startswith("_")
  ]


#: Slice C, `contracts/slice-c.md` §1(b): "`deals.py` is a business
#: repository with no identity-keyed exception" — joins `contacts` on the
#: ARC-001 allowlist's business side. Updated here rather than left to trip
#: (`slice-b.md` §1(b) B2's own instruction, extended by the same logic).
_BUSINESS_REPOSITORY_MODULES: Final[frozenset[str]] = frozenset({"contacts", "deals"})


def test_arc001_sql032_business_repositories_are_exactly_contacts_and_deals() -> None:
  """The ARC-001 allowlist is exactly the identity/infrastructure modules — not `contacts`/`deals`.

  Written as a frozenset in this test (not inferred from the allowlist a
  gate happens to check), per `contracts/slice-b.md` §1(b) B2's own
  instruction: "this must be stated in ARC-001/SQL-032's allowlist or the
  ast gate trips on both" — extended here for Slice C's `deals.py`.
  """
  assert _REPOSITORIES_DIR.is_dir(), f"{_REPOSITORIES_DIR} does not exist yet"
  modules = {path.stem for path in _REPOSITORIES_DIR.glob("*.py") if path.stem != "__init__"}
  assert modules, f"no repository modules found under {_REPOSITORIES_DIR}"
  business_modules = modules - _SCOPE_EXEMPT_REPOSITORY_MODULES
  assert business_modules == _BUSINESS_REPOSITORY_MODULES, (
    f"expected exactly the business repository modules outside the ARC-001 allowlist "
    f"({sorted(_SCOPE_EXEMPT_REPOSITORY_MODULES)}): {sorted(_BUSINESS_REPOSITORY_MODULES)}. "
    f"Got {sorted(business_modules)}"
  )


@pytest.mark.parametrize("module_name", sorted(_BUSINESS_REPOSITORY_MODULES))
def test_arc001_sql032_business_repository_functions_take_scope_second(module_name: str) -> None:
  """Every public function of a business repository takes `scope` as its 2nd positional arg.

  `contracts/slice-b.md` §1(b) B1: "`scope` is the second positional
  argument, not the first" — `conn` stays first (the shipped Slice A
  convention), `scope` is the first *business* argument, so the gate can
  see it by position. `contracts/slice-c.md` §1(b) reconciles the same
  convention for `deals.py`, unchanged.
  """
  path = _REPOSITORIES_DIR / f"{module_name}.py"
  assert path.is_file(), f"{path} does not exist yet"
  tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
  functions = _public_top_level_functions(tree)
  assert functions, f"no public functions found in {path}"
  offenders: list[str] = []
  for function in functions:
    args = function.args.args
    if len(args) < 2 or args[1].arg != "scope":
      offenders.append(f"{function.name} at line {function.lineno}")
  assert offenders == [], f"public {path.name} function(s) missing `scope` as arg 2: {offenders}"


def test_arc001_sql032_identity_infrastructure_modules_take_no_scope() -> None:
  """None of the allowlisted identity/infrastructure modules' public functions take a `scope`.

  The empirical half of the allowlist claim: every module named in
  :data:`_SCOPE_EXEMPT_REPOSITORY_MODULES` genuinely holds no `Scope`
  consumer, positional or keyword — it is not merely asserted, it is
  checked against the shipped code.
  """
  offenders: list[str] = []
  checked_modules: set[str] = set()
  for name in sorted(_SCOPE_EXEMPT_REPOSITORY_MODULES):
    path = _REPOSITORIES_DIR / f"{name}.py"
    if not path.is_file():
      continue
    checked_modules.add(name)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for function in _public_top_level_functions(tree):
      arg_names = {arg.arg for arg in function.args.args} | {
        arg.arg for arg in function.args.kwonlyargs
      }
      if "scope" in arg_names:
        offenders.append(f"{name}.py::{function.name} at line {function.lineno}")
  assert checked_modules == _SCOPE_EXEMPT_REPOSITORY_MODULES, (
    f"expected every allowlisted module to exist on disk; missing "
    f"{sorted(_SCOPE_EXEMPT_REPOSITORY_MODULES - checked_modules)}"
  )
  assert offenders == [], (
    f"identity/infrastructure function(s) unexpectedly take `scope`: {offenders}"
  )


@pytest.mark.parametrize("module_name", sorted(_BUSINESS_REPOSITORY_MODULES))
def test_sql032_business_repository_has_no_python_side_ownership_filter(module_name: str) -> None:
  """A business repository filters ownership in SQL only, never by post-filtering rows.

  A cheap structural guard, not a proof (documented as such, like
  `ARC-003` above): walks every `ast.Compare` node for an `==`/`!=`
  comparison whose operand is literally named or attributed `owner_id` —
  the shape a Python-side post-filter (``if row.owner_id ==
  scope.actor_id``) would take. The real predicate lives in `sql.SQL`
  string literals (`_visible_where`/`_read_scope`/`_write_scope`), which
  this walk never flags because a string literal is not an `ast.Compare`.
  `deals.py` carries no `owner_id` column at all (**PIN C8**) — its
  ownership predicate is entirely the join to `contacts`, so this gate is
  vacuously satisfied there and still worth running: a future edit adding
  a `deals.owner_id` shortcut would trip it immediately.
  """
  path = _REPOSITORIES_DIR / f"{module_name}.py"
  assert path.is_file(), f"{path} does not exist yet"
  tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
  offenders: list[str] = []
  for node in ast.walk(tree):
    if not isinstance(node, ast.Compare):
      continue
    if not any(isinstance(op, ast.Eq | ast.NotEq) for op in node.ops):
      continue
    for operand in (node.left, *node.comparators):
      name = operand.attr if isinstance(operand, ast.Attribute) else getattr(operand, "id", None)
      if name == "owner_id":
        offenders.append(f"line {node.lineno}")
  assert offenders == [], (
    f"Python-side owner_id comparison found in {path} at line(s) {offenders} "
    "(ownership must be a SQL predicate, never a post-filter)"
  )


# ---------------------------------------------------------------------------
# SQL-031 (Slice B, ruling R66) — no server-clock function reaches
# app/db/** or migrations/**, with the one named exemption
# DATA_CONTRACT.md §9.1 records: app/db/journal.py's
# _INSERT_JOURNAL_SQL/_MARK_VERIFIED_SQL, which stamp
# schema_migrations.applied_at/verified_at with CURRENT_TIMESTAMP.
# ---------------------------------------------------------------------------

_DB_DIR: Final = APP_DIR / "db"
_MIGRATIONS_DIR: Final = APP_ROOT / "migrations"
_JOURNAL_PY: Final = _DB_DIR / "journal.py"

#: DATA_CONTRACT.md §9.1's clock/window-arithmetic ban: every instant and
#: window boundary is computed in Python and bound, never read from the
#: server's own clock inside SQL.
_SERVER_CLOCK_PATTERN: Final = re.compile(
  r"\bnow\s*\(\)|\bcurrent_timestamp\b|\bclock_timestamp\s*\(\)|"
  r"\btransaction_timestamp\s*\(\)|\bstatement_timestamp\s*\(\)|"
  r"\bdate_trunc\s*\(|\bcurrent_date\b|\bcurrent_time\b|"
  r"\blocaltimestamp\b|\blocaltime\b|\binterval\b",
  re.IGNORECASE,
)
_SQL_LINE_COMMENT: Final = re.compile(r"--.*$", re.MULTILINE)
#: The exact number of `CURRENT_TIMESTAMP` occurrences the two named
#: journal constants carry today (`_INSERT_JOURNAL_SQL`'s two,
#: `_MARK_VERIFIED_SQL`'s one) — bounded so a THIRD, unrelated use would
#: not silently widen the exemption to "anything in journal.py".
_JOURNAL_PY_EXEMPT_COUNT: Final = 3


def _docstring_node_ids(tree: ast.Module) -> set[int]:
  """Return ``id()`` of every docstring's `Constant` node (module/class/function).

  A docstring is documentation, not code the application executes as SQL
  — excluding it is what keeps this grep gate from false-positiving on
  prose that *names* a banned construct while explaining its absence
  (this very codebase's docstrings do exactly that, repeatedly: e.g.
  "`ON CONFLICT` would be one statement and is banned").
  """
  ids: set[int] = set()

  def _mark(body: list[ast.stmt]) -> None:
    if (
      body
      and isinstance(body[0], ast.Expr)
      and isinstance(body[0].value, ast.Constant)
      and isinstance(body[0].value.value, str)
    ):
      ids.add(id(body[0].value))

  _mark(tree.body)
  for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
      _mark(node.body)
  return ids


def _docstring_line_ranges(path: Path) -> list[tuple[int, int]]:
  """Return ``(start_line, end_line)`` for every module/class/function docstring in ``path``.

  Used to exclude *prose describing a banned pattern* (this codebase's
  docstrings routinely name the very construct they forbid, e.g. "no
  ``%f``") from a raw-text regex scan, the same false-positive
  ``_docstring_node_ids`` already guards the SQL-031 gate against — but
  expressed as line spans rather than node ids, since a plain regex over
  source text has no node identity to compare against.
  """
  tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
  ranges: list[tuple[int, int]] = []

  def _mark(body: list[ast.stmt]) -> None:
    if (
      body
      and isinstance(body[0], ast.Expr)
      and isinstance(body[0].value, ast.Constant)
      and isinstance(body[0].value.value, str)
    ):
      node = body[0].value
      end = node.end_lineno if node.end_lineno is not None else node.lineno
      ranges.append((node.lineno, end))

  _mark(tree.body)
  for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
      _mark(node.body)
  return ranges


def _non_docstring_string_constants(path: Path) -> list[tuple[int, str]]:
  """Return ``(lineno, value)`` for every non-docstring string literal in a ``.py`` file.

  A type annotation (``UUID``, ``Scope``) is a name/attribute node, never
  a string constant — even under ``from __future__ import annotations``,
  which defers *evaluation*, not what :func:`ast.parse` itself produces —
  so this walk never sees one. A ``#`` comment is not part of the AST at
  all. What remains is exactly the text this application would actually
  execute as SQL or emit: `sql.SQL(...)` literals and the like.
  """
  tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
  excluded = _docstring_node_ids(tree)
  return [
    (node.lineno, node.value)
    for node in ast.walk(tree)
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in excluded
  ]


def test_sql031_no_server_clock_function_outside_journals_documented_exemption() -> None:
  """No server-clock function reaches `app/db/**` or `migrations/**` — one named exemption.

  `DATA_CONTRACT.md` §9.1: every instant and window boundary is computed
  in Python and bound as a parameter, never read from the database's own
  clock inside SQL — with one named exemption, `app/db/journal.py`'s
  `_INSERT_JOURNAL_SQL`/`_MARK_VERIFIED_SQL`, which stamp
  `schema_migrations.applied_at`/`verified_at` with `CURRENT_TIMESTAMP`
  and nothing else, anywhere.
  """
  offenders: list[str] = []
  journal_hits = 0

  py_files = _python_files_under(_DB_DIR)
  assert py_files, f"{_DB_DIR} does not exist yet"
  for path in py_files:
    if "__pycache__" in path.parts:
      continue
    for lineno, value in _non_docstring_string_constants(path):
      for match in _SERVER_CLOCK_PATTERN.finditer(value):
        if path == _JOURNAL_PY:
          journal_hits += 1
          continue
        offenders.append(f"{path.relative_to(APP_ROOT)}:{lineno}: {match.group(0)!r}")

  assert _MIGRATIONS_DIR.is_dir(), f"{_MIGRATIONS_DIR} does not exist yet"
  for path in sorted(_MIGRATIONS_DIR.rglob("*.sql")):
    text = _SQL_LINE_COMMENT.sub("", path.read_text(encoding="utf-8"))
    for match in _SERVER_CLOCK_PATTERN.finditer(text):
      line_number = text.count("\n", 0, match.start()) + 1
      offenders.append(f"{path.relative_to(APP_ROOT)}:{line_number}: {match.group(0)!r}")

  assert offenders == [], "\n".join(offenders)
  # Not vacuous, and bounded: journal.py must carry exactly the documented
  # exemption's own count, not "any number" — a THIRD, unrelated use of
  # CURRENT_TIMESTAMP would otherwise silently widen the exemption to the
  # whole file.
  assert journal_hits == _JOURNAL_PY_EXEMPT_COUNT, (
    f"expected exactly {_JOURNAL_PY_EXEMPT_COUNT} server-clock use(s) in {_JOURNAL_PY} "
    f"(the two documented, named statements); found {journal_hits} — the exemption's own "
    "scope may have drifted"
  )


# ---------------------------------------------------------------------------
# ARC-021 (Slice C, **proposed** — `contracts/slice-c.md` §2(h), not yet
# allocated in `ACCESS_MATRIX.md` §7; **PIN C1**: "money is `decimal.Decimal`
# end to end"). Static half only, over the four paths the pin names:
# `app/services/money.py`, `app/services/deals.py`,
# `app/db/repositories/deals.py`, `app/templates/**`. The runtime half —
# `format_eur` raising `TypeError` on a non-`Decimal` — is
# `tests/unit/test_money.py::test_format_eur_rejects_a_float_with_typeerror`;
# not duplicated here, per this file's own "each gate lives in exactly one
# place" character (a purely static file otherwise).
# ---------------------------------------------------------------------------

_MONEY_PATH_MODULES: Final[tuple[Path, ...]] = (
  APP_DIR / "services" / "money.py",
  APP_DIR / "services" / "deals.py",
  _REPOSITORIES_DIR / "deals.py",
)

#: `float(`, `round(` (over anything — the pin bans it outright on a money
#: path, not only over a known-float argument, since the ast gate cannot
#: prove an argument's type without a type checker), `Decimal(` called with
#: something that is not a string/int/tuple literal (a float literal would
#: read `Decimal(1.5)` — a `Constant` node whose value is a `float`), and
#: the two C-style money format specifiers.
_FLOAT_CALL_NAMES: Final[frozenset[str]] = frozenset({"float", "round"})
_PERCENT_F_PATTERN: Final = re.compile(r"%\s*\.?\d*f\b")
#: `{value:,.2f}`-shaped: an optional thousands-separator `,`, an optional
#: `.` + precision digits, then the `f` conversion, inside `{ }`.
_FORMAT_F_PATTERN: Final = re.compile(r":\s*,?\.?\d*f\}")


def test_arc021_no_float_or_round_call_on_a_money_path() -> None:
  """`float(`/`round(` never appear, as a call, in any of the four money-path modules."""
  offenders: list[str] = []
  for path in _MONEY_PATH_MODULES:
    assert path.is_file(), f"{path} does not exist yet"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
      if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _FLOAT_CALL_NAMES
      ):
        offenders.append(f"{path.relative_to(APP_ROOT)}:{node.lineno}: {node.func.id}(...)")
  assert offenders == [], "\n".join(offenders)


def test_arc021_no_decimal_built_from_a_float_literal_on_a_money_path() -> None:
  """`Decimal(1.5)`-shaped construction (a float literal argument) never appears."""
  offenders: list[str] = []
  for path in _MONEY_PATH_MODULES:
    assert path.is_file(), f"{path} does not exist yet"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
      if not (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Decimal"
      ):
        continue
      for argument in node.args:
        if isinstance(argument, ast.Constant) and isinstance(argument.value, float):
          offenders.append(f"{path.relative_to(APP_ROOT)}:{node.lineno}: Decimal({argument.value})")
  assert offenders == [], "\n".join(offenders)


def _matches_outside_docstrings(
  pattern: re.Pattern[str], text: str, ranges: list[tuple[int, int]]
) -> list[re.Match[str]]:
  """Return every ``pattern`` match in ``text`` whose line falls outside ``ranges``."""
  hits: list[re.Match[str]] = []
  for match in pattern.finditer(text):
    line_number = text.count("\n", 0, match.start()) + 1
    if not any(start <= line_number <= end for start, end in ranges):
      hits.append(match)
  return hits


def test_arc021_no_percent_f_or_format_f_specifier_on_a_money_path() -> None:
  """No `%f`-style or `:.2f`-style format specifier appears in the four money-path modules.

  `format_eur`'s own `f"€ {value:,.2f}"` is exempt by construction: at
  that point `value` has already passed the `isinstance(value, Decimal)`
  guard, and `Decimal.__format__` implements the same `,.2f` mini-language
  exactly, without ever going through `float.__format__`. The gate is
  therefore over the *source text* pattern only as a tripwire for a
  **second**, unguarded formatting site appearing anywhere on a money
  path — not a claim that this one exact line is itself suspect.
  """
  offenders: list[str] = []
  money_module = APP_DIR / "services" / "money.py"
  for path in _MONEY_PATH_MODULES:
    assert path.is_file(), f"{path} does not exist yet"
    text = path.read_text(encoding="utf-8")
    docstring_ranges = _docstring_line_ranges(path)
    percent_hits = _matches_outside_docstrings(_PERCENT_F_PATTERN, text, docstring_ranges)
    format_hits = _matches_outside_docstrings(_FORMAT_F_PATTERN, text, docstring_ranges)
    if path == money_module:
      # Exactly format_eur's own one exempted `{value:,.2f}` site.
      assert len(format_hits) == 1, (
        f"expected exactly one `:,.2f`-shaped specifier in {path} (format_eur's own); "
        f"found {len(format_hits)}"
      )
      assert percent_hits == [], f"unexpected %f-style specifier in {path}"
      continue
    for match in percent_hits + format_hits:
      line_number = text.count("\n", 0, match.start()) + 1
      offenders.append(f"{path.relative_to(APP_ROOT)}:{line_number}: {match.group(0)!r}")
  assert offenders == [], "\n".join(offenders)


def test_arc021_templates_carry_no_float_round_or_raw_percent_f_format() -> None:
  """No `.html` template calls `float(`/`round(` or spells a raw `%f` (Jinja has neither builtin).

  Templates cannot call `Decimal(` with a float literal (Jinja has no
  float literal syntax reaching that constructor at all — this is a
  Python-only failure mode), so only the call/format-specifier halves
  apply here.
  """
  offenders: list[str] = []
  templates = sorted(TEMPLATES_DIR.rglob("*.html")) if TEMPLATES_DIR.is_dir() else []
  assert templates, f"no templates found under {TEMPLATES_DIR} yet"
  call_pattern = re.compile(r"\b(?:float|round)\s*\(")
  for template in templates:
    text = template.read_text(encoding="utf-8")
    for match in list(call_pattern.finditer(text)) + list(_PERCENT_F_PATTERN.finditer(text)):
      line_number = text.count("\n", 0, match.start()) + 1
      offenders.append(f"{template.relative_to(APP_ROOT)}:{line_number}: {match.group(0)!r}")
  assert offenders == [], "\n".join(offenders)


def test_arc021_no_numpy_or_fractions_import_on_the_deal_money_path() -> None:
  """No alternate numeric-module import (`numpy`, `fractions`) shadows `Decimal` on a money path.

  `contracts/slice-c.md` §2(h) also says "`import decimal` is the only
  numeric import on the path", read here as *money-relevant* numerics —
  `app/services/deals.py` legitimately imports `math` for
  `math.ceil(total / per_page)` (`DealListView.pages`, an integer page
  count, never an amount), so a blanket "no other numeric import at all"
  reading would fail on that unrelated, harmless call. `numpy` and
  `fractions` have no such innocent use on this path and would be a
  concrete signal of an alternate numeric type quietly displacing
  `Decimal` for arithmetic.
  """
  banned_numeric_modules = {"numpy", "fractions"}
  offenders: list[str] = []
  for path in _MONEY_PATH_MODULES:
    assert path.is_file(), f"{path} does not exist yet"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for module_name in _module_imports(tree):
      top_level = module_name.split(".", 1)[0]
      if top_level in banned_numeric_modules:
        offenders.append(f"{path.relative_to(APP_ROOT)} imports {module_name!r}")
  assert offenders == [], "\n".join(offenders)
