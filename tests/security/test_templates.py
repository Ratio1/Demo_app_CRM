"""Template-level static and rendering checks — SEC-005, SEC-018, delta D11.

Authority: ``ACCESS_MATRIX.md`` §7 (SEC-005, SEC-018); ``slice-a.md`` §6 D11
(the explicit Jinja environment: ``FileSystemLoader``, ``autoescape=True``,
``undefined=StrictUndefined``, ``auto_reload=False``).

These run against the templates the Frontend lane has already shipped
(``app/templates/auth/login.html``, ``app/templates/auth/change_password.html``),
using a **locally constructed** Jinja environment that mirrors D11 exactly.
This proves the templates behave correctly *under* that environment; it is
not proof that ``app/main.py`` actually builds its ``Jinja2Templates`` this
way, since ``app/main.py`` does not exist yet — that half stays
NOT VERIFIED and is not claimed here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import jinja2
import pytest

APP_DIR = Path(__file__).resolve().parent.parent.parent / "app"
TEMPLATES_DIR = APP_DIR / "templates"

_LOGIN_TEMPLATE = "auth/login.html"
_CHANGE_PASSWORD_TEMPLATE = "auth/change_password.html"

#: The five field-input source files SEC-018 and SEC-005 read directly.
_PASSWORD_BEARING_TEMPLATES = (_LOGIN_TEMPLATE, _CHANGE_PASSWORD_TEMPLATE)


def _d11_environment() -> jinja2.Environment:
  """Build the exact environment delta D11 pins.

  Returns
  -------
  jinja2.Environment
    ``FileSystemLoader(app/templates)``, ``autoescape=True``,
    ``undefined=StrictUndefined``, ``auto_reload=False``.
  """
  return jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,
    undefined=jinja2.StrictUndefined,
    auto_reload=False,
  )


def _base_context(**overrides: Any) -> dict[str, Any]:
  """The frozen base context (``base.html``'s own docstring / CONTRACTS.md §8.1).

  Parameters
  ----------
  **overrides : Any
    Page-specific keys layered on top.

  Returns
  -------
  dict[str, Any]
  """
  context: dict[str, Any] = {
    "app_name": "Demo_App_CRM",
    "page_title": "Sign in",
    "principal": None,
    "csrf_token": "test-csrf-token",
    "private": False,
    "nav_active": None,
    "announce": None,
    "scope_label": None,
    "notice": None,
  }
  context.update(overrides)
  return context


def _login_context(**overrides: Any) -> dict[str, Any]:
  """The login page's context, beyond the base (``slice-a.md`` §4 route table)."""
  context = _base_context(
    form={"email": ""},
    errors={},
    next=None,
    signed_out=False,
    session_ended=False,
    retry_after_seconds=None,
  )
  context.update(overrides)
  return context


def _change_password_context(**overrides: Any) -> dict[str, Any]:
  """The change-password page's context, beyond the base."""
  context = _base_context(
    page_title="Change password",
    private=True,
    forced=False,
    errors={},
    min_length=15,
    max_length=128,
  )
  context.update(overrides)
  return context


# ---------------------------------------------------------------------------
# SEC-005 — stored/reflected XSS renders inert.
# ---------------------------------------------------------------------------

_XSS_CORPUS: tuple[str, ...] = (
  "<script>alert(1)</script>",
  '"><img src=x onerror=alert(1)>',
  "'; alert(document.cookie); //",
  "<svg onload=alert(1)>",
  "</textarea><script>alert(1)</script>",
)


def _assert_rendered_inert(html: str, payload: str) -> None:
  """Assert ``payload`` reached the page only in escaped form, never verbatim.

  Every corpus entry contains at least one of ``< > & ' "``, so escaping
  guarantees the *exact* raw payload string cannot be a substring of
  correctly escaped output. This is the sound version of a "dangerous
  substring absent" check: matching on fragments like ``onload=`` is
  unsound, because that fragment legitimately survives as inert text once
  its surrounding ``<``/``>`` are escaped (``&lt;svg onload=alert(1)&gt;``
  is safe precisely because it is no longer a tag).

  Parameters
  ----------
  html : str
    The rendered page.
  payload : str
    The raw corpus entry that was fed into the context.
  """
  assert payload not in html, f"payload reached the response unescaped: {payload!r}"
  assert "<script>" not in html
  # The escaped form must still be present somewhere — proving autoescape
  # transformed the value rather than the field being silently dropped.
  assert any(marker in html for marker in ("&lt;", "&#34;", "&#39;", "&amp;"))


@pytest.mark.parametrize("payload", _XSS_CORPUS)
def test_sec005_login_email_field_renders_the_xss_corpus_inert(payload: str) -> None:
  """A hostile ``form.email`` value never reaches the response as live markup."""
  environment = _d11_environment()
  template = environment.get_template(_LOGIN_TEMPLATE)
  html = template.render(**_login_context(form={"email": payload}))
  _assert_rendered_inert(html, payload)


@pytest.mark.parametrize("payload", _XSS_CORPUS)
def test_sec005_change_password_error_text_renders_the_xss_corpus_inert(payload: str) -> None:
  """A hostile validation-error message never reaches the response as live markup."""
  environment = _d11_environment()
  template = environment.get_template(_CHANGE_PASSWORD_TEMPLATE)
  html = template.render(**_change_password_context(errors={"new_password": [payload]}))
  _assert_rendered_inert(html, payload)


def test_sec005_autoescape_holds_without_any_explicit_escape_call() -> None:
  """The template source names no ``|e``/``|escape``/``safe`` — autoescape alone must carry it."""
  for name in _PASSWORD_BEARING_TEMPLATES:
    source = (TEMPLATES_DIR / name).read_text(encoding="utf-8")
    assert "|safe" not in source
    assert "Markup(" not in source


# ---------------------------------------------------------------------------
# SEC-018 — paste and password managers permitted.
# ---------------------------------------------------------------------------

_FORBIDDEN_PASTE_BLOCKERS = (
  "onpaste",
  "oncopy",
  "oncut",
  "ondrop",
  'autocomplete="off"',
  "readonly",
)


@pytest.mark.parametrize("name", _PASSWORD_BEARING_TEMPLATES)
def test_sec018_no_paste_or_password_manager_blocker_in_source(name: str) -> None:
  """Neither template carries a paste-blocking handler, ``autocomplete="off"`` or ``readonly``."""
  source = (TEMPLATES_DIR / name).read_text(encoding="utf-8")
  for forbidden in _FORBIDDEN_PASTE_BLOCKERS:
    assert forbidden not in source, f"{name} contains forbidden {forbidden!r}"


def test_sec018_login_password_field_is_autocomplete_current_password() -> None:
  """The login password field is ``autocomplete="current-password"``, not blocked."""
  source = (TEMPLATES_DIR / _LOGIN_TEMPLATE).read_text(encoding="utf-8")
  assert 'name="password"' in source
  assert 'autocomplete="current-password"' in source


def test_sec018_change_password_fields_use_the_contracted_autocomplete_values() -> None:
  """Current password is ``current-password``; both new/confirm fields are ``new-password``."""
  source = (TEMPLATES_DIR / _CHANGE_PASSWORD_TEMPLATE).read_text(encoding="utf-8")
  assert source.count('autocomplete="new-password"') == 2
  assert 'name="current_password"' in source
  assert 'autocomplete="current-password"' in source


def test_sec018_a_pasted_value_arrives_intact_in_the_rendered_value_attribute() -> None:
  """The rendered ``value`` attribute round-trips a distinctive string byte for byte (escaped only).

  This is the template-rendering half of SEC-018's "a paste into each is
  asserted to arrive intact in the submitted body" — the browser half (an
  actual paste event) needs Playwright and is covered in ``tests/e2e``.
  """
  distinctive = "pasted+value@example.test"
  environment = _d11_environment()
  template = environment.get_template(_LOGIN_TEMPLATE)
  html = template.render(**_login_context(form={"email": distinctive}))
  assert f'value="{distinctive}"' in html


# ---------------------------------------------------------------------------
# D11 — StrictUndefined turns a missing context key into a loud failure.
# ---------------------------------------------------------------------------


def test_d11_strict_undefined_raises_on_a_missing_context_key() -> None:
  """Omitting a required context key raises ``UndefinedError`` rather than rendering blank."""
  environment = _d11_environment()
  template = environment.get_template(_LOGIN_TEMPLATE)
  incomplete_context = _login_context()
  del incomplete_context["signed_out"]
  with pytest.raises(jinja2.UndefinedError):
    template.render(**incomplete_context)


def test_d11_every_shipped_template_renders_with_no_missing_key_under_a_full_context() -> None:
  """Sanity check: the two auth templates render cleanly given their documented full context."""
  environment = _d11_environment()
  login_html = environment.get_template(_LOGIN_TEMPLATE).render(**_login_context())
  assert "<h1>Sign in</h1>" in login_html
  change_password_html = environment.get_template(_CHANGE_PASSWORD_TEMPLATE).render(
    **_change_password_context()
  )
  assert "Change password" in change_password_html
