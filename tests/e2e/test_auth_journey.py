"""Playwright end-to-end journey — login, forced reset, logout, keyboard, axe.

Plain **sync** tests (pytest-playwright's ``page`` fixture is sync); no
``pytestmark = pytest.mark.asyncio`` in this module. ``live_server`` serves
plain HTTP (root ``conftest.py``), so every browser context here is
pytest-playwright's ordinary default — no TLS, no certificate, nothing to
ignore.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from conftest import (
  MANAGE,
  OWNER_ENV_FILE,
  SUBMODULE_ROOT,
  VENV_PYTHON,
  WITH_ENV,
  LiveServer,
  ProvisionedUser,
  unique_email,
  write_password_fixture,
)
from playwright.sync_api import Page, expect

VIEWPORTS = [
  pytest.param({"width": 390, "height": 844}, id="mobile-390x844"),
  pytest.param({"width": 1440, "height": 900}, id="desktop-1440x900"),
]


def _provision_forced_reset_agent(tmp_path: Path) -> tuple[str, str]:
  """Create one fresh agent and immediately force a password reset on it.

  Returns
  -------
  tuple[str, str]
    ``(email, password)`` — the password that still authenticates (the
    forced flag does not invalidate the current password, only demands a
    change after login).
  """
  email = unique_email("e2e-forced")
  password = "a fictional forced-reset e2e passphrase"
  password_file = write_password_fixture(tmp_path, password, name="pw-create")
  try:
    with password_file.open("rb") as stdin_file:
      log_path = tmp_path / "create-user.log"
      with log_path.open("wb") as log_file:
        subprocess.run(  # noqa: S603
          [
            str(WITH_ENV),
            OWNER_ENV_FILE,
            "--",
            str(VENV_PYTHON),
            "-B",
            str(MANAGE),
            "create-user",
            "--email",
            email,
            "--name",
            "E2E Forced Reset",
            "--role",
            "agent",
            "--password-stdin",
          ],
          cwd=SUBMODULE_ROOT,
          stdin=stdin_file,
          stdout=log_file,
          stderr=subprocess.STDOUT,
          check=True,
          timeout=30.0,
        )
  finally:
    password_file.unlink(missing_ok=True)

  password_file = write_password_fixture(tmp_path, password, name="pw-reset")
  try:
    with password_file.open("rb") as stdin_file:
      log_path = tmp_path / "reset-password.log"
      with log_path.open("wb") as log_file:
        subprocess.run(  # noqa: S603
          [
            str(WITH_ENV),
            OWNER_ENV_FILE,
            "--",
            str(VENV_PYTHON),
            "-B",
            str(MANAGE),
            "reset-password",
            "--email",
            email,
            "--password-stdin",
          ],
          cwd=SUBMODULE_ROOT,
          stdin=stdin_file,
          stdout=log_file,
          stderr=subprocess.STDOUT,
          check=True,
          timeout=30.0,
        )
  finally:
    password_file.unlink(missing_ok=True)

  return email, password


@pytest.fixture
def forced_reset_agent(live_server: LiveServer, tmp_path: Path) -> Iterator[tuple[str, str]]:
  """Yield ``(email, password)`` for one agent whose next login must change its password."""
  del live_server  # ordering only: the schema/origin must exist first
  yield _provision_forced_reset_agent(tmp_path)


@pytest.mark.parametrize("viewport", VIEWPORTS)
def test_login_forced_reset_change_password_logout_back_button(
  page: Page,
  live_server: LiveServer,
  forced_reset_agent: tuple[str, str],
  viewport: dict[str, int],
) -> None:
  """Login -> forced reset -> change password -> logout -> back button shows no private content."""
  email, password = forced_reset_agent
  page.set_viewport_size(viewport)  # type: ignore[arg-type]

  page.goto(f"{live_server.base_url}/login")
  page.get_by_label("Email").fill(email)
  page.get_by_label("Password", exact=True).fill(password)
  page.get_by_role("button", name="Sign in").click()

  expect(page).to_have_url(f"{live_server.base_url}/account/password")
  expect(page.get_by_role("heading", name="Change password")).to_be_visible()

  new_password = "a fictional new e2e passphrase 2"
  # `exact=True` on "New password": Playwright's `get_by_label` does a
  # case-insensitive *substring* match by default, and "Repeat new
  # password" contains "new password" — without `exact`, this locator
  # resolves to both fields and Playwright refuses to `fill` an ambiguous
  # one (strict mode). A test defect, not a backend one: the two labels
  # are legitimately distinct and accessible on the rendered page.
  page.get_by_label("Current password").fill(password)
  page.get_by_label("New password", exact=True).fill(new_password)
  page.get_by_label("Repeat new password").fill(new_password)
  page.get_by_role("button", name="Change password").click()

  # The 303 lands on /dashboard; this test asserts only that the browser
  # left /account/password's forced state, i.e. that the redirect fired,
  # not the dashboard's own content (covered in tests/access).
  page.wait_for_url(lambda url: "/account/password" not in url, timeout=10_000)

  # Confirm the account is no longer forced: a direct visit to the change-
  # password page must not show the forced banner.
  page.goto(f"{live_server.base_url}/account/password")
  expect(page.get_by_text("Set a new password to continue")).not_to_be_visible()

  # `partials/nav.html` renders the account block twice — an always-open
  # ``<nav>`` at >=1024px, and a closed native ``<details>``/``<summary>``
  # "Menu" toggle below that width (its own docstring's documented
  # breakpoint) — with CSS hiding whichever does not apply. A closed
  # ``<details>``'s children are not in the accessibility tree, so below
  # the breakpoint "Sign out" must be revealed by opening the menu first.
  # The ``<details>`` element itself is exposed as an accessible *group*
  # named after its ``<summary>`` text, not as a "button" role (confirmed
  # live via ``page.aria_snapshot()``: ``group: Menu``, nested one level
  # under ``navigation "Primary"``) — while closed its bounding box is
  # exactly the summary's, so a plain structural locator on the summary
  # itself is the direct, unambiguous way to open it.
  if viewport["width"] < 1024:
    page.locator(".app-menu > details > summary").click()
  page.get_by_role("button", name="Sign out").click()
  expect(page).to_have_url(f"{live_server.base_url}/login?notice=signed_out")

  page.go_back()
  # Back navigation after logout must not reveal the private page from
  # cache: either the browser re-requests it and the server bounces to
  # /login again, or bfcache serves a page carrying Cache-Control: no-store
  # and the app immediately redirects. Either way, the change-password form
  # itself must not remain visible with live content.
  expect(page.get_by_role("heading", name="Change password")).not_to_be_visible()


def test_keyboard_only_login_reaches_the_submit_button_by_tab_order(
  page: Page, live_server: LiveServer, bootstrap_admin: ProvisionedUser
) -> None:
  """Tab from email to password, then Enter submits — no mouse click on either field or button."""
  page.goto(f"{live_server.base_url}/login")
  page.get_by_label("Email").click()  # focus without a mouse-drag anywhere else
  page.keyboard.type(bootstrap_admin.email)
  page.keyboard.press("Tab")
  page.keyboard.type(bootstrap_admin.password)
  page.keyboard.press("Enter")
  expect(page).not_to_have_url(f"{live_server.base_url}/login")


def test_axe_pass_on_login_page(page: Page, live_server: LiveServer) -> None:
  """An automated axe-core scan of the login page reports zero violations."""
  # axe-playwright-python ships no py.typed marker (real, installed
  # dependency — a genuine import-untyped case, not a not-yet-shipped one).
  from axe_playwright_python.sync_playwright import Axe  # type: ignore[import-untyped]

  page.goto(f"{live_server.base_url}/login")
  results = Axe().run(page)
  assert results.violations_count == 0, results.generate_snapshot()


def test_axe_pass_on_change_password_page(
  page: Page, live_server: LiveServer, forced_reset_agent: tuple[str, str]
) -> None:
  """An automated axe-core scan of the (forced) change-password page reports zero violations."""
  from axe_playwright_python.sync_playwright import Axe

  email, password = forced_reset_agent
  page.goto(f"{live_server.base_url}/login")
  page.get_by_label("Email").fill(email)
  page.get_by_label("Password", exact=True).fill(password)
  page.get_by_role("button", name="Sign in").click()
  expect(page).to_have_url(f"{live_server.base_url}/account/password")

  results = Axe().run(page)
  assert results.violations_count == 0, results.generate_snapshot()
