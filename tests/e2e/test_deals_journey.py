"""Deals Playwright journey — contact -> new deal -> edit -> move -> Won -> pipeline, keyboard, axe.

Authority: ``ACCESS_MATRIX.md`` §7 (`PRD-001`); ``UX_FLOWS.md`` §4.7 (S7
deal list / S8 pipeline / S9 deal editor / S10 deal detail), §4.8 (the
accessible, non-drag stage-change control, R22), §7 (acceptance
checklist); ``contracts/slice-c.md`` §2(c) (route table), §2(d) (the
stage control's exact fields), §2(e) (the contact detail's `#deals`
region is a full-page render, never enhanced).

**Locator note**, same posture as ``test_contacts_journey.py``'s own:
every locator below is read off the **shipped** templates
(``app/templates/deals/*.html``, ``app/templates/partials/stage_control.html``,
``app/templates/partials/confirm.html``, ``app/templates/partials/pipeline.html``,
``app/templates/contacts/detail.html``'s `#deals` region) rather than
guessed from copy ids alone, since those templates now exist. A locator
failure here is either a real regression or the markup moved since this
was written — check the named template first.
"""

from __future__ import annotations

import re
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import (
  MANAGE,
  OWNER_ENV_FILE,
  SUBMODULE_ROOT,
  VENV_PYTHON,
  WITH_ENV,
  LiveServer,
)
from playwright.sync_api import Page, expect

VIEWPORTS = [
  pytest.param({"width": 390, "height": 844}, id="mobile-390x844"),
  pytest.param({"width": 1440, "height": 900}, id="desktop-1440x900"),
]


@pytest.fixture
def browser_context_args(browser_context_args: dict[str, Any]) -> dict[str, Any]:
  """Extend pytest-playwright's default context args with ``ignore_https_errors``."""
  return {**browser_context_args, "ignore_https_errors": True}


@pytest.fixture
def ready_agent(live_server: LiveServer, tmp_path: Path) -> Iterator[tuple[str, str]]:
  """Yield ``(email, first_password)`` for an agent whose *next* login is still forced.

  Mirrors ``tests/e2e/test_contacts_journey.py``'s fixture of the same
  name and shape (each e2e module keeps its own copy, matching that
  file's own convention rather than a cross-module import).
  """
  del live_server
  email = f"e2e-deals+{uuid.uuid4().hex[:10]}@example.test"
  password = "a fictional e2e deals agent passphrase"
  password_file = tmp_path / "pw-create"
  password_file.write_text(password + "\n", encoding="utf-8")
  password_file.chmod(0o600)
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
            "E2E Deals Agent",
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
  yield email, password


def _sign_in_and_complete_forced_reset(page: Page, base_url: str, email: str, password: str) -> str:
  """Log in, complete the mandatory forced password change, return the new password."""
  page.goto(f"{base_url}/login")
  page.get_by_label("Email").fill(email)
  page.get_by_label("Password", exact=True).fill(password)
  page.get_by_role("button", name="Sign in").click()
  expect(page).to_have_url(f"{base_url}/account/password")

  new_password = f"a fictional e2e post-reset passphrase {uuid.uuid4().hex[:8]}"
  page.get_by_label("Current password").fill(password)
  page.get_by_label("New password", exact=True).fill(new_password)
  page.get_by_label("Repeat new password").fill(new_password)
  page.get_by_role("button", name="Change password").click()
  page.wait_for_url(lambda url: "/account/password" not in url, timeout=10_000)
  return new_password


def _create_contact(page: Page, base_url: str, *, name: str) -> str:
  """Create one fictional contact through the real form, return its detail URL."""
  page.goto(f"{base_url}/contacts/new")
  page.get_by_label("Full name").fill(name)
  page.get_by_label("Company").fill("Northwind SRL")
  page.get_by_label("Work email").fill(f"deal-e2e+{uuid.uuid4().hex[:8]}@example.test")
  page.get_by_role("radio", name="Lead").check()
  page.get_by_role("button", name="Save contact").click()
  expect(page).to_have_url(re.compile(r"/contacts/.*notice=contact_created"))
  return page.url.split("?", 1)[0]


@pytest.mark.parametrize("viewport", VIEWPORTS)
def test_prd001_contact_to_deal_edit_move_won_and_pipeline_journey(
  page: Page,
  live_server: LiveServer,
  ready_agent: tuple[str, str],
  viewport: dict[str, int],
) -> None:
  """contact -> new deal -> edit -> move to proposal -> Won -> pipeline shows it under Won."""
  page.set_viewport_size(viewport)  # type: ignore[arg-type]
  email, first_password = ready_agent
  password = _sign_in_and_complete_forced_reset(page, live_server.base_url, email, first_password)
  del password

  contact_url = _create_contact(page, live_server.base_url, name="Beatrix Kiddo")

  # --- New deal, from the contact workspace's #deals region -------------
  page.goto(contact_url)
  expect(page.get_by_role("heading", name="Deals")).to_be_visible()
  page.get_by_role("link", name="Add deal").click()
  expect(page.get_by_role("heading", name="New deal")).to_be_visible()
  page.get_by_label("Title").fill("Northwind platform expansion")
  page.get_by_label("Amount").fill("1250.00")
  page.get_by_role("button", name="Save deal").click()
  expect(page).to_have_url(re.compile(r"/contacts/.*notice=deal_created#deal-"))
  # `get_by_text` alone is ambiguous here: the deal card's own title link
  # AND the stage control's `Move "{title}" to` <label> both contain the
  # title text (`app/templates/contacts/detail.html`,
  # `partials/stage_control.html`) — the link role scopes to the one
  # unambiguous occurrence.
  expect(page.get_by_role("link", name="Northwind platform expansion", exact=True)).to_be_visible()
  expect(page.get_by_text("€ 1,250.00")).to_be_visible()

  # --- Edit -----------------------------------------------------------------
  page.get_by_role("link", name="Northwind platform expansion", exact=True).click()
  expect(page.get_by_role("heading", name="Northwind platform expansion")).to_be_visible()
  deal_url = page.url.split("?", 1)[0]
  page.get_by_role("link", name="Edit deal").click()
  expect(page.get_by_role("heading", name="Edit deal")).to_be_visible()
  page.get_by_label("Title").fill("Northwind platform expansion (renamed)")
  page.get_by_role("button", name="Save deal").click()
  expect(page).to_have_url(re.compile(r"notice=deal_saved"))
  expect(page.get_by_role("heading", name="Northwind platform expansion (renamed)")).to_be_visible()

  # --- Move to Proposal, through the real <select> + Move form ----------
  move_label = page.get_by_label('Move "Northwind platform expansion (renamed)" to')
  move_label.select_option(label="Proposal")
  page.get_by_role("button", name="Move").click()
  expect(page).to_have_url(re.compile(r"notice=deal_moved"))

  # --- Mark as Won, through the <details> confirmation -------------------
  page.goto(deal_url)
  page.get_by_text("Mark as won…").click()  # opens the <details> disclosure
  page.get_by_role("button", name="Mark as won").click()
  expect(page).to_have_url(re.compile(r"notice=deal_won"))

  page.goto(deal_url)
  expect(page.get_by_text("Won deals cannot be moved to another stage.")).to_be_visible()

  # --- Pipeline: the Won column shows it, with the right sum -------------
  page.goto(f"{live_server.base_url}/deals/pipeline")
  expect(page.get_by_role("heading", name="Pipeline")).to_be_visible()
  won_heading = page.locator("#col-won-heading")
  expect(won_heading).to_contain_text("€ 1,250.00")
  won_column = page.locator("section.pipeline-column", has=won_heading)
  expect(won_column.get_by_text("Northwind platform expansion (renamed)")).to_be_visible()


def test_keyboard_only_stage_change_no_drag(
  page: Page, live_server: LiveServer, ready_agent: tuple[str, str]
) -> None:
  """A stage move is driven entirely by Tab/Arrow/Enter on the real `<select>` + button — no drag.

  R22: the stage control is a real, semantic form (a `<select>` of the
  LATERAL targets and a submit button), never a drag-and-drop board —
  this test proves it is operable that way, not merely that a mouse click
  on it happens to work.
  """
  email, first_password = ready_agent
  password = _sign_in_and_complete_forced_reset(page, live_server.base_url, email, first_password)
  del password

  contact_url = _create_contact(page, live_server.base_url, name="Keyboard Stage Contact")
  page.goto(contact_url)
  page.get_by_role("link", name="Add deal").click()
  page.get_by_label("Title").fill("Keyboard-only move deal")
  page.get_by_label("Amount").fill("500.00")
  page.get_by_role("button", name="Save deal").click()
  expect(page).to_have_url(re.compile(r"notice=deal_created"))

  # A freshly created deal is at "New"; LATERAL targets (STAGE_ORDER minus
  # the current stage) are Qualified and Proposal — "Proposal" is the only
  # one starting with "P", so a single keystroke's native <select>
  # type-ahead lands on it unambiguously, without needing the dropdown
  # open (real, standard keyboard-only <select> operation).
  select = page.get_by_label('Move "Keyboard-only move deal" to')
  select.focus()
  expect(select).to_be_focused()
  page.keyboard.press("P")
  expect(select).to_have_value("proposal")
  page.keyboard.press("Tab")
  move_button = page.get_by_role("button", name="Move")
  expect(move_button).to_be_focused()
  page.keyboard.press("Enter")

  expect(page).to_have_url(re.compile(r"notice=deal_moved"))
  page.goto(contact_url)
  expect(page.get_by_text("Proposal", exact=True)).to_be_visible()


def test_contact_detail_deals_region_lists_the_contacts_own_deals(
  page: Page, live_server: LiveServer, ready_agent: tuple[str, str]
) -> None:
  """The contact detail `#deals` region (PIN C7) lists its deals, plus an "Add deal" action."""
  email, first_password = ready_agent
  password = _sign_in_and_complete_forced_reset(page, live_server.base_url, email, first_password)
  del password

  contact_url = _create_contact(page, live_server.base_url, name="Deals Region Contact")
  page.goto(contact_url)
  expect(page.get_by_text("No deals yet for this contact.")).to_be_visible()

  page.get_by_role("link", name="Add deal").click()
  page.get_by_label("Title").fill("Region-visible deal")
  page.get_by_label("Amount").fill("42.00")
  page.get_by_role("button", name="Save deal").click()
  expect(page).to_have_url(re.compile(r"notice=deal_created"))

  deals_region = page.locator("section.workspace-deals")
  expect(deals_region.get_by_role("link", name="Region-visible deal", exact=True)).to_be_visible()
  expect(deals_region.get_by_role("link", name="Add deal")).to_be_visible()
  # PIN C7 / slice-c.md §2(e): the region is a FULL PAGE RENDER ONLY —
  # never an htmx-enhanced fragment.
  assert deals_region.get_attribute("hx-get") is None
  assert deals_region.get_attribute("hx-target") is None


@pytest.mark.parametrize(
  ("page_name", "goto_path"),
  [
    ("deal list", "/deals"),
    ("pipeline", "/deals/pipeline"),
  ],
)
def test_axe_pass_on_deal_list_and_pipeline_pages(
  page: Page, live_server: LiveServer, ready_agent: tuple[str, str], page_name: str, goto_path: str
) -> None:
  """An automated axe-core scan of the deal list / pipeline page reports zero violations."""
  from axe_playwright_python.sync_playwright import Axe

  email, first_password = ready_agent
  password = _sign_in_and_complete_forced_reset(page, live_server.base_url, email, first_password)
  del password
  page.goto(f"{live_server.base_url}{goto_path}")
  results = Axe().run(page)
  assert results.violations_count == 0, f"{page_name}: {results.generate_snapshot()}"


def test_axe_pass_on_new_deal_form(
  page: Page, live_server: LiveServer, ready_agent: tuple[str, str]
) -> None:
  """An automated axe-core scan of the "new deal" form reports zero violations."""
  from axe_playwright_python.sync_playwright import Axe

  email, first_password = ready_agent
  password = _sign_in_and_complete_forced_reset(page, live_server.base_url, email, first_password)
  del password
  contact_url = _create_contact(page, live_server.base_url, name="Axe New Deal Contact")
  page.goto(contact_url)
  page.get_by_role("link", name="Add deal").click()
  results = Axe().run(page)
  assert results.violations_count == 0, results.generate_snapshot()


def test_axe_pass_on_deal_detail_page_with_stage_control(
  page: Page, live_server: LiveServer, ready_agent: tuple[str, str]
) -> None:
  """An automated axe-core scan of a deal's detail page, WITH its stage control, reports zero."""
  from axe_playwright_python.sync_playwright import Axe

  email, first_password = ready_agent
  password = _sign_in_and_complete_forced_reset(page, live_server.base_url, email, first_password)
  del password
  contact_url = _create_contact(page, live_server.base_url, name="Axe Deal Detail Contact")
  page.goto(contact_url)
  page.get_by_role("link", name="Add deal").click()
  page.get_by_label("Title").fill("Axe Scan Deal")
  page.get_by_label("Amount").fill("10.00")
  page.get_by_role("button", name="Save deal").click()
  page.get_by_role("link", name="Axe Scan Deal").click()
  expect(page.get_by_role("heading", name="Axe Scan Deal")).to_be_visible()
  results = Axe().run(page)
  assert results.violations_count == 0, results.generate_snapshot()


def test_axe_pass_on_contact_detail_page_with_deals_region(
  page: Page, live_server: LiveServer, ready_agent: tuple[str, str]
) -> None:
  """An automated axe-core scan of the contact detail page WITH a populated `#deals` region."""
  from axe_playwright_python.sync_playwright import Axe

  email, first_password = ready_agent
  password = _sign_in_and_complete_forced_reset(page, live_server.base_url, email, first_password)
  del password
  contact_url = _create_contact(page, live_server.base_url, name="Axe Contact Deals Region")
  page.goto(contact_url)
  page.get_by_role("link", name="Add deal").click()
  page.get_by_label("Title").fill("Axe Region Deal")
  page.get_by_label("Amount").fill("10.00")
  page.get_by_role("button", name="Save deal").click()
  results = Axe().run(page)
  assert results.violations_count == 0, results.generate_snapshot()
