"""Session lifecycle — SEC-011 through SEC-015, SEC-024, SEC-025, SEC-029, SEC-037.

Authority: ``ACCESS_MATRIX.md`` §7; ``slice-a.md`` §1.1 (``app/security/sessions.py``,
``PREAUTH_TTL``/``IDLE_TTL``/``ABSOLUTE_TTL``), §2.2 (cookie), §10(b)
(``sessions.py`` repository — ``read_live_session``, expiry filtered in SQL).

Split by how the assertion is observable (module docstring of
``conftest.py`` explains why): expiry and revocation (SEC-013, SEC-014,
SEC-015) are **in-process**, driving the repository's own ``now`` parameter
against ``crm_test`` directly — the only way to test them without sleeping,
since the live server's clock cannot be swapped. Everything else here is
wire-observable and uses ``live_server``.

Typing note: ``db_connection`` and ``clock`` are typed ``Any`` in this file,
not ``object``. Both come from fixtures whose real implementation
(``psycopg.AsyncConnection``, ``app.security.clock.ManualClock``) does not
exist in this tree yet; ``object`` would need a ``# type: ignore`` on every
attribute access, and — confirmed empirically — mypy's handling of those
per-line ignores is inconsistent once several other files in the same run
also import from modules that do not exist yet (some are flagged "unused"
depending on unrelated files elsewhere in the same invocation). ``Any``
sidesteps that instability entirely and is the honest type regardless: this
module genuinely does not know the real type until the Backend/Data lanes
ship it.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import LiveServer, ProvisionedUser, insert_test_user_row, login_via_http

pytestmark = pytest.mark.asyncio


def _token_and_digest() -> tuple[str, str]:
  """A CSPRNG token and its SHA-256 hex digest, for direct repository seeding."""
  token = secrets.token_urlsafe(32)
  return token, hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# SEC-013 — pre-auth 10 min, idle 30 min, absolute 8 h, in-process.
# ---------------------------------------------------------------------------


async def test_sec013_preauth_session_is_live_at_9m59s_and_dead_at_10m01s(
  db_connection: Any, clock: Any
) -> None:
  """A pre-auth row is readable one second before its 10-minute expiry, dead one second after."""
  from app.db.repositories.sessions import (  # type: ignore[import-not-found]
    create_preauth_session,
    read_live_session,
  )
  from app.security.sessions import PREAUTH_TTL  # type: ignore[import-not-found]

  _token, token_sha256 = _token_and_digest()
  _, csrf_sha256 = _token_and_digest()
  session_id = uuid.uuid4()
  now = clock.now()
  expires_at = now + PREAUTH_TTL
  await create_preauth_session(
    db_connection,
    session_id=session_id,
    token_sha256=token_sha256,
    csrf_sha256=csrf_sha256,
    now=now,
    expires_at=expires_at,
  )
  await db_connection.commit()

  just_before = await read_live_session(
    db_connection, token_sha256=token_sha256, now=expires_at - timedelta(seconds=1)
  )
  assert just_before is not None

  just_after = await read_live_session(
    db_connection, token_sha256=token_sha256, now=expires_at + timedelta(seconds=1)
  )
  assert just_after is None


async def test_sec013_idle_30min_and_absolute_8h_both_independently_expire_a_full_session(
  db_connection: Any, clock: Any, tmp_path: Path
) -> None:
  """A full session dies at idle timeout even while inside its absolute window, and vice versa."""
  from app.db.repositories.sessions import (
    promote_session,
    read_live_session,
  )
  from app.security.sessions import ABSOLUTE_TTL, IDLE_TTL

  now = clock.now()
  user_id = str(uuid.uuid4())
  insert_test_user_row(
    user_id=user_id,
    email=f"session-expiry+{uuid.uuid4().hex[:8]}@example.test",
    display_name="Session Expiry Test",
    role="agent",
    password_hash="$argon2id$v=19$m=19456,t=2,p=1$" + "a" * 32,
    must_change_password=False,
    now=now.isoformat(),
    log_path=tmp_path / "seed_user.log",
  )

  _, token_sha256 = _token_and_digest()
  _, csrf_sha256 = _token_and_digest()
  session_id = uuid.uuid4()
  idle_expires_at = now + IDLE_TTL
  absolute_expires_at = now + ABSOLUTE_TTL
  await promote_session(
    db_connection,
    preauth_id=None,
    session_id=session_id,
    user_id=uuid.UUID(user_id),
    token_sha256=token_sha256,
    csrf_sha256=csrf_sha256,
    now=now,
    idle_expires_at=idle_expires_at,
    absolute_expires_at=absolute_expires_at,
  )
  await db_connection.commit()

  # Idle expiry fires first, well inside the 8-hour absolute window.
  after_idle = await read_live_session(
    db_connection, token_sha256=token_sha256, now=idle_expires_at + timedelta(seconds=1)
  )
  assert after_idle is None, "idle expiry (30 min) did not end the session"

  # A second session, touched right up to the absolute boundary, still dies there.
  _, token_sha256_2 = _token_and_digest()
  _, csrf_sha256_2 = _token_and_digest()
  session_id_2 = uuid.uuid4()
  await promote_session(
    db_connection,
    preauth_id=None,
    session_id=session_id_2,
    user_id=uuid.UUID(user_id),
    token_sha256=token_sha256_2,
    csrf_sha256=csrf_sha256_2,
    now=now,
    idle_expires_at=now + ABSOLUTE_TTL,  # idle pushed out past the absolute bound
    absolute_expires_at=absolute_expires_at,
  )
  await db_connection.commit()
  after_absolute = await read_live_session(
    db_connection, token_sha256=token_sha256_2, now=absolute_expires_at + timedelta(seconds=1)
  )
  assert after_absolute is None, "absolute expiry (8 h) did not end the session"


# ---------------------------------------------------------------------------
# SEC-014 / SEC-015 — revocation, in-process.
# ---------------------------------------------------------------------------


async def test_sec014_logout_deletes_the_session_row_and_it_is_no_longer_live(
  db_connection: Any, clock: Any, tmp_path: Path
) -> None:
  """``delete_session`` (logout) makes an immediately prior read return ``None``."""
  from app.db.repositories.sessions import (
    delete_session,
    promote_session,
    read_live_session,
  )
  from app.security.sessions import ABSOLUTE_TTL, IDLE_TTL

  now = clock.now()
  user_id = str(uuid.uuid4())
  insert_test_user_row(
    user_id=user_id,
    email=f"logout+{uuid.uuid4().hex[:8]}@example.test",
    display_name="Logout Test",
    role="agent",
    password_hash="$argon2id$v=19$m=19456,t=2,p=1$" + "a" * 32,
    must_change_password=False,
    now=now.isoformat(),
    log_path=tmp_path / "seed_user.log",
  )
  _, token_sha256 = _token_and_digest()
  _, csrf_sha256 = _token_and_digest()
  session_id = uuid.uuid4()
  await promote_session(
    db_connection,
    preauth_id=None,
    session_id=session_id,
    user_id=uuid.UUID(user_id),
    token_sha256=token_sha256,
    csrf_sha256=csrf_sha256,
    now=now,
    idle_expires_at=now + IDLE_TTL,
    absolute_expires_at=now + ABSOLUTE_TTL,
  )
  await db_connection.commit()

  live = await read_live_session(db_connection, token_sha256=token_sha256, now=now)
  assert live is not None

  await delete_session(db_connection, session_id=session_id)
  await db_connection.commit()
  after = await read_live_session(db_connection, token_sha256=token_sha256, now=now)
  assert after is None


async def test_sec015_revoke_sessions_keeps_only_the_named_session(
  db_connection: Any, clock: Any, tmp_path: Path
) -> None:
  """``revoke_sessions(keep_session_id=...)`` (password change) kills every sibling session."""
  from app.db.repositories.sessions import (
    promote_session,
    read_live_session,
    revoke_sessions,
  )
  from app.security.sessions import ABSOLUTE_TTL, IDLE_TTL

  now = clock.now()
  user_id = str(uuid.uuid4())
  insert_test_user_row(
    user_id=user_id,
    email=f"revoke+{uuid.uuid4().hex[:8]}@example.test",
    display_name="Revoke Test",
    role="agent",
    password_hash="$argon2id$v=19$m=19456,t=2,p=1$" + "a" * 32,
    must_change_password=False,
    now=now.isoformat(),
    log_path=tmp_path / "seed_user.log",
  )

  sessions: list[tuple[uuid.UUID, str]] = []
  for _ in range(3):
    _, token_sha256 = _token_and_digest()
    _, csrf_sha256 = _token_and_digest()
    session_id = uuid.uuid4()
    await promote_session(
      db_connection,
      preauth_id=None,
      session_id=session_id,
      user_id=uuid.UUID(user_id),
      token_sha256=token_sha256,
      csrf_sha256=csrf_sha256,
      now=now,
      idle_expires_at=now + IDLE_TTL,
      absolute_expires_at=now + ABSOLUTE_TTL,
    )
    sessions.append((session_id, token_sha256))
  await db_connection.commit()

  kept_id, kept_token_sha256 = sessions[0]
  await revoke_sessions(db_connection, user_id=uuid.UUID(user_id), keep_session_id=kept_id)
  await db_connection.commit()

  kept_row = await read_live_session(db_connection, token_sha256=kept_token_sha256, now=now)
  assert kept_row is not None, "the current session must survive its own revocation call"
  for _session_id, token_sha256 in sessions[1:]:
    row = await read_live_session(db_connection, token_sha256=token_sha256, now=now)
    assert row is None, "a sibling session survived revoke_sessions"


# ---------------------------------------------------------------------------
# SEC-011, SEC-012, SEC-024, SEC-025, SEC-029, SEC-037 — over HTTP.
# ---------------------------------------------------------------------------


async def test_sec011_the_session_cookie_is_named_exactly_dunder_host_crm_session(
  admin_session: httpx.AsyncClient,
) -> None:
  """The literal cookie name is ``__Host-crm_session`` (R10) — not merely the prefix."""
  assert "__Host-crm_session" in admin_session.cookies


async def test_sec012_login_rotates_the_cookie_value_the_preauth_token_no_longer_works(
  http_client_factory: Any, bootstrap_admin: ProvisionedUser
) -> None:
  """The pre-auth cookie value dies on login; only the new, post-login value authenticates."""
  client: httpx.AsyncClient = http_client_factory()
  await client.get("/login")
  preauth_value = client.cookies.get("__Host-crm_session")
  assert preauth_value is not None

  await login_via_http(client, email=bootstrap_admin.email, password=bootstrap_admin.password)
  full_value = client.cookies.get("__Host-crm_session")
  assert full_value is not None
  assert full_value != preauth_value

  replay_client: httpx.AsyncClient = http_client_factory()
  replay_client.cookies.set("__Host-crm_session", preauth_value, domain="127.0.0.1")
  response = await replay_client.get("/account/password")
  assert response.status_code in (303, 403), "the dead pre-auth token must not authenticate"


async def test_sec024_private_page_carries_hx_history_false() -> None:
  """A private page's ``<body>`` carries ``hx-history="false"`` so it is never HTMX-cached.

  Static, template-level (see ``base.html``'s ``{% if private %}`` guard);
  this is the executable-today half. The full behavioural half (a browser
  never restoring the fragment from history) needs Playwright and belongs
  in ``tests/e2e``, not here.
  """
  base_html = (
    Path(__file__).resolve().parent.parent.parent / "app" / "templates" / "base.html"
  ).read_text(encoding="utf-8")
  assert 'hx-history="false"' in base_html


async def test_sec025_a_private_page_response_carries_cache_control_no_store(
  admin_session: httpx.AsyncClient,
) -> None:
  """Every private page response carries ``Cache-Control: no-store``."""
  response = await admin_session.get("/account/password")
  assert response.headers.get("cache-control") == "no-store"


async def test_sec029_logout_carries_clear_site_data_and_expires_the_cookie(
  admin_session: httpx.AsyncClient,
) -> None:
  """``POST /logout`` carries ``Clear-Site-Data: "cache", "storage"`` and an expired cookie."""
  from conftest import extract_csrf_token

  get_response = await admin_session.get("/account/password")
  csrf_token = extract_csrf_token(get_response.text)
  response = await admin_session.post("/logout", data={"csrf_token": csrf_token})
  assert response.status_code == 303
  assert response.headers.get("clear-site-data") == '"cache", "storage"'
  set_cookie = response.headers.get("set-cookie", "")
  assert "__Host-crm_session=" in set_cookie
  assert "Max-Age=0" in set_cookie


def _run_manage_with_stdin(*args: str, password: str, tmp_path: Path, name: str) -> None:
  """Run ``scripts/manage <args> --password-stdin`` under the owner env file."""
  import subprocess

  from conftest import MANAGE, OWNER_ENV_FILE, SUBMODULE_ROOT, VENV_PYTHON, WITH_ENV
  from conftest import write_password_fixture as _write_password_fixture

  password_file = _write_password_fixture(tmp_path, password, name=name)
  try:
    with password_file.open("rb") as stdin_file:
      subprocess.run(  # noqa: S603
        [str(WITH_ENV), OWNER_ENV_FILE, "--", str(VENV_PYTHON), "-B", str(MANAGE), *args],
        cwd=SUBMODULE_ROOT,
        stdin=stdin_file,
        check=True,
        timeout=30.0,
      )
  finally:
    password_file.unlink(missing_ok=True)


async def test_sec037_a_forced_reset_session_reaches_only_password_and_logout(
  live_server: LiveServer,
  http_client_factory: Any,
  tmp_path: Path,
) -> None:
  """A ``must_change_password`` session gets 403 on every route but the two forced-path exceptions.

  Provisions its own agent through ``manage reset-password`` (which sets
  ``must_change_password``) rather than reusing ``admin_session``, so this
  never touches the shared admin.
  """
  from conftest import unique_email

  email = unique_email("forced-reset")
  password = "a fictional forced reset passphrase"
  _run_manage_with_stdin(
    "create-user",
    "--email",
    email,
    "--name",
    "Forced Reset",
    "--role",
    "agent",
    "--password-stdin",
    password=password,
    tmp_path=tmp_path,
    name="pw-create",
  )
  _run_manage_with_stdin(
    "reset-password",
    "--email",
    email,
    "--password-stdin",
    password=password,
    tmp_path=tmp_path,
    name="pw-reset",
  )

  client: httpx.AsyncClient = http_client_factory()
  await login_via_http(client, email=email, password=password)
  response = await client.get("/account/password")
  assert response.status_code == 200
  denied = await client.get("/")
  assert denied.status_code == 403
  del live_server
