"""Unit tests for ``app.security.passwords`` — SEC-008, SEC-009, ARC-020.

Authority: ``ACCESS_MATRIX.md`` §7 (SEC-008, SEC-009, ARC-020);
``slice-a.md`` §1.1 (``PasswordService.validate``/``hash``/``verify``), §7.4
(the fast test profile, never used for these three assertions themselves).

``app/security/passwords.py`` does not exist in this tree yet (Backend
lane), so every test below imports it inside the test body and is expected
to fail with ``ModuleNotFoundError`` until then — reported, not hidden.
"""

from __future__ import annotations

import pytest


def _make_service(fast_hasher: object) -> object:
  """Build a ``PasswordService`` with the documented fast test profile.

  Parameters
  ----------
  fast_hasher : object
    The ``fast_password_hasher`` fixture's real ``argon2.PasswordHasher``.

  Returns
  -------
  app.security.passwords.PasswordService
  """
  # Deferred import: app/security/passwords.py is contracted (slice-a.md
  # §1.1) but not yet shipped.
  from app.security.passwords import PasswordService  # type: ignore[import-not-found]

  return PasswordService(
    fast_hasher,
    blocklist=frozenset({"demo_app_crm", "crm", "example.test", "admin", "agent"}),
    clock=_system_clock(),
    max_active=1,
    max_queued=8,
  )


def _system_clock() -> object:
  """Return a real ``SystemClock`` — ``PasswordService`` needs a ``Clock``, not a timer."""
  from app.security.clock import SystemClock  # type: ignore[import-not-found]

  return SystemClock()


# ---------------------------------------------------------------------------
# SEC-008 — password length bounds.
# ---------------------------------------------------------------------------


def test_sec008_a_14_character_password_is_rejected(fast_password_hasher: object) -> None:
  """14 characters is one below the 15-character floor and is rejected."""
  service = _make_service(fast_password_hasher)
  errors = service.validate("a" * 14, context=())  # type: ignore[attr-defined]
  assert errors != []


@pytest.mark.parametrize("length", [15, 128])
def test_sec008_15_and_128_characters_are_accepted(
  fast_password_hasher: object, length: int
) -> None:
  """15 (the floor) and 128 (the ceiling) are both accepted."""
  service = _make_service(fast_password_hasher)
  # A varied, non-dictionary string so no blocklist/context rule fires.
  candidate = "".join(chr(ord("a") + (i % 26)) for i in range(length))
  errors = service.validate(candidate, context=())  # type: ignore[attr-defined]
  assert errors == []


def test_sec008_a_129_character_password_is_rejected(fast_password_hasher: object) -> None:
  """129 characters is one above the 128-character ceiling and is rejected."""
  service = _make_service(fast_password_hasher)
  candidate = "".join(chr(ord("a") + (i % 26)) for i in range(129))
  errors = service.validate(candidate, context=())  # type: ignore[attr-defined]
  assert errors != []


def test_sec008_no_truncation_a_128_character_password_authenticates_unchanged(
  fast_password_hasher: object,
) -> None:
  """Hashing and verifying the full 128 characters round-trips — no silent truncation."""
  service = _make_service(fast_password_hasher)
  candidate = "".join(chr(ord("a") + (i % 26)) for i in range(128))
  encoded = _run(service.hash(candidate))  # type: ignore[attr-defined]
  assert _run(service.verify(encoded, candidate)) is True  # type: ignore[attr-defined]
  # Any single truncated or altered character must not still verify.
  altered = candidate[:-1] + ("b" if candidate[-1] != "b" else "c")
  assert _run(service.verify(encoded, altered)) is False  # type: ignore[attr-defined]


def _run(awaitable: object) -> object:
  """Run a coroutine to completion from a synchronous test function.

  Parameters
  ----------
  awaitable : object
    Actually a ``Coroutine[Any, Any, Any]``; typed loosely because the
    return type of the not-yet-existing ``PasswordService`` methods is not
    something this module can import a stub for.

  Returns
  -------
  object
    Whatever the coroutine returned.
  """
  import asyncio

  return asyncio.run(awaitable)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# SEC-009 — blocklist and context words.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
  "candidate",
  [
    "Demo_App_CRM12345",
    "crm crm crm crm!",
    "example.test12345",
    "administrator12345",  # contains the role word "admin"
  ],
)
def test_sec009_blocklisted_and_context_words_are_rejected(
  fast_password_hasher: object, candidate: str
) -> None:
  """A password built around the app name, ``crm``, the fictional domain or a role name fails."""
  service = _make_service(fast_password_hasher)
  errors = service.validate(candidate, context=())  # type: ignore[attr-defined]
  assert errors != []


def test_sec009_caller_supplied_context_words_are_also_rejected(
  fast_password_hasher: object,
) -> None:
  """The per-call ``context`` sequence (e.g. the user's own name/email local part) is honoured."""
  service = _make_service(fast_password_hasher)
  errors = service.validate(  # type: ignore[attr-defined]
    "AdaAdminAdaAdmin", context=("ada", "admin")
  )
  assert errors != []


def test_sec009_an_unrelated_long_random_password_is_accepted(
  fast_password_hasher: object,
) -> None:
  """A password containing none of the blocklist or context words passes."""
  service = _make_service(fast_password_hasher)
  errors = service.validate(  # type: ignore[attr-defined]
    "correct horse battery staple 9", context=("someone-else",)
  )
  assert errors == []


# ---------------------------------------------------------------------------
# ARC-020 — Argon2 parameters come from the constructor only.
# ---------------------------------------------------------------------------


def test_arc020_passwords_module_reads_no_environment_variable(
  monkeypatch: pytest.MonkeyPatch, fast_password_hasher: object
) -> None:
  """Setting an env var that *would* select a cost profile changes nothing.

  There is, by contract, no such variable — this proves it by setting
  several plausible names and asserting the constructed service still uses
  exactly the ``PasswordHasher`` it was given.
  """
  for plausible_name in ("PASSWORD_HASH_PROFILE", "ARGON2_FAST", "CRM_TEST_MODE", "PYTEST_FAST"):
    monkeypatch.setenv(plausible_name, "1")
  service = _make_service(fast_password_hasher)
  encoded = _run(service.hash("a fictional passphrase 12345"))  # type: ignore[attr-defined]
  assert str(encoded).startswith("$argon2id$v=19$m=8,t=1,p=1$")


def test_arc020_no_environ_read_in_module_source() -> None:
  """Static half of ARC-020: the module source names no environment read at all."""
  import inspect

  # Deferred import: see module docstring.
  from app.security import passwords  # type: ignore[import-not-found]

  source = inspect.getsource(passwords)
  assert "os.environ" not in source
  assert "os.getenv" not in source
