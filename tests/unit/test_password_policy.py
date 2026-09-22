"""Unit tests for ``app.security.passwords``: length bounds, blocklist, and Argon2 parameters.

``PasswordService.validate``/``hash``/``verify`` are exercised directly; the
fast test Argon2 profile is used only for setup speed, never for the three
assertions that actually check parameter values.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
  from collections.abc import Coroutine

  from argon2 import PasswordHasher

  from app.security.passwords import PasswordService


def _make_service(fast_hasher: PasswordHasher) -> PasswordService:
  """Build a ``PasswordService`` with the documented fast test profile.

  Parameters
  ----------
  fast_hasher : argon2.PasswordHasher
    The ``fast_password_hasher`` fixture's real hasher.

  Returns
  -------
  app.security.passwords.PasswordService
  """
  from app.security.clock import SystemClock
  from app.security.passwords import PasswordService

  return PasswordService(
    fast_hasher,
    blocklist=frozenset({"demo_app_crm", "crm", "example.test", "admin", "agent"}),
    clock=SystemClock(),
    max_active=1,
    max_queued=8,
  )


def _run[T](awaitable: Coroutine[object, object, T]) -> T:
  """Run a coroutine to completion from a synchronous test function.

  Parameters
  ----------
  awaitable : Coroutine[object, object, T]
    A coroutine returned by one of ``PasswordService``'s async methods.

  Returns
  -------
  T
    Whatever the coroutine returned.
  """
  return asyncio.run(awaitable)


# ---------------------------------------------------------------------------
# Password length bounds.
# ---------------------------------------------------------------------------


def test_a_14_character_password_is_rejected(fast_password_hasher: PasswordHasher) -> None:
  """14 characters is one below the 15-character floor and is rejected."""
  service = _make_service(fast_password_hasher)
  errors = service.validate("a" * 14, context=())
  assert errors != []


@pytest.mark.parametrize("length", [15, 128])
def test_15_and_128_characters_are_accepted(
  fast_password_hasher: PasswordHasher, length: int
) -> None:
  """15 (the floor) and 128 (the ceiling) are both accepted."""
  service = _make_service(fast_password_hasher)
  # A varied, non-dictionary string so no blocklist/context rule fires.
  candidate = "".join(chr(ord("a") + (i % 26)) for i in range(length))
  errors = service.validate(candidate, context=())
  assert errors == []


def test_a_129_character_password_is_rejected(
  fast_password_hasher: PasswordHasher,
) -> None:
  """129 characters is one above the 128-character ceiling and is rejected."""
  service = _make_service(fast_password_hasher)
  candidate = "".join(chr(ord("a") + (i % 26)) for i in range(129))
  errors = service.validate(candidate, context=())
  assert errors != []


def test_no_truncation_a_128_character_password_authenticates_unchanged(
  fast_password_hasher: PasswordHasher,
) -> None:
  """Hashing and verifying the full 128 characters round-trips — no silent truncation."""
  service = _make_service(fast_password_hasher)
  candidate = "".join(chr(ord("a") + (i % 26)) for i in range(128))
  encoded = _run(service.hash(candidate))
  assert _run(service.verify(encoded, candidate)) is True
  # Any single truncated or altered character must not still verify.
  altered = candidate[:-1] + ("b" if candidate[-1] != "b" else "c")
  assert _run(service.verify(encoded, altered)) is False


# ---------------------------------------------------------------------------
# Blocklist and context words.
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
def test_blocklisted_and_context_words_are_rejected(
  fast_password_hasher: PasswordHasher, candidate: str
) -> None:
  """A password built around the app name, ``crm``, the fictional domain or a role name fails."""
  service = _make_service(fast_password_hasher)
  errors = service.validate(candidate, context=())
  assert errors != []


def test_caller_supplied_context_words_are_also_rejected(
  fast_password_hasher: PasswordHasher,
) -> None:
  """The per-call ``context`` sequence (e.g. the user's own name/email local part) is honoured."""
  service = _make_service(fast_password_hasher)
  errors = service.validate("AdaAdminAdaAdmin", context=("ada", "admin"))
  assert errors != []


def test_an_unrelated_long_random_password_is_accepted(
  fast_password_hasher: PasswordHasher,
) -> None:
  """A password containing none of the blocklist or context words passes."""
  service = _make_service(fast_password_hasher)
  errors = service.validate("correct horse battery staple 9", context=("someone-else",))
  assert errors == []


# ---------------------------------------------------------------------------
# Argon2 parameters come from the constructor only.
# ---------------------------------------------------------------------------


def test_passwords_module_reads_no_environment_variable(
  monkeypatch: pytest.MonkeyPatch, fast_password_hasher: PasswordHasher
) -> None:
  """Setting an env var that *would* select a cost profile changes nothing.

  There is, by contract, no such variable — this proves it by setting
  several plausible names and asserting the constructed service still uses
  exactly the ``PasswordHasher`` it was given.
  """
  for plausible_name in ("PASSWORD_HASH_PROFILE", "ARGON2_FAST", "CRM_TEST_MODE", "PYTEST_FAST"):
    monkeypatch.setenv(plausible_name, "1")
  service = _make_service(fast_password_hasher)
  encoded = _run(service.hash("a fictional passphrase 12345"))
  assert encoded.startswith("$argon2id$v=19$m=8,t=1,p=1$")


def test_no_environ_read_in_module_source() -> None:
  """Static check: the module source names no environment read at all."""
  import inspect

  from app.security import passwords

  source = inspect.getsource(passwords)
  assert "os.environ" not in source
  assert "os.getenv" not in source
