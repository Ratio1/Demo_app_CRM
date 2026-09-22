"""Password hashing, verification, policy and the bounded hash queue (``S1``).

Authority: ``slice-a.md`` §1.1 (the :class:`PasswordService` surface), §7.4
(parameters come from the constructor and nowhere else — ``ARC-020``),
``THREAT_MODEL.md`` §10 item 10 (the blocklist's context words),
``UX_FLOWS.md`` §6.1 (``CP-71``-``CP-73``, the copy a rejected password
shows).

Three properties this module exists to hold:

*Parameters are injected, never selected.* The :class:`argon2.PasswordHasher`
is a constructor argument. There is no environment variable, no
configuration key and no branch here that could pick a cheaper profile, so
a production process cannot be talked into test-grade hashing
(``ARC-020``); the module source names no environment read at all.

*Hashing is bounded.* Argon2id at the pinned parameters allocates 19 MiB and
runs ~20 ms. Unbounded concurrency would turn the login form into a memory
amplifier, so every hash and every verify passes through a gate admitting
``max_active`` at a time with at most ``max_queued`` waiting; the request
that would exceed that raises :class:`HashQueueFull`, which the route
answers with a sanitized ``429`` (``SEC-034``).

*A missing account costs the same as a wrong password.* ``verify(None, …)``
runs a real Argon2 verification against a dummy hash in the same gate slot,
so the response time of "no such user" and "wrong password" are the same
measurement (``SEC-032``, ``SEC-033``).
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Iterable, Sequence
from typing import TYPE_CHECKING, Final

from argon2.exceptions import HashingError, InvalidHashError, VerificationError

if TYPE_CHECKING:
  from argon2 import PasswordHasher

  from app.security.clock import Clock

__all__ = [
  "CP_71_TOO_SHORT",
  "CP_72_TOO_LONG",
  "CP_73_BLOCKLISTED",
  "DEFAULT_BLOCKLIST",
  "MAX_PASSWORD_LENGTH",
  "MIN_CONTEXT_TOKEN_LENGTH",
  "MIN_PASSWORD_LENGTH",
  "HashQueueFull",
  "PasswordService",
]

MIN_PASSWORD_LENGTH: Final = 15
MAX_PASSWORD_LENGTH: Final = 128

#: A context word shorter than this is ignored. Two- and three-letter
#: fragments of a display name ("Jo", "Ana", "e2e") match far too much
#: ordinary text to be evidence that a password was built from the name,
#: and rejecting on them would refuse good passwords for no security gain.
MIN_CONTEXT_TOKEN_LENGTH: Final = 4

CP_71_TOO_SHORT: Final = "Use at least 15 characters."
CP_72_TOO_LONG: Final = "Use 128 characters or fewer."
CP_73_BLOCKLISTED: Final = "Choose a password that is harder to guess."

#: ``THREAT_MODEL.md`` §10 item 10: the application's own context words and
#: "simple permutations" of them. Everything is matched case-insensitively
#: as a substring, so a permutation such as ``Demo_App_CRM2026`` is caught
#: by the base word.
DEFAULT_BLOCKLIST: Final[frozenset[str]] = frozenset(
  {
    "demo_app_crm",
    "demo-app-crm",
    "demo app crm",
    "demoappcrm",
    "demo",
    "crm",
    "example.test",
    "admin",
    "agent",
    "ratio1",
  }
)

#: The password the dummy hash is built from. It is never accepted as a
#: credential: the dummy hash is only ever compared against a *submitted*
#: password, and a submission equal to this string still fails, because the
#: account it would be verified for does not exist.
_DUMMY_PASSWORD: Final = "a fictional password that authenticates nobody"  # noqa: S105

_TOKEN_SPLIT: Final = re.compile(r"[^0-9a-z]+")


class HashQueueFull(RuntimeError):
  """Raised when the bounded hash gate has no free active or queued slot.

  Carries no detail beyond the configured depths: the caller turns it into
  a sanitized ``429`` with a ``Retry-After`` and never echoes it.
  """


class PasswordService:
  """Hash, verify and validate passwords under injected parameters."""

  def __init__(
    self,
    hasher: PasswordHasher,
    *,
    blocklist: frozenset[str],
    clock: Clock,
    max_active: int = 1,
    max_queued: int = 8,
  ) -> None:
    """Build the service around one hasher and one gate.

    Parameters
    ----------
    hasher : argon2.PasswordHasher
      Already configured with its cost parameters. Production passes
      ``time_cost=2, memory_cost=19456, parallelism=1, hash_len=32,
      salt_len=16, type=Type.ID``; a test fixture may pass a documented
      fast profile. This class never inspects or overrides them.
    blocklist : frozenset[str]
      Lower-cased words a password may not contain.
      :data:`DEFAULT_BLOCKLIST` is what production passes.
    clock : Clock
      The injected time source. Held so that the service never reaches for
      a wall clock of its own (``ARC-019``).
    max_active : int, optional
      Hashes running at once. One, so a burst of logins cannot multiply the
      19 MiB arena.
    max_queued : int, optional
      Callers allowed to wait for a slot. Beyond this the request is
      refused immediately rather than queued without bound.

    Raises
    ------
    ValueError
      If ``max_active`` is below one or ``max_queued`` is negative.

    Notes
    -----
    The dummy hash is computed here, once, with the same hasher, so that
    ``verify(None, …)`` costs exactly one verification and never a hash
    plus a verification.
    """
    if max_active < 1:
      raise ValueError("max_active must be at least 1")
    if max_queued < 0:
      raise ValueError("max_queued must not be negative")
    self._hasher = hasher
    self._blocklist = frozenset(word.casefold() for word in blocklist if word)
    self._clock = clock
    self._max_active = max_active
    self._max_queued = max_queued
    self._inflight = 0
    self._gate: asyncio.Semaphore | None = None
    self._gate_loop: asyncio.AbstractEventLoop | None = None
    self._dummy_encoded = hasher.hash(_DUMMY_PASSWORD)

  # -- the bounded gate ----------------------------------------------------

  def _semaphore(self) -> asyncio.Semaphore:
    """Return the gate for the running event loop, building it on first use.

    Returns
    -------
    asyncio.Semaphore
      A semaphore of depth ``max_active``.

    Notes
    -----
    The semaphore is created lazily and re-created if the service is ever
    used from a second event loop. The served application has exactly one
    loop, so in production this happens once; a test that calls
    :func:`asyncio.run` twice against the same service would otherwise hit
    asyncio's "bound to a different event loop" guard on the first
    contended acquisition.
    """
    loop = asyncio.get_running_loop()
    if self._gate is None or self._gate_loop is not loop:
      self._gate = asyncio.Semaphore(self._max_active)
      self._gate_loop = loop
      self._inflight = 0
    return self._gate

  async def _guarded[T](self, work: Callable[[], T]) -> T:
    """Run ``work`` in a worker thread, inside the bounded gate.

    Parameters
    ----------
    work : Callable[[], T]
      A synchronous Argon2 call.

    Returns
    -------
    T
      Whatever ``work`` returned.

    Raises
    ------
    HashQueueFull
      If ``max_active + max_queued`` callers are already in the gate.

    Notes
    -----
    Argon2 is CPU- and memory-bound C code; running it with
    :func:`asyncio.to_thread` keeps the event loop answering health checks
    and cheap routes while a hash is in progress. The admission test and
    the counter increment are not separated by an ``await``, so on a single
    event loop they are atomic.
    """
    if self._inflight >= self._max_active + self._max_queued:
      raise HashQueueFull("the password hashing queue is full")
    gate = self._semaphore()
    self._inflight += 1
    try:
      async with gate:
        return await asyncio.to_thread(work)
    finally:
      self._inflight -= 1

  # -- hashing and verification -------------------------------------------

  async def hash(self, password: str) -> str:
    """Hash ``password`` with the injected parameters.

    Parameters
    ----------
    password : str
      The plaintext, never truncated and never logged.

    Returns
    -------
    str
      The PHC-encoded Argon2id string, which carries the parameters and the
      salt, so a later parameter change is detectable by
      :meth:`needs_rehash`.

    Raises
    ------
    HashQueueFull
      If the bounded gate is full.
    """
    return await self._guarded(lambda: self._hasher.hash(password))

  async def verify(self, encoded: str | None, password: str) -> bool:
    """Verify ``password`` against ``encoded``, or against the dummy hash.

    Parameters
    ----------
    encoded : str | None
      The stored hash, or ``None`` when no account matched the submitted
      identifier.
    password : str
      The submitted plaintext.

    Returns
    -------
    bool
      ``True`` only when ``encoded`` is a real hash and the password
      matches it. ``None`` always returns ``False`` — after paying the full
      cost of a verification.

    Raises
    ------
    HashQueueFull
      If the bounded gate is full. The caller answers ``429``; this is the
      one refusal that is *not* an authentication outcome, and it is
      deliberately raised for a missing account too, so the queue's
      behaviour is not itself an oracle.

    Notes
    -----
    ``T-03``/``SEC-033``: the dummy path runs in the same gate slot with
    the same parameters, so a missing account and a wrong password cost the
    same and contend for the same resource.
    """
    target = self._dummy_encoded if encoded is None else encoded

    def _work() -> bool:
      try:
        return bool(self._hasher.verify(target, password))
      except (VerificationError, InvalidHashError, HashingError):
        return False

    matched = await self._guarded(_work)
    return False if encoded is None else matched

  def needs_rehash(self, encoded: str) -> bool:
    """Return whether ``encoded`` was produced with other parameters.

    Parameters
    ----------
    encoded : str
      A stored PHC string.

    Returns
    -------
    bool
      ``True`` when the stored parameters differ from the injected ones, or
      when the string cannot be parsed at all — an unparsable hash can
      never verify, so replacing it on the next successful login is the
      only useful answer.
    """
    try:
      return bool(self._hasher.check_needs_rehash(encoded))
    except InvalidHashError:
      return True

  # -- policy --------------------------------------------------------------

  def validate(self, password: str, *, context: Sequence[str]) -> list[str]:
    """Check a **self-chosen** password against the policy.

    Parameters
    ----------
    password : str
      The candidate, exactly as submitted: never stripped, never truncated,
      so what is validated is what is hashed.
    context : Sequence[str]
      Values about this particular user — display name, the local part of
      the email address — whose words must not appear in the password.
      Words shorter than :data:`MIN_CONTEXT_TOKEN_LENGTH` are ignored.

    Returns
    -------
    list[str]
      Rendered copy strings, in a fixed order, empty when the password is
      acceptable: ``CP-71`` (too short), ``CP-72`` (too long), ``CP-73``
      (blocklisted or built from a context word). The strings are the
      user-facing text of ``UX_FLOWS.md`` §6.1 rather than bare ids,
      because the templates render a message verbatim in both the field
      error and the error summary.

    Notes
    -----
    Length is measured in characters, not bytes, and there is no upper
    truncation anywhere in this module: ``SEC-008`` asserts that a
    128-character password authenticates unchanged.
    """
    errors: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
      errors.append(CP_71_TOO_SHORT)
    elif len(password) > MAX_PASSWORD_LENGTH:
      errors.append(CP_72_TOO_LONG)

    folded = password.casefold()
    if any(word in folded for word in self._forbidden_words(context)):
      errors.append(CP_73_BLOCKLISTED)
    return errors

  def _forbidden_words(self, context: Sequence[str]) -> Iterable[str]:
    """Return the blocklist plus the usable words of ``context``.

    Parameters
    ----------
    context : Sequence[str]
      Raw context values, each of which may hold several words.

    Returns
    -------
    Iterable[str]
      Lower-cased words. Context values are split on anything that is not
      an ASCII letter or digit, so ``"Ada Admin"`` and
      ``"ada.admin+tag"`` both yield ``{"admin"}`` once the short ``ada``
      is dropped.
    """
    words = set(self._blocklist)
    for value in context:
      for token in _TOKEN_SPLIT.split(value.casefold()):
        if len(token) >= MIN_CONTEXT_TOKEN_LENGTH:
          words.add(token)
    return words
