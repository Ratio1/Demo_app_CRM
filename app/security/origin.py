"""The stored public origin, the ``Host``/``Origin`` check and ``next`` safety.

Spec §4 keeps the public HTTPS origin **in the database**, never in an
environment variable and never derived from a request header: a header is
attacker-controlled, and an application that believes ``Host`` will happily
mint a password-reset link pointing at the attacker's server.

Two consequences this module implements:

*The origin is read, cached briefly, and compared.* A five-second TTL keeps
``manage set-origin`` effective within a few seconds while costing one tiny
read per five seconds instead of one per request.

*A redirect target is validated, never trusted.* :func:`is_safe_relative`
is the whole of ``SEC-042``: the ``next`` parameter is a path on this
origin or it is dropped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from app.db.manifest import readiness
from app.db.repositories.settings import read_setting
from app.db.retry import run_read_committed

if TYPE_CHECKING:
  from app.db.manifest import ReadyReport
  from app.db.pool import Pool, PoolConnection
  from app.security.clock import Clock

__all__ = [
  "ORIGIN_SETTING_KEY",
  "ORIGIN_TTL_S",
  "OriginCache",
  "ReadinessCache",
  "authority_of",
  "is_safe_relative",
]

ORIGIN_SETTING_KEY: Final = "public_origin"
ORIGIN_TTL_S: Final = 5.0
READINESS_TTL_S: Final = 5.0

#: Characters a path may not contain at all. Everything below 0x20 plus
#: DEL: a bare CR or LF in a ``Location`` header is response splitting, and
#: the rest have no business in a URL path.
_CONTROL_CHARACTERS: Final = frozenset(chr(code) for code in [*range(0x20), 0x7F])


def authority_of(origin: str) -> str:
  """Return the ``host[:port]`` authority of an absolute origin.

  Parameters
  ----------
  origin : str
    An absolute origin such as ``https://127.0.0.1:3002``.

  Returns
  -------
  str
    The authority exactly as a browser sends it in ``Host`` — the host with
    its port when the origin names one, lower-cased. An origin that cannot
    be parsed yields the empty string, which matches no ``Host`` and so
    fails closed.
  """
  parts = urlsplit(origin.strip())
  if not parts.scheme or not parts.netloc:
    return ""
  return parts.netloc.casefold()


def is_safe_relative(path: str) -> bool:
  r"""Return whether ``path`` is a safe same-origin redirect target.

  Parameters
  ----------
  path : str
    A candidate ``next`` value, exactly as submitted.

  Returns
  -------
  bool
    ``True`` only for a single-slash-rooted path with no scheme, no
    authority and no control character.

  Notes
  -----
  ``SEC-042``'s four hostile shapes and why each is refused:

  * ``//evil.example.test`` — a protocol-relative URL: browsers read the
    part after ``//`` as an authority, so it leaves this origin.
  * ``https://evil.example.test`` — an absolute URL.
  * ``/\\evil.example.test`` — several browsers normalize ``\\`` to ``/``
    before parsing, which turns this into the first case.
  * anything holding ``\\r`` or ``\\n`` — header injection.

  A relative value with no leading slash is refused too: it would resolve
  against whatever path the browser is on, which is not a target this
  application chose.
  """
  if not path.startswith("/") or path.startswith("//"):
    return False
  if "\\" in path:
    return False
  if any(character in _CONTROL_CHARACTERS for character in path):
    return False
  parts = urlsplit(path)
  return not parts.scheme and not parts.netloc


class OriginCache:
  """The stored ``public_origin``, re-read at most every ``ttl_s`` seconds."""

  def __init__(self, pool: Pool, clock: Clock, *, ttl_s: float = ORIGIN_TTL_S) -> None:
    """Build the cache around the pool it reads through.

    Parameters
    ----------
    pool : Pool
      The process pool.
    clock : Clock
      Injected time source; only ``monotonic()`` is used, because a TTL is
      an elapsed-time question and must survive a wall-clock adjustment.
    ttl_s : float, optional
      Seconds a value stays fresh.
    """
    self._pool = pool
    self._clock = clock
    self._ttl_s = ttl_s
    self._value: str | None = None
    self._read_at: float | None = None

  async def get(self) -> str | None:
    """Return the stored origin, or ``None`` when the deployment is unprovisioned.

    Returns
    -------
    str | None
      The exact origin string, or ``None`` when no row exists. ``None``
      makes step 0a answer ``503`` — an unprovisioned deployment serves
      nothing but ``/health/*``.

    Notes
    -----
    A read failure is **not** cached: the next request tries again. A
    cached "unprovisioned" would otherwise outlive a database that came
    back, and a cached origin would outlive a ``set-origin`` by the TTL at
    most.
    """
    now = self._clock.monotonic()
    if self._read_at is not None and now - self._read_at < self._ttl_s:
      return self._value

    async def _read(conn: PoolConnection) -> str | None:
      return await read_setting(conn, key=ORIGIN_SETTING_KEY)

    value = await run_read_committed(self._pool, _read, op="read-public-origin")
    self._value = value
    self._read_at = now
    return value

  def invalidate(self) -> None:
    """Drop the cached value so the next :meth:`get` re-reads."""
    self._read_at = None


class ReadinessCache:
  """The ``/health/ready`` verdict, re-computed at most every ``ttl_s`` seconds.

  The probe walks the migration journal and three provisioning predicates.
  That is cheap, but a readiness endpoint is polled by an orchestrator
  every few seconds and there is no reason to spend a connection per poll.
  """

  def __init__(self, pool: Pool, clock: Clock, *, ttl_s: float = READINESS_TTL_S) -> None:
    """Build the cache around the pool it probes through.

    Parameters
    ----------
    pool : Pool
      The process pool.
    clock : Clock
      Injected time source; ``monotonic()`` only.
    ttl_s : float, optional
      Seconds a verdict stays fresh.
    """
    self._pool = pool
    self._clock = clock
    self._ttl_s = ttl_s
    self._value: ReadyReport | None = None
    self._read_at: float | None = None

  async def get(self) -> ReadyReport:
    """Return the readiness verdict, fresh or cached.

    Returns
    -------
    ReadyReport
      ``ready`` plus fixed condition names for the log. The names never
      reach the HTTP body, which is fixed text (``H-09``).
    """
    now = self._clock.monotonic()
    cached = self._value
    if cached is not None and self._read_at is not None and now - self._read_at < self._ttl_s:
      return cached

    async def _probe(conn: PoolConnection) -> ReadyReport:
      return await readiness(conn)

    report = await run_read_committed(self._pool, _probe, op="health-ready")
    self._value = report
    self._read_at = now
    return report
