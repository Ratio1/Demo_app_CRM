"""The only time source in the application.

Every expiry, window and timing measurement in ``app/`` is read from a
:class:`Clock` handed in through a constructor. No other module calls
``datetime.now()``, ``datetime.utcnow()``, ``time.time()`` or
``time.monotonic()``. The test suite asserts that no module does, and it is
what lets every expiry test advance a clock instead of sleeping.

:class:`Clock` exposes ``monotonic()`` as well as ``now()`` because
``CorrelationMiddleware``'s ``duration_ms`` is the one place an implementer
would otherwise reach for :func:`time.monotonic` directly.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Protocol

__all__ = ["Clock", "ManualClock", "SystemClock"]


class Clock(Protocol):
  """A source of the current instant and of an elapsed-time counter."""

  def now(self) -> datetime:
    """Return the current instant as a timezone-aware UTC datetime.

    Returns
    -------
    datetime
      Timezone-aware, ``tzinfo`` is :data:`datetime.UTC`.
    """
    ...

  def monotonic(self) -> float:
    """Return a monotonically non-decreasing counter in seconds.

    Returns
    -------
    float
      Only differences between two readings are meaningful; the origin is
      unspecified.
    """
    ...


class SystemClock:
  """The production clock: the operating system's UTC and monotonic clocks."""

  def now(self) -> datetime:
    """Return the current UTC instant.

    Returns
    -------
    datetime
      ``datetime.now(UTC)`` — timezone-aware, never naive.
    """
    return datetime.now(UTC)

  def monotonic(self) -> float:
    """Return the process monotonic counter.

    Returns
    -------
    float
      :func:`time.monotonic`, which never goes backwards across a system
      clock adjustment.
    """
    return time.monotonic()


class ManualClock:
  """A clock tests construct and advance by hand; never selected by anything.

  There is no environment variable, configuration key or branch anywhere in
  ``app/`` that selects this class: a test constructs it and injects it —
  either through the constructor of the one service under test, or through
  ``create_app(clock=…)``, which
  hands the same instance to ``CorrelationMiddleware`` and to every service
  the lifespan builds, so an in-process request through the whole
  application can be driven by advancing it.
  """

  def __init__(self, start: datetime) -> None:
    """Fix the clock at ``start``.

    Parameters
    ----------
    start : datetime
      The initial instant. Must be timezone-aware; it is converted to UTC.

    Raises
    ------
    ValueError
      If ``start`` is naive. A naive instant would silently compare wrongly
      against the timezone-aware values every expiry column holds.
    """
    if start.tzinfo is None:
      raise ValueError("ManualClock needs a timezone-aware start instant")
    self._now = start.astimezone(UTC)
    self._monotonic = 0.0

  def now(self) -> datetime:
    """Return the instant this clock currently stands at.

    Returns
    -------
    datetime
      Timezone-aware UTC.
    """
    return self._now

  def monotonic(self) -> float:
    """Return the elapsed-seconds counter, advanced only by :meth:`advance`.

    Returns
    -------
    float
      Seconds since construction, as advanced.
    """
    return self._monotonic

  def advance(self, delta: timedelta) -> None:
    """Move the clock forward by ``delta``.

    Parameters
    ----------
    delta : timedelta
      How far to move. Both the instant and the monotonic counter advance
      by the same amount.

    Raises
    ------
    ValueError
      If ``delta`` is negative: a monotonic counter that goes backwards
      would make an elapsed-time assertion meaningless.
    """
    if delta < timedelta(0):
      raise ValueError("a clock never moves backwards")
    self._now += delta
    self._monotonic += delta.total_seconds()
