"""The refusals the request pipeline raises, and nothing else.

Every class here is a *decision already taken*: the pipeline step that
raises it has finished deciding, and the only thing left is to render the
answer ``slice-a.md`` §2.1 pins for it. None of them carries a message a
user sees, a value read from the request, or anything from the database —
the rendered page comes from a frozen template and a copy id, so two
different causes of the same status are byte-identical apart from the
correlation id (``R27``).

They are ordinary exceptions rather than ``HTTPException`` subclasses
because three of them are raised from a pure-ASGI middleware, outside the
router, where Starlette's exception handlers do not run.
"""

from __future__ import annotations

__all__ = [
  "BudgetExceeded",
  "ForcedResetRequired",
  "NoSession",
  "NotProvisioned",
  "RoleRequired",
  "StepZeroDenied",
  "TooLarge",
]


class StepZeroDenied(Exception):
  """``Host``, ``Origin`` or CSRF did not match — the step-0 ``403``.

  Every cause renders the same ``errors/403.html`` with ``reason="session"``
  and the public shell, so the response cannot tell a spoofed ``Host`` from
  a stale form (``ACC-010``, ``SEC-040``).
  """


class NotProvisioned(Exception):
  """No ``public_origin`` row exists yet — the ``503`` of ``slice-a.md`` §2.1.

  Raised before routing, so an unprovisioned deployment answers the same
  way on every path but ``/health/*``.
  """


class NoSession(Exception):
  """Step 1 found no live session.

  A private ``GET`` becomes ``303 /login``; an unsafe method becomes ``403``;
  an ``HX-Request`` becomes ``401`` with ``HX-Redirect`` (``R26``).
  """


class ForcedResetRequired(Exception):
  """Step 2: a ``must_change_password`` session asked for a barred route."""


class RoleRequired(Exception):
  """Step 3: the principal's role does not admit this function."""


class BudgetExceeded(Exception):
  """A rate budget or the login throttle refused this request.

  Attributes
  ----------
  retry_after_s : int
    Whole seconds until the window rolls, for the ``Retry-After`` header.
    Never longer than the window itself, so the advertised recovery matches
    the real one (``SEC-031``(c)).
  """

  def __init__(self, retry_after_s: int) -> None:
    """Record the bounded retry hint.

    Parameters
    ----------
    retry_after_s : int
      Seconds until recovery; clamped to at least one so a client never
      reads ``Retry-After: 0`` and retries immediately.
    """
    super().__init__("rate budget exceeded")
    self.retry_after_s = max(1, retry_after_s)


class TooLarge(Exception):
  """The request body exceeded the 64 KiB cap before any handler saw it."""
