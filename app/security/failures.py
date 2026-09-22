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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from uuid import UUID

__all__ = [
  "BudgetExceeded",
  "ContactNotFound",
  "DealNotFound",
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


class ContactNotFound(Exception):
  """Step 4: the scope predicate admitted no contact — foreign **or** missing.

  Raised, never returned, so the six contact surfaces cannot drift apart
  (``contracts/slice-b.md`` §2(a) note 1): one handler writes
  ``ACCESS_MATRIX.md`` §4.5 **row 1** and renders the one ``404`` body, so
  a foreign object and a missing one are byte-identical for the same
  principal modulo the correlation id (**PIN 8**, **R27**).

  Raising it from inside ``run_serializable`` also unwinds the transaction
  and returns its connection **before** the handler opens the deny-audit's
  own one, which is the one-connection-at-a-time rule
  (``DATA_CONTRACT.md`` §6.1).

  Attributes
  ----------
  object_id : UUID | None
    The requested id, **iff** the application already validated it as a
    canonical 36-character UUID; ``None`` otherwise (§4.5 rule 1). A
    hostile path segment would violate ``ck_audit_events_object_id`` and
    the best-effort write would then die on exactly the inputs the row
    exists to record.
  """

  def __init__(self, object_id: UUID | None) -> None:
    """Record the id the deny row may carry.

    Parameters
    ----------
    object_id : UUID | None
      The canonical id, or ``None`` when the segment was not canonical.
    """
    super().__init__("contact not found")
    self.object_id = object_id


class DealNotFound(Exception):
  """Step 4: the join to ``contacts`` admitted no deal — foreign **or** missing.

  The deal twin of :class:`ContactNotFound`, and for the same reason
  (``contracts/slice-c.md`` §2(a) decision 1): raised rather than returned,
  so the five deal surfaces — detail, edit form, update, stage change and
  the two terminal moves — reach **one** handler, which writes
  ``ACCESS_MATRIX.md`` §4.5 **row 2** (``deal`` / ``access_denied``) and
  renders the one ``404`` body. A foreign deal and a missing one are then
  byte-identical for the same principal modulo the correlation id
  (``ACC-202``, **PIN 8**, **R27**).

  A **parent** miss is not this exception. ``POST /contacts/{id}/deals`` and
  ``GET /contacts/{id}/deals/new`` raise :class:`ContactNotFound` instead,
  because §4.5 rule 2 says a reference-as-parent denial names the *parent*:
  the object the caller was refused is the contact (``ACC-207``,
  ``ACC-228``).

  Attributes
  ----------
  object_id : UUID | None
    The requested id, **iff** it was already validated as a canonical
    36-character UUID; ``None`` otherwise (§4.5 rule 1).
  """

  def __init__(self, object_id: UUID | None) -> None:
    """Record the id the deny row may carry.

    Parameters
    ----------
    object_id : UUID | None
      The canonical id, or ``None`` when the segment was not canonical.
    """
    super().__init__("deal not found")
    self.object_id = object_id
