"""EUR money, and the two display formats every deal surface renders.

Money is :class:`decimal.Decimal` end to end: an amount is parsed
server-side before it is bound, and it is displayed as ``€ 12,345.00``.

Three rules carry that, and all three live here rather than in a service so
that four surfaces cannot spell them four ways:

*The submitted string is classified before any ``Decimal`` exists.*
``DECIMAL(12,2)`` **rounds** a third decimal place rather than refusing it,
so the column is no second line of defence
for scale: :data:`AMOUNT_RE` is the only control there is, and it runs on
the text. A rejected value is never handed to :class:`decimal.Decimal`, so
no rounding can happen behind the refusal. The ``CHECK (amount >= 0)`` is a
real second line for the **sign**, and the ten-digit cap is what keeps the
column's own ``22003`` unreachable.

*Nothing on a money path is a float.* There is no ``float(``, no
``round(``, no ``%f`` and no :class:`decimal.Decimal` built from a float in
this module or in anything it hands a value to.
:meth:`decimal.Decimal.__format__` is exact, which is why
:func:`format_eur` can be a plain format string.

*One canonical spelling per amount.* :func:`canonical_amount` is what the
idempotency digest hashes, so ``1250`` and ``1250.00`` are one payload and a
resubmission of the first after the second **replays** instead of answering
a spurious 409 ``duplicate``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
  from datetime import date

__all__ = [
  "AMOUNT_FORMAT_MESSAGE",
  "AMOUNT_NEGATIVE_MESSAGE",
  "AMOUNT_RE",
  "AMOUNT_REQUIRED_MESSAGE",
  "AMOUNT_TOO_LARGE_MESSAGE",
  "AMOUNT_TOO_MANY_DECIMALS_MESSAGE",
  "CENTS",
  "AmountError",
  "canonical_amount",
  "format_day",
  "format_eur",
  "parse_amount",
]

#: The acceptor: one to ten integer digits and at most
#: two decimals. No sign, no thousands separator, no exponent, no leading
#: ``+``, no whitespace inside. Anchored with ``\A``/``\Z`` and never with
#: ``^``/``$``, which also match at a newline — ``"1250\n-1"`` would pass a
#: ``^…$`` pattern and reach the database as a negative amount.
AMOUNT_RE: Final = re.compile(r"\A\d{1,10}(\.\d{1,2})?\Z")

#: The quantum of ``DECIMAL(12,2)``. Every accepted amount is quantized to
#: it, which is what makes ``1250`` and ``1250.00`` one value and one digest.
CENTS: Final = Decimal("0.01")

#: The three decimals-or-worse patterns, matched **in this order** on the
#: stripped string so that ``-1.005`` reads as a negative amount and not as
#: a scale error. Each exists to give one wrong value its own
#: sentence instead of the residual one.
_TOO_MANY_DECIMALS_RE: Final = re.compile(r"\A\d{1,10}\.\d{3,}\Z")
_TOO_LARGE_RE: Final = re.compile(r"\A\d{11,}(\.\d{1,2})?\Z")

#: The field errors a submitted amount can produce, as resolved strings —
#: the same shape the contact and deal validators use.
AMOUNT_REQUIRED_MESSAGE: Final = "Enter an amount."
AMOUNT_NEGATIVE_MESSAGE: Final = "Enter 0.00 or more."
AMOUNT_TOO_MANY_DECIMALS_MESSAGE: Final = "Use at most two decimals, such as 1250.00."
AMOUNT_TOO_LARGE_MESSAGE: Final = "Enter an amount up to 9999999999.99."

#: The residual malformed-amount case — a thousands separator, an exponent,
#: a stray ``+``, letters. One sentence for everything the three patterns
#: above do not name, so no wrong value is left without an explanation.
AMOUNT_FORMAT_MESSAGE: Final = "Enter an amount like 1250.00."

#: The month names. Written out rather than taken from
#: ``strftime("%b")``, which is locale-dependent, or from ``"%-d"``, which
#: is not portable — the rendered date must read ``21 Sep 2026`` on every
#: platform the image runs on.
_MONTHS: Final[tuple[str, ...]] = (
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
)


@dataclass(frozen=True, slots=True)
class AmountError:
  """Why one submitted amount was refused.

  Attributes
  ----------
  message : str
    The resolved sentence, ready to be put in an
    ``Invalid`` outcome's ``errors["amount"]`` list. It names no submitted
    value, so nothing a user typed is echoed through a copy string.
  """

  message: str


def parse_amount(raw: str | None) -> Decimal | AmountError:
  """Turn one submitted amount into a :class:`~decimal.Decimal`, or refuse it.

  Parameters
  ----------
  raw : str | None
    The ``amount`` field as the body carried it, or ``None`` when the body
    omitted it. Attacker-controlled.

  Returns
  -------
  Decimal | AmountError
    The quantized amount, or the refusal carrying the sentence that
    describes it. The three named cases — negative, more than two
    decimals, above ``DECIMAL(12,2)`` — each get their own message, and
    everything else gets the residual one.

  Notes
  -----
  The classification order is binding: empty, then
  the leading ``-``, then the scale, then the magnitude, then the residual
  case. It runs **on the string**: a value that will be refused is never
  passed to :class:`decimal.Decimal`, so ``1.005`` cannot be quietly
  rounded to ``1.01`` on its way to being rejected — and a hostile
  ``"NaN"``, ``"Infinity"`` or ``"1e9"``, every one of which
  :class:`decimal.Decimal` accepts, never reaches the constructor at all.

  :meth:`~decimal.Decimal.quantize` on a value that already has two or
  fewer decimal places is exact and cannot raise, because the pattern has
  already bounded the scale; it is what gives every accepted amount one
  spelling.
  """
  text = "" if raw is None else raw.strip()
  if not text:
    return AmountError(AMOUNT_REQUIRED_MESSAGE)
  if text.startswith("-"):
    return AmountError(AMOUNT_NEGATIVE_MESSAGE)
  if _TOO_MANY_DECIMALS_RE.match(text) is not None:
    return AmountError(AMOUNT_TOO_MANY_DECIMALS_MESSAGE)
  if _TOO_LARGE_RE.match(text) is not None:
    return AmountError(AMOUNT_TOO_LARGE_MESSAGE)
  if AMOUNT_RE.match(text) is None:
    return AmountError(AMOUNT_FORMAT_MESSAGE)
  return Decimal(text).quantize(CENTS)


def canonical_amount(value: Decimal) -> str:
  """Return the one spelling of ``value`` the payload digest hashes.

  Parameters
  ----------
  value : Decimal
    An amount that came back from :func:`parse_amount` or from a row.

  Returns
  -------
  str
    Two decimal places, no separator and no currency — ``"1250.00"``. The
    digest is computed over this rather than over what was typed, so
    ``1250`` resubmitted after ``1250.00`` is a **replay** and not a 409
    ``duplicate``.
  """
  return str(value.quantize(CENTS))


def format_eur(value: object) -> str:
  """Render one amount as ``€ 12,345.00``.

  Parameters
  ----------
  value : object
    The amount. Typed :class:`object` and not :class:`~decimal.Decimal`
    because this is registered as a Jinja filter, where the call site is
    a template and the annotation buys nothing — the ``isinstance`` check
    below is the guard that actually holds.

  Returns
  -------
  str
    One ordinary space after the ``€``, a comma thousands separator and
    exactly two decimals, from :meth:`decimal.Decimal.__format__`, which is
    exact.

  Raises
  ------
  TypeError
    When ``value`` is not a :class:`~decimal.Decimal`. This is the runtime
    half of the no-float rule: a ``float`` that reached a money path through an
    untyped seam fails loudly here instead of rendering a value that is
    off by a cent. The message names the type it got and never the value.
  """
  if not isinstance(value, Decimal):
    raise TypeError(f"money must be a decimal.Decimal, got {type(value).__name__}")
  return f"€ {value:,.2f}"


def format_day(value: date) -> str:
  """Render one date as ``21 Sep 2026``.

  Parameters
  ----------
  value : date
    A stored ``DATE``. ISO ``yyyy-mm-dd`` exists **only on the wire** —
    ``<input type="date">`` values, ``<time datetime="…">`` and the
    "enter a date as YYYY-MM-DD" message — so a user never reads a bare
    ISO date.

  Returns
  -------
  str
    The day unpadded, the three-letter month and the four-digit year.
  """
  return f"{value.day} {_MONTHS[value.month - 1]} {value.year}"
