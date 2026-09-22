"""Unit tests for ``app.services.money``.

Money is parsed and classified as text before ever becoming a
:class:`~decimal.Decimal`: a malformed amount is rejected with one of a
fixed set of messages, `1250` and `1250.00` canonicalize to the same
string, and every downstream function (:func:`~app.services.money.format_eur`)
raises on anything that is not a `decimal.Decimal` — money stays
`decimal.Decimal` end to end, never a `float`.

No HTTP, no database: this is a parametrized table driven directly against
the shipped module. Every import is deferred into the test body so this
file keeps collecting cleanly regardless of import order across a session.
"""

from __future__ import annotations

import pytest

#: `(raw, expected constant NAME)` — the *name* is looked up on the module
#: inside the test body, never at collection time. `raw` is `str | None`
#: because the last case below is the missing-field shape (`None`, not
#: `""`), which `parse_amount` must classify identically to the empty string.
_AMOUNT_REJECTIONS: tuple[tuple[str | None, str], ...] = (
  ("", "CP_68_AMOUNT_REQUIRED"),
  ("-1.00", "CP_69_AMOUNT_NEGATIVE"),
  ("1.005", "CP_69A_TOO_MANY_DECIMALS"),
  ("-1.005", "CP_69_AMOUNT_NEGATIVE"),  # classification order: sign before scale (§2(a))
  ("10000000000.00", "CP_69B_TOO_LARGE"),
  ("1,250.00", "CP_69C_MALFORMED"),
  ("+1", "CP_69C_MALFORMED"),
  ("1e3", "CP_69C_MALFORMED"),
  ("NaN", "CP_69C_MALFORMED"),
  ("Infinity", "CP_69C_MALFORMED"),
  ("abc", "CP_69C_MALFORMED"),
  (" ", "CP_68_AMOUNT_REQUIRED"),
  (None, "CP_68_AMOUNT_REQUIRED"),
)


@pytest.mark.parametrize(("raw", "expected_constant_name"), _AMOUNT_REJECTIONS)
def test_parse_amount_rejects_every_malformed_shape_with_its_pinned_message(
  raw: str | None, expected_constant_name: str
) -> None:
  """`parse_amount` classifies every malformed shape into its exact pinned message."""
  import app.services.money as money_module
  from app.services.money import AmountError, parse_amount

  expected_message = getattr(money_module, expected_constant_name)
  result = parse_amount(raw)
  assert isinstance(result, AmountError), f"{raw!r} should have been rejected, got {result!r}"
  assert result.message == expected_message, (
    f"{raw!r} classified as {result.message!r}, expected {expected_message!r}"
  )


@pytest.mark.parametrize("raw", ["1250", "1250.00", "0", "0.00", "0.01", "9999999999.99"])
def test_parse_amount_accepts_every_valid_shape_as_a_decimal(raw: str) -> None:
  """A well-formed amount parses to a `decimal.Decimal`, never a `float`."""
  from decimal import Decimal

  from app.services.money import parse_amount

  result = parse_amount(raw)
  assert isinstance(result, Decimal), f"{raw!r} should have parsed, got {result!r}"
  # mypy (warn_unreachable): once narrowed to Decimal, a float instance is
  # statically impossible (the two are unrelated extension types that cannot
  # share a subclass) — but "never a float" is the property under test, so
  # the runtime check stays as explicit, readable evidence.
  assert not isinstance(result, float)  # type: ignore[unreachable]


def test_parse_amount_10000000000_00_is_rejected_but_9999999999_99_is_accepted() -> None:
  """The `DECIMAL(12,2)` boundary is exact: one digit over the cap is rejected as too large."""
  from decimal import Decimal

  from app.services.money import CP_69B_TOO_LARGE, AmountError, parse_amount

  just_over = parse_amount("10000000000.00")
  assert isinstance(just_over, AmountError)
  assert just_over.message == CP_69B_TOO_LARGE

  at_the_cap = parse_amount("9999999999.99")
  assert isinstance(at_the_cap, Decimal)
  assert at_the_cap == Decimal("9999999999.99")


def test_parse_amount_1250_and_1250_00_share_one_canonical_string() -> None:
  """`1250` and `1250.00` canonicalize identically, so a resubmit replays, never 409s."""
  from decimal import Decimal

  from app.services.money import canonical_amount, parse_amount

  bare = parse_amount("1250")
  padded = parse_amount("1250.00")
  assert isinstance(bare, Decimal)
  assert isinstance(padded, Decimal)
  assert canonical_amount(bare) == canonical_amount(padded) == "1250.00"


def test_parse_amount_1_005_is_never_silently_rounded_to_1_01() -> None:
  """The classifier catches `1.005` before any `Decimal` is built.

  `DECIMAL(12,2)` would round `1.005` to `1.01` at the database — the value
  must never reach that column: it is refused as text, so no
  `Decimal("1.005")` is ever constructed on this path.
  """
  from app.services.money import AmountError, parse_amount

  result = parse_amount("1.005")
  assert isinstance(result, AmountError)


def test_format_eur_renders_the_pinned_shape() -> None:
  """`format_eur` renders the exact `€ 12,345.00` shape from a `Decimal`."""
  from decimal import Decimal

  from app.services.money import format_eur

  assert format_eur(Decimal("12345.00")) == "€ 12,345.00"
  assert format_eur(Decimal("0.00")) == "€ 0.00"
  assert format_eur(Decimal("9999999999.99")) == "€ 9,999,999,999.99"


def test_format_eur_rejects_a_float_with_typeerror() -> None:
  """A `float` reaching `format_eur` fails loudly, never silently."""
  from app.services.money import format_eur

  with pytest.raises(TypeError):
    format_eur(12345.00)


def test_format_eur_rejects_a_plain_string_with_typeerror() -> None:
  """A pre-formatted string is not a `Decimal` either — the guard is by type, not by shape."""
  from app.services.money import format_eur

  with pytest.raises(TypeError):
    format_eur("12345.00")


def test_format_day_renders_the_pinned_shape() -> None:
  """`format_day` renders the exact `21 Sep 2026` shape, unpadded, no locale."""
  from datetime import date

  from app.services.money import format_day

  assert format_day(date(2026, 9, 21)) == "21 Sep 2026"
  assert format_day(date(2026, 1, 1)) == "1 Jan 2026"
  assert format_day(date(2026, 10, 3)) == "3 Oct 2026"
