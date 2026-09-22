"""Unit tests for ``app.services.money`` — PIN C1, ask A-6, `ARC-021` (proposed).

Authority: ``contracts/slice-c.md`` §2(a) (the classification order and the
`CP-##` each shape maps to), §1(h) ask **A-6** (`1250` and `1250.00` share
one canonical digest), §2(h) `ARC-021` (money is `decimal.Decimal` end to
end — the runtime half: :func:`~app.services.money.format_eur` raises on
anything that is not a :class:`~decimal.Decimal`); ``UX_FLOWS.md`` §6.7
(the `CP-68`..`CP-69c` sentences); test hook 5
(``contracts/slice-c.md`` §2(g)).

No HTTP, no database: this is the parametrized table hook 5 names, driven
directly against the shipped module. Every import is deferred into the
test body (this repo's convention while a lane is still landing code) even
though ``app/services/money.py`` has now shipped, so this file keeps
collecting cleanly regardless of import order across a session.
"""

from __future__ import annotations

import pytest

#: `(raw, expected constant NAME)` — the *name* is looked up on the module
#: inside the test body, never at collection time.
_AMOUNT_REJECTIONS: tuple[tuple[str, str], ...] = (
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
  """`parse_amount` classifies every malformed shape into its exact `UX_FLOWS.md` §6.7 sentence."""
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
  assert not isinstance(result, float)


def test_parse_amount_10000000000_00_is_rejected_but_9999999999_99_is_accepted() -> None:
  """The `DECIMAL(12,2)` boundary is exact: one digit over the cap is `CP_69B_TOO_LARGE`."""
  from decimal import Decimal

  from app.services.money import CP_69B_TOO_LARGE, AmountError, parse_amount

  just_over = parse_amount("10000000000.00")
  assert isinstance(just_over, AmountError)
  assert just_over.message == CP_69B_TOO_LARGE

  at_the_cap = parse_amount("9999999999.99")
  assert isinstance(at_the_cap, Decimal)
  assert at_the_cap == Decimal("9999999999.99")


def test_parse_amount_1250_and_1250_00_share_one_canonical_string() -> None:
  """Ask `A-6`: `1250` and `1250.00` canonicalize identically, so a resubmit replays, never 409s."""
  from decimal import Decimal

  from app.services.money import canonical_amount, parse_amount

  bare = parse_amount("1250")
  padded = parse_amount("1250.00")
  assert isinstance(bare, Decimal)
  assert isinstance(padded, Decimal)
  assert canonical_amount(bare) == canonical_amount(padded) == "1250.00"


def test_parse_amount_1_005_is_never_silently_rounded_to_1_01() -> None:
  """§1(g) probe 6's finding: the CLASSIFIER catches `1.005` before any `Decimal` is built.

  `DECIMAL(12,2)` would round `1.005` to `1.01` at the database — PIN C1's
  whole point is that the value never reaches that column: it is refused
  as text, so no `Decimal("1.005")` is ever constructed on this path.
  """
  from app.services.money import AmountError, parse_amount

  result = parse_amount("1.005")
  assert isinstance(result, AmountError)


def test_format_eur_renders_the_pinned_shape() -> None:
  """`format_eur` renders `CONTRACTS.md` §8.2's exact `€ 12,345.00` shape from a `Decimal`."""
  from decimal import Decimal

  from app.services.money import format_eur

  assert format_eur(Decimal("12345.00")) == "€ 12,345.00"
  assert format_eur(Decimal("0.00")) == "€ 0.00"
  assert format_eur(Decimal("9999999999.99")) == "€ 9,999,999,999.99"


def test_format_eur_rejects_a_float_with_typeerror() -> None:
  """`ARC-021`'s runtime half: a `float` reaching `format_eur` fails loudly, never silently."""
  from app.services.money import format_eur

  with pytest.raises(TypeError):
    format_eur(12345.00)


def test_format_eur_rejects_a_plain_string_with_typeerror() -> None:
  """A pre-formatted string is not a `Decimal` either — the guard is by type, not by shape."""
  from app.services.money import format_eur

  with pytest.raises(TypeError):
    format_eur("12345.00")


def test_format_day_renders_the_pinned_shape() -> None:
  """`format_day` renders `UX_FLOWS.md` §1.4's exact `21 Sep 2026` shape, unpadded, no locale."""
  from datetime import date

  from app.services.money import format_day

  assert format_day(date(2026, 9, 21)) == "21 Sep 2026"
  assert format_day(date(2026, 1, 1)) == "1 Jan 2026"
  assert format_day(date(2026, 10, 3)) == "3 Oct 2026"
