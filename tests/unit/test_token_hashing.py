"""Unit tests for session-token minting.

Session tokens are 256-bit CSPRNG values, and only their SHA-256 digest is
stored in the database (``app.security.sessions.mint_token() -> tuple[str,
str]``).
"""

from __future__ import annotations

import hashlib
import math

MIN_ENTROPY_BITS = 256


def _mint() -> tuple[str, str]:
  """Call ``mint_token()``, deferred-imported.

  Returns
  -------
  tuple[str, str]
    ``(token, sha256_hex)``.
  """
  from app.security.sessions import mint_token

  token, digest = mint_token()
  return str(token), str(digest)


def test_the_returned_digest_is_sha256_of_the_token() -> None:
  """The second element is exactly ``sha256(token).hexdigest()``, not some other digest."""
  token, digest = _mint()
  assert digest == hashlib.sha256(token.encode("utf-8")).hexdigest()


def test_the_digest_is_64_lowercase_hex_characters() -> None:
  """A SHA-256 hex digest is always 64 lowercase hex characters."""
  _token, digest = _mint()
  assert len(digest) == 64
  assert digest == digest.lower()
  assert all(character in "0123456789abcdef" for character in digest)


def test_the_token_carries_at_least_256_bits_of_entropy() -> None:
  """The raw token, decoded from its wire encoding, is at least 256 bits.

  ``mint_token`` does not pin an encoding (hex, URL-safe base64, ...), so
  this decodes generously: the token must contain enough *symbols*, given
  the alphabet it visibly uses, to carry >= 256 bits. A 256-bit CSPRNG value
  needs 64 hex characters, 43 base64url characters (6 bits/char, ceil(256/6))
  or 32 raw bytes — this test accepts any of those encodings by measuring
  the token's own alphabet size and length rather than assuming one.
  """
  token, _digest = _mint()
  alphabet = set(token)
  # A conservative floor: even the widest common encoding here (base64url,
  # ~64 symbols) needs at least 43 characters for 256 bits; a narrower
  # alphabet (hex, 16 symbols) needs 64. Fail loudly on anything that could
  # not possibly reach the floor for its own observed alphabet size.
  bits_per_symbol = math.log2(max(len(alphabet), 2))
  estimated_bits = len(token) * bits_per_symbol
  assert estimated_bits >= MIN_ENTROPY_BITS, (
    f"token length {len(token)} over an alphabet of {len(alphabet)} symbols "
    f"estimates only {estimated_bits:.1f} bits, short of the 256-bit floor"
  )


def test_tokens_are_unique_across_many_mints() -> None:
  """1,000 consecutive mints produce 1,000 distinct tokens and 1,000 distinct digests.

  A CSPRNG source makes a collision astronomically unlikely; a broken source
  (a fixed seed, a narrow counter) would collide immediately at this sample
  size.
  """
  sample_size = 1_000
  tokens: set[str] = set()
  digests: set[str] = set()
  for _ in range(sample_size):
    token, digest = _mint()
    tokens.add(token)
    digests.add(digest)
  assert len(tokens) == sample_size
  assert len(digests) == sample_size


def test_no_two_mints_share_the_python_random_module() -> None:
  """The module uses a CSPRNG (``secrets``/``os.urandom``), not ``random``.

  A seeded ``random.seed(0)`` around the call must not make two mints
  collide the way it would for the non-cryptographic ``random`` module.
  """
  import random

  random.seed(0)
  first_token, _ = _mint()
  random.seed(0)
  second_token, _ = _mint()
  assert first_token != second_token
