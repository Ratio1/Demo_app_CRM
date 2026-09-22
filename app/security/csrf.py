"""The synchronizer CSRF token (``S3``, ``SEC-020``-``SEC-023``).

Pure: no connection, no repository. The token is minted with the same
CSPRNG as a session token and only its SHA-256 reaches the database, in
``sessions.csrf_sha256`` — so the token is bound to exactly one session row
and a token from another session is worthless.

The comparison is constant-time. The values compared are digests of
attacker-supplied input, so a byte-by-byte early exit would leak how much of
a guess was right.
"""

from __future__ import annotations

import hmac

from app.security.sessions import mint_token, sha256_hex

__all__ = ["mint_csrf", "verify_csrf"]


def mint_csrf() -> tuple[str, str]:
  """Mint one CSRF token and its digest.

  Returns
  -------
  tuple[str, str]
    ``(token, sha256_hex(token))``. The token is rendered into the form's
    hidden ``csrf_token`` field; the digest is stored on the session row.
  """
  return mint_token()


def verify_csrf(submitted: str | None, stored_sha256: str | None) -> bool:
  """Return whether ``submitted`` matches the digest held on the session row.

  Parameters
  ----------
  submitted : str | None
    The value of the ``csrf_token`` form field, or ``None`` when the field
    was absent altogether.
  stored_sha256 : str | None
    ``sessions.csrf_sha256`` for the row this request authenticated
    against, or ``None`` when there is no such row.

  Returns
  -------
  bool
    ``True`` only when both are present and the digests match. A missing
    field, a missing row and a wrong token are one outcome — the caller
    answers all three with the same ``403`` body (``R27``).

  Notes
  -----
  :func:`hmac.compare_digest` is used rather than ``==`` even though both
  operands are digests of public-ish values: it costs nothing and removes a
  whole class of argument about whether the timing of a rejected token is
  observable.
  """
  if not submitted or not stored_sha256:
    return False
  return hmac.compare_digest(sha256_hex(submitted), stored_sha256)
