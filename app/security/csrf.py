"""The per-session CSRF token.

Pure: no connection, no repository. Only the token's SHA-256 reaches the
database, in ``sessions.csrf_sha256``, so the token is bound to exactly one
session row and a token minted for another session is worthless.

Why the token is **derived** from the session token rather than drawn
independently
-------------------------------------------------------------------
Every page that carries a form must render the *token*, while the database
holds only its *digest*: neither raw value ever reaches the database. A
token drawn independently at INSERT time is therefore unrecoverable on the
next request, which leaves three ways out, and two of them break a rule
this application keeps everywhere else:

* store the raw token — then a database read discloses a live credential;
* re-mint it on each render and ``UPDATE`` the row — a write on a safe
  method, which no ``GET`` here performs;
* re-mint it and insert a new row — a second pre-auth row per render,
  where a still-valid pre-auth cookie must instead **reuse** its row.

So the token is a one-way function of the session token:
``sha256("crm-csrf-v1:" + session_token)``. The security properties that
matter are unchanged. It is unpredictable to anyone who cannot read the
cookie, which is the entire CSRF threat model — a cross-site attacker can
cause a request but cannot read a ``__Host-``, ``HttpOnly``, ``SameSite=Lax``
cookie. It is still validated **against the session row's stored digest**,
so it is a synchronizer token and not a bare double-submit: a token from
another session fails. And the derivation is one-way, so the CSRF token —
which appears in HTML, in page caches and in browser history — never leaks
the session token back.

The derivation is documented here because it is the one place where a
reader might expect an independently drawn secret and find a derived one.
"""

from __future__ import annotations

import hmac
from typing import Final

from app.security.sessions import sha256_hex

__all__ = ["CSRF_DERIVATION_LABEL", "csrf_for_token", "verify_csrf"]

#: Domain separation, and a version marker: a future change to the
#: derivation changes this string, which invalidates every outstanding
#: token at once instead of silently accepting both forms.
CSRF_DERIVATION_LABEL: Final = "crm-csrf-v1:"


def csrf_for_token(session_token: str) -> tuple[str, str]:
  """Derive the CSRF token for a session, and its stored digest.

  Parameters
  ----------
  session_token : str
    The raw session token from the cookie — never the digest, which is all
    the database holds.

  Returns
  -------
  tuple[str, str]
    ``(csrf_token, sha256_hex(csrf_token))``. The token is rendered into
    the hidden ``csrf_token`` field; the digest is what
    ``create_preauth_session`` and ``promote_session`` store, and what
    :func:`verify_csrf` compares against.
  """
  token = sha256_hex(CSRF_DERIVATION_LABEL + session_token)
  return token, sha256_hex(token)


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
    answers all three with the same ``403`` body.

  Notes
  -----
  :func:`hmac.compare_digest` rather than ``==``: the right operand is a
  stored secret's digest and the left is attacker-supplied, and a
  byte-by-byte early exit would leak how much of a guess was right.
  """
  if not submitted or not stored_sha256:
    return False
  return hmac.compare_digest(sha256_hex(submitted), stored_sha256)
