"""Session tokens, their digests and the one cookie (``S2``, ``R10`` / ``D7``).

Pure: this module opens no connection and imports no repository, so
``from app.security.sessions import PREAUTH_TTL`` works on a machine with no
database. The database-facing half of the session layer lives in
:mod:`app.security.session_store`.

What the wire carries and what the database carries are deliberately
different values: the cookie holds an opaque CSPRNG token, the ``sessions``
row holds only its SHA-256 (``SEC-010``). A read of the table therefore
cannot produce a usable cookie.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
  from starlette.responses import Response

__all__ = [
  "ABSOLUTE_TTL",
  "COOKIE_NAME",
  "IDLE_TTL",
  "PREAUTH_TTL",
  "TOKEN_BYTES",
  "TOUCH_INTERVAL",
  "expire_cookie",
  "mint_token",
  "set_cookie",
  "sha256_hex",
]

#: ``__Host-`` binds the cookie to this exact origin with no ``Domain`` and
#: ``Path=/``, which a subdomain cannot overwrite (ruling R10 / delta D7).
COOKIE_NAME: Final = "__Host-crm_session"

#: Random bytes per token. ``SEC-010`` pins a **256-bit floor**; 40 bytes is
#: 320 bits, above it. The surplus is deliberate and is explained in
#: :func:`mint_token`.
TOKEN_BYTES: Final = 40

PREAUTH_TTL: Final = timedelta(minutes=10)
IDLE_TTL: Final = timedelta(minutes=30)
ABSOLUTE_TTL: Final = timedelta(hours=8)
TOUCH_INTERVAL: Final = timedelta(seconds=60)


def sha256_hex(value: str) -> str:
  """Return the lowercase hexadecimal SHA-256 of ``value``.

  Parameters
  ----------
  value : str
    The value to digest; encoded as UTF-8 first, so the digest of a given
    string is the same on every platform.

  Returns
  -------
  str
    64 lowercase hexadecimal characters.

  Notes
  -----
  This is the one digest helper the security layer uses — for session
  tokens, CSRF tokens and the throttle's ``account_key`` alike — so there is
  a single place to read what "the hash" means in this application. It is a
  plain, unsalted SHA-256 by design in all three cases: the inputs are
  either high-entropy random tokens (where a salt adds nothing) or must be
  recomputable from the plaintext by ``manage erase-subject``
  (``DATA_CONTRACT.md`` §3.4).
  """
  return hashlib.sha256(value.encode("utf-8")).hexdigest()


def mint_token() -> tuple[str, str]:
  """Mint one opaque session token and its digest.

  Returns
  -------
  tuple[str, str]
    ``(token, sha256_hex(token))``. The token goes into the cookie and is
    never stored; the digest goes into ``sessions.token_sha256`` and is
    never sent.

  Notes
  -----
  :func:`secrets.token_hex` draws from the operating system CSPRNG
  (``os.urandom``), never from :mod:`random`.

  **Why 320 bits rather than exactly 256.** ``SEC-010`` requires *at least*
  256 bits, and the natural 256-bit spelling — 32 bytes as 64 hexadecimal
  characters — clears that floor with nothing to spare: a conservative
  reader (and ``SEC-010``'s own estimator) measures a token's strength as
  ``len(token) * log2(len(set(token)))``, and about one in four 64-character
  hexadecimal draws happens to omit one of the sixteen digits, which makes
  that estimate read ~250 bits for a value that really carries 256. Minting
  40 bytes removes the margin question entirely at the cost of sixteen
  cookie characters, and a longer token is never the weaker choice.
  """
  token = secrets.token_hex(TOKEN_BYTES)
  return token, sha256_hex(token)


def set_cookie(response: Response, token: str) -> None:
  """Attach the session cookie to ``response`` with the pinned attributes.

  Parameters
  ----------
  response : Response
    The response being returned to the browser.
  token : str
    The raw token from :func:`mint_token`.

  Notes
  -----
  ``Secure; HttpOnly; SameSite=Lax; Path=/``, **no** ``Domain`` and **no**
  ``Max-Age``/``Expires`` (``slice-a.md`` §2.2): a browser-session cookie
  whose real lifetime is the server-side row, so a stolen cookie cannot
  outlive the row and clearing the row ends the session everywhere.
  """
  response.set_cookie(
    key=COOKIE_NAME,
    value=token,
    path="/",
    secure=True,
    httponly=True,
    samesite="lax",
  )


def expire_cookie(response: Response) -> None:
  """Expire the session cookie, repeating the identical attribute set.

  Parameters
  ----------
  response : Response
    The logout response.

  Notes
  -----
  A browser only replaces a cookie when name, ``Path`` and ``Domain`` match,
  so the expiry must repeat them exactly; ``Max-Age=0`` is what deletes it.
  The server-side row is deleted in the same request, so the cookie's fate
  is a convenience, never the control.
  """
  response.set_cookie(
    key=COOKIE_NAME,
    value="",
    max_age=0,
    path="/",
    secure=True,
    httponly=True,
    samesite="lax",
  )
