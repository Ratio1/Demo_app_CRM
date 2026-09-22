"""Session tokens, their digests and the one cookie.

Pure: this module opens no connection and imports no repository, so
``from app.security.sessions import PREAUTH_TTL`` works on a machine with no
database. The database-facing half of the session layer lives in
:mod:`app.security.session_store`.

What the wire carries and what the database carries are deliberately
different values: the cookie holds an opaque CSPRNG token, the ``sessions``
row holds only its SHA-256. A read of the table therefore
cannot produce a usable cookie.

The cookie's **name and ``Secure`` flag follow the stored public origin's
scheme**, and nothing else — no environment variable selects them, because
a deployment that can be told "this is not really HTTPS" by its environment
has a downgrade switch. An ``https://`` origin gets ``__Host-crm_session``
with ``Secure``; an ``http://`` origin (a local acceptance run behind
nothing) gets ``crm_session`` without it, because a browser discards a
``Secure`` cookie — and every ``__Host-`` cookie — on a plain-HTTP origin,
which would make the application unusable rather than safe. Every other
attribute is identical on both paths, and exactly **one** of the two names
is ever read: see :func:`cookie_name`.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

if TYPE_CHECKING:
  from starlette.responses import Response

__all__ = [
  "ABSOLUTE_TTL",
  "COOKIE_NAME_PLAIN",
  "COOKIE_NAME_SECURE",
  "IDLE_TTL",
  "PREAUTH_TTL",
  "TOKEN_BYTES",
  "TOUCH_INTERVAL",
  "cookie_name",
  "cookie_secure",
  "expire_cookie",
  "mint_token",
  "set_cookie",
  "sha256_hex",
]

#: The name on an ``https://`` origin. ``__Host-`` binds the cookie to that
#: exact origin with no ``Domain`` and ``Path=/``, which a subdomain cannot
#: overwrite. The prefix is only honoured by a browser when the cookie also
#: carries ``Secure``, so the two travel together.
COOKIE_NAME_SECURE: Final = "__Host-crm_session"

#: The name on an ``http://`` origin. The prefix is dropped with the
#: ``Secure`` flag rather than kept as decoration: a browser ignores a
#: ``__Host-`` cookie that is not ``Secure``, so keeping the name would
#: promise a binding that nothing enforces.
COOKIE_NAME_PLAIN: Final = "crm_session"

#: Random bytes per token. The floor this application holds itself to is
#: 256 bits; 40 bytes is 320 bits, above it. The surplus is deliberate and
#: is explained in :func:`mint_token`.
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
  recomputable from the plaintext by ``manage erase-subject``.
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

  **Why 320 bits rather than exactly 256.** The floor is *at least* 256
  bits, and the natural 256-bit spelling — 32 bytes as 64 hexadecimal
  characters — clears that floor with nothing to spare: a conservative
  reader measures a token's strength as
  ``len(token) * log2(len(set(token)))``, and about one in four 64-character
  hexadecimal draws happens to omit one of the sixteen digits, which makes
  that estimate read ~250 bits for a value that really carries 256. Minting
  40 bytes removes the margin question entirely at the cost of sixteen
  cookie characters, and a longer token is never the weaker choice.
  """
  token = secrets.token_hex(TOKEN_BYTES)
  return token, sha256_hex(token)


def cookie_secure(origin: str | None) -> bool:
  """Return whether this deployment's session cookie carries ``Secure``.

  Parameters
  ----------
  origin : str | None
    The stored public origin, or ``None`` when it is not known on this
    request (an unprovisioned deployment, or a path that never reached the
    ``Host``/``Origin`` check).

  Returns
  -------
  bool
    ``False`` only for an origin whose scheme is exactly ``http``.
    Everything else — ``https``, and an origin that is missing or
    unparseable — is ``True``, which fails closed in both directions: a
    ``Secure`` cookie is never sent to a browser over plain HTTP, and a
    ``Secure`` cookie this application cannot place is a session that
    simply does not start.

  Notes
  -----
  The scheme is read here rather than imported from
  :mod:`app.security.origin`, which makes the mirror-image read for
  ``Strict-Transport-Security`` (:func:`app.security.origin.is_https_origin`):
  keeping the one line local is what lets this module stay free of any
  database import. The two differ deliberately on an **unknown** origin —
  the cookie stays ``Secure``, while the header is omitted — because
  omitting a header is inert and dropping ``Secure`` would not be.
  """
  if not origin:
    return True
  return urlsplit(origin.strip()).scheme.casefold() != "http"


def cookie_name(origin: str | None) -> str:
  """Return the one session cookie name this deployment reads and writes.

  Parameters
  ----------
  origin : str | None
    The stored public origin, as for :func:`cookie_secure`.

  Returns
  -------
  str
    :data:`COOKIE_NAME_SECURE` or :data:`COOKIE_NAME_PLAIN`.

  Notes
  -----
  Exactly one name is live at a time. Every writer *and* every reader of
  the cookie goes through this function, so a token presented under the
  other name is not a session at all — there is no fallback that would let
  a plain-HTTP cookie be honoured by an HTTPS deployment or the reverse.
  """
  return COOKIE_NAME_SECURE if cookie_secure(origin) else COOKIE_NAME_PLAIN


def set_cookie(response: Response, token: str, *, origin: str | None) -> None:
  """Attach the session cookie to ``response`` with the pinned attributes.

  Parameters
  ----------
  response : Response
    The response being returned to the browser.
  token : str
    The raw token from :func:`mint_token`.
  origin : str | None
    The stored public origin, which decides the name and ``Secure`` and
    nothing else.

  Notes
  -----
  ``HttpOnly; SameSite=Lax; Path=/``, **no** ``Domain`` and **no**
  ``Max-Age``/``Expires``: a browser-session cookie
  whose real lifetime is the server-side row, so a stolen cookie cannot
  outlive the row and clearing the row ends the session everywhere.
  ``Secure`` — and with it the ``__Host-`` name — is added on an ``https``
  origin; see :func:`cookie_secure`.
  """
  response.set_cookie(
    key=cookie_name(origin),
    value=token,
    path="/",
    secure=cookie_secure(origin),
    httponly=True,
    samesite="lax",
  )


def expire_cookie(response: Response, *, origin: str | None) -> None:
  """Expire the session cookie, repeating the identical attribute set.

  Parameters
  ----------
  response : Response
    The logout response.
  origin : str | None
    The stored public origin, so the expiry names the same cookie the
    login set.

  Notes
  -----
  A browser only replaces a cookie when name, ``Path`` and ``Domain`` match,
  so the expiry must repeat them exactly; ``Max-Age=0`` is what deletes it.
  The server-side row is deleted in the same request, so the cookie's fate
  is a convenience, never the control.
  """
  response.set_cookie(
    key=cookie_name(origin),
    value="",
    max_age=0,
    path="/",
    secure=cookie_secure(origin),
    httponly=True,
    samesite="lax",
  )
