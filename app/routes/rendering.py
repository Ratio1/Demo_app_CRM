"""The Jinja environment, the frozen base context and the notice table.

Authority: delta **D11** (the explicit environment), ``CONTRACTS.md`` §8.1
(the frozen base context), ``slice-a.md`` §2.7 / ruling **R20** (the
``?notice=`` enum), ``UX_FLOWS.md`` §6 (every string below).

Three decisions worth reading before changing anything here:

*The environment is explicit.* ``Jinja2Templates(directory=…)`` builds
``Environment(autoescape=select_autoescape())``, which escapes ``.html``,
``.htm`` and ``.xml`` and renders ``.txt``, ``.j2`` and ``.jinja``
**unescaped** — verified (``slice-a.md`` §8.5). ``autoescape=True`` makes
``SEC-005`` independent of a filename. ``undefined=StrictUndefined`` turns a
missing context key into a loud failure instead of a silently blank page,
and ``auto_reload=False`` keeps a served process from stat-ing templates.

*The environment is module-level, not per-application.* Templates are static
files baked into the image. Building them here means an error page still
renders when the application has no context at all — which is exactly when
a 500 or a 503 needs to be rendered.

*Notice text never travels in a URL.* The redirect carries a code from a
fixed allowlist and the table below turns it into copy. An unknown,
repeated or malformed value renders no banner at all: it is never echoed
and never becomes a 400 (**R20**).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import jinja2
from fastapi.templating import Jinja2Templates

from app.security.csrf import csrf_for_token
from app.security.sessions import COOKIE_NAME

if TYPE_CHECKING:
  from pathlib import Path

  from starlette.requests import Request
  from starlette.responses import Response

  from app.security.principal import Principal

__all__ = [
  "APP_NAME",
  "NOTICE_CODES",
  "TEMPLATES",
  "TEMPLATES_DIR",
  "base_context",
  "csrf_token_for_request",
  "notice_for",
  "render",
]

APP_NAME: Final = "Demo_App_CRM"


def _templates_dir() -> Path:
  """Return the template directory, resolved from this package.

  Returns
  -------
  Path
    ``app/templates`` next to the code that renders it, so the working
    directory never decides whether a page can be found.
  """
  from pathlib import Path

  return Path(__file__).resolve().parent.parent / "templates"


TEMPLATES_DIR: Final = _templates_dir()

TEMPLATES: Final = Jinja2Templates(
  env=jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,
    undefined=jinja2.StrictUndefined,
    auto_reload=False,
  )
)

#: Slice A's three codes (``slice-a.md`` §2.7). Later slices extend this
#: table additively; nothing else may render a banner.
NOTICE_CODES: Final[dict[str, dict[str, str]]] = {
  "signed_out": {"kind": "success", "text": "You are signed out."},
  "session_ended": {"kind": "info", "text": "Your session ended. Sign in to continue."},
  "password_changed": {
    "kind": "success",
    "text": "Password changed. You have been signed out everywhere else.",
  },
}


def notice_for(request: Request) -> dict[str, str] | None:
  """Return the banner for this request's ``?notice=`` code, if any.

  Parameters
  ----------
  request : Request
    The inbound request.

  Returns
  -------
  dict[str, str] | None
    ``{"kind": …, "text": …}`` for an allowlisted code, ``None`` for an
    absent, unknown, malformed or repeated one.

  Notes
  -----
  A repeated ``?notice=a&notice=b`` renders nothing rather than picking
  one: two codes is not a state this application produces, so it is a
  crafted request and the honest answer is no banner.
  """
  values = request.query_params.getlist("notice")
  if len(values) != 1:
    return None
  entry = NOTICE_CODES.get(values[0])
  return dict(entry) if entry is not None else None


def csrf_token_for_request(request: Request) -> str:
  """Return the CSRF token for whatever session this request presents.

  Parameters
  ----------
  request : Request
    The inbound request.

  Returns
  -------
  str
    The derived token, or the empty string when no cookie was presented.
    Derivation is pure (:mod:`app.security.csrf`), so an error page can
    render a working form without touching the database.
  """
  token = request.cookies.get(COOKIE_NAME)
  if not token:
    return ""
  csrf_token, _digest = csrf_for_token(token)
  return csrf_token


def base_context(
  *,
  page_title: str,
  principal: Principal | None = None,
  csrf_token: str = "",
  private: bool = False,
  nav_active: str | None = None,
  announce: str | None = None,
  scope_label: str | None = None,
  notice: dict[str, str] | None = None,
) -> dict[str, Any]:
  """Build the frozen base context every template starts from.

  Parameters
  ----------
  page_title : str
    The ``<title>`` prefix.
  principal : Principal | None
    ``None`` selects the public shell; a principal whose
    ``must_change_password`` is set selects the reduced forced-reset nav.
    The ``500``, ``503`` and step-0 ``403`` handlers pass ``None``
    unconditionally (**R32**, ``ACC-010``).
  csrf_token : str
    Rendered into the navigation's sign-out form and into any page form.
  private : bool
    Adds ``hx-history="false"`` to ``<body>`` so htmx never restores the
    page from its history cache (``SEC-024``).
  nav_active : str | None
    Which destination carries ``aria-current="page"``.
  announce : str | None
    Text for the polite live region.
  scope_label : str | None
    ``CP-30``/``CP-31``; unused until a list exists.
  notice : dict[str, str] | None
    The banner from :func:`notice_for`.

  Returns
  -------
  dict[str, Any]
    Exactly the nine keys ``CONTRACTS.md`` §8.1 freezes — always all nine,
    because ``StrictUndefined`` makes a missing one a failure rather than
    a blank.
  """
  return {
    "app_name": APP_NAME,
    "page_title": page_title,
    "principal": principal,
    "csrf_token": csrf_token,
    "private": private,
    "nav_active": nav_active,
    "announce": announce,
    "scope_label": scope_label,
    "notice": notice,
  }


def render(
  request: Request,
  template: str,
  context: dict[str, Any],
  *,
  status_code: int = 200,
  headers: dict[str, str] | None = None,
) -> Response:
  """Render ``template`` with ``context``.

  Parameters
  ----------
  request : Request
    The inbound request, which Starlette puts into the template context.
  template : str
    A path under ``app/templates``.
  context : dict[str, Any]
    The full context, base keys included.
  status_code : int, optional
    The response status.
  headers : dict[str, str] | None, optional
    Extra response headers, such as ``Retry-After``.

  Returns
  -------
  Response
    An ``text/html`` response. Security headers are added by the
    middleware on the way out, or by the error renderer for a response
    built outside it.
  """
  return TEMPLATES.TemplateResponse(
    request, template, context, status_code=status_code, headers=headers
  )
