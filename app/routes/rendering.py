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

*Two filters, registered once* (``contracts/slice-c.md`` §2(a)). ``eur``
and ``day`` are the only entries in the environment's filter table, so a
template can render ``€ 12,345.00`` and ``21 Sep 2026`` without reaching
for a platform-dependent ``strftime("%-d")`` or building a money string by
hand. Filters are not context keys, so ``CONTRACTS.md`` §8 is untouched by
their existence; ``eur`` refuses anything that is not a
:class:`decimal.Decimal` (``ARC-021``'s runtime half).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Final

import jinja2
from fastapi.templating import Jinja2Templates

from app.security.csrf import csrf_for_token
from app.security.sessions import COOKIE_NAME
from app.services.money import format_day, format_eur

if TYPE_CHECKING:
  from collections.abc import Mapping
  from pathlib import Path

  from starlette.requests import Request
  from starlette.responses import Response

  from app.security.principal import Principal

__all__ = [
  "APP_NAME",
  "NOTICE_CODES",
  "TEMPLATES",
  "TEMPLATES_DIR",
  "View",
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


def _environment() -> jinja2.Environment:
  """Build the one Jinja environment, with its two filters already on it.

  Returns
  -------
  jinja2.Environment
    The explicit environment of delta **D11**, carrying ``eur`` and ``day``
    (``contracts/slice-c.md`` §2(a)). Registering them here rather than at
    first use is what makes the filter table a property of the module: a
    template that renders money can never reach a differently-configured
    environment, and an error page built outside the application still has
    both filters.
  """
  environment = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,
    undefined=jinja2.StrictUndefined,
    auto_reload=False,
  )
  environment.filters["eur"] = format_eur
  environment.filters["day"] = format_day
  return environment


TEMPLATES: Final = Jinja2Templates(env=_environment())

#: Slice A's three codes (``slice-a.md`` §2.7), Slice B's five and Slice
#: C's five (``CONTRACTS.md`` §8.5, ``UX_FLOWS.md`` §6.6). Later slices
#: extend this table additively; nothing else may render a banner.
NOTICE_CODES: Final[dict[str, dict[str, str]]] = {
  "signed_out": {"kind": "success", "text": "You are signed out."},
  "session_ended": {"kind": "info", "text": "Your session ended. Sign in to continue."},
  "password_changed": {
    "kind": "success",
    "text": "Password changed. You have been signed out everywhere else.",
  },
  "contact_created": {"kind": "success", "text": "Contact created."},
  "contact_saved": {"kind": "success", "text": "Contact saved."},
  "contact_archived": {"kind": "success", "text": "Contact archived."},
  "contact_restored": {"kind": "success", "text": "Contact restored."},
  "owner_changed": {"kind": "success", "text": "Owner changed to {name}."},
  "deal_created": {"kind": "success", "text": "Deal created."},
  "deal_saved": {"kind": "success", "text": "Deal saved."},
  "deal_won": {"kind": "success", "text": "Deal marked won."},
  "deal_lost": {"kind": "success", "text": "Deal marked lost."},
  "deal_moved": {"kind": "success", "text": "Deal moved to {stage}."},
}

#: The one substitution shape a notice string may carry. ``CP-57``'s
#: ``{name}`` is the second of the fourteen (``CONTRACTS.md`` §8.5 and
#: ``UX_FLOWS.md`` §6.6 both say *"``deal_moved``'s ``{stage}`` is the
#: only substitution"*, which is false — finding **F-2**). The value is
#: supplied by the **destination handler** from a re-read row, never from
#: the query string: no free text travels in a URL (**R20**).
_NOTICE_PLACEHOLDER: Final = re.compile(r"\{([a-z_]+)\}")


class View:
  """A context sub-object whose keys are read as attributes, not as items.

  Jinja resolves ``a.b`` by trying :func:`getattr` **first** and only then
  ``a["b"]``, so a plain :class:`dict` hands a template its own method for
  any key that shares a name with one: ``results.items``,
  ``timeline.items``, ``activity_form.values`` and
  ``stale.keep_form.values`` are all frozen context keys
  (``CONTRACTS.md`` §8.3/§8.2/§8.4) that collide exactly that way. Wrapping
  those four in this class is what makes them resolve to their values — and
  it is also what §8's rule 1 asks for, *"every context value is a view
  model or a primitive"*.

  ``__slots__`` carries the data under one private name, so **every** other
  attribute falls through to :meth:`__getattr__` and no key can ever be
  shadowed by something inherited from :class:`object`. Item access is kept
  as well, so a template may spell either.

  A sub-context a template calls a real mapping method on — ``errors``,
  which every form reads with ``.get(...)`` and the error summary iterates
  with ``.items()`` — stays a plain :class:`dict` and must not be wrapped.
  """

  __slots__ = ("_data",)

  def __init__(self, **data: Any) -> None:
    """Store this view's keys.

    Parameters
    ----------
    **data : Any
      The context keys, exactly as the frozen inventory names them.
    """
    object.__setattr__(self, "_data", data)

  def __getattr__(self, name: str) -> Any:
    """Return one key as an attribute, or raise :class:`AttributeError`."""
    try:
      return self._data[name]
    except KeyError:
      raise AttributeError(name) from None

  def __getitem__(self, key: str) -> Any:
    """Return one key as an item, for a template that spells it that way."""
    return self._data[key]

  def __repr__(self) -> str:
    """Return a debug representation naming the keys but not the values."""
    return f"View({', '.join(sorted(self._data))})"


def notice_for(
  request: Request, *, substitutions: Mapping[str, str] | None = None
) -> dict[str, str] | None:
  """Return the banner for this request's ``?notice=`` code, if any.

  Parameters
  ----------
  request : Request
    The inbound request.
  substitutions : Mapping[str, str] | None, optional
    Server-side values for a code whose copy carries a placeholder, such as
    ``owner_changed``'s ``{name}``. Supplied by the handler from a row it
    has just read.

  Returns
  -------
  dict[str, str] | None
    ``{"kind": …, "text": …}`` for an allowlisted code, ``None`` for an
    absent, unknown, malformed or repeated one — and ``None`` for a code
    whose placeholder this caller cannot fill, so a crafted
    ``?notice=owner_changed`` on a page that knows no owner renders no
    banner rather than a literal ``{name}``.

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
  if entry is None:
    return None
  banner = dict(entry)
  needed = set(_NOTICE_PLACEHOLDER.findall(banner["text"]))
  if needed:
    supplied = dict(substitutions or {})
    if not needed <= supplied.keys():
      return None
    banner["text"] = _NOTICE_PLACEHOLDER.sub(lambda match: supplied[match.group(1)], banner["text"])
  return banner


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
