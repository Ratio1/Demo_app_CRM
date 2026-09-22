r"""One JSON object per request on stdout, and nothing else.

The record carries exactly these keys and no others::

    ts level event method path status duration_ms correlation_id actor_id

What is *absent* is the point of the module. No request body, no cookie, no
header value, no SQL text, no traceback, no password, no identifier a user
typed and **no query string** — ``path`` is ``request.url.path``, which
stops at the ``?``. That is why ``scripts/start`` and ``scripts/dev-run.sh``
pass ``--no-access-log``: uvicorn's own access line logs the full target,
query string included, and would reintroduce the leak this module exists to
close.

Values are serialized with :func:`json.dumps`, so a control character in
any value — a ``\\r\\n`` pasted into an email field — is escaped inside the
JSON string rather than starting a line. A forged log record is therefore
not expressible from request data, and in any case no
request-supplied value reaches a record at all.

The one handler writes to a stream, never to a file: a container's log is
its stdout, and a file handler would put personal data on a disk nobody
rotates.
"""

from __future__ import annotations

import json
import logging
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
  from typing import TextIO

__all__ = [
  "LOGGER_NAME",
  "RECORD_KEYS",
  "JsonLinesFormatter",
  "configure_logging",
  "current_correlation_id",
  "log_request",
  "log_unhandled",
  "new_correlation_id",
  "set_correlation_id",
]

LOGGER_NAME: Final = "app"

#: The whole vocabulary, in the order it is emitted.
RECORD_KEYS: Final[tuple[str, ...]] = (
  "ts",
  "level",
  "event",
  "method",
  "path",
  "status",
  "duration_ms",
  "correlation_id",
  "actor_id",
)

_PAYLOAD_ATTRIBUTE: Final = "crm_payload"

#: The current request's correlation id. Set by ``CorrelationMiddleware`` at
#: the very top of the stack, so every log line, every error page and every
#: audit row written while handling one request carry the same value and a
#: reviewer can join the three.
_CORRELATION_ID: ContextVar[str] = ContextVar("crm_correlation_id", default="")


def new_correlation_id() -> str:
  """Mint a correlation id.

  Returns
  -------
  str
    A canonical lowercase 36-character UUIDv4 string — ``str(uuid.uuid4())``,
    hyphenated.

  Notes
  -----
  The form is not cosmetic: ``ck_audit_events_correlation`` requires
  ``char_length(correlation_id) = 36``, so a 32-character hex digest would
  make every audit INSERT fail ``23514``. It is also the same shape as every
  other identifier in the schema, which is what lets one value be grepped
  across the log stream, an error page and the audit trail.
  """
  return str(uuid.uuid4())


def set_correlation_id(correlation_id: str) -> None:
  """Bind ``correlation_id`` to the current context.

  Parameters
  ----------
  correlation_id : str
    The value minted for this request.
  """
  _CORRELATION_ID.set(correlation_id)


def current_correlation_id() -> str:
  """Return the current request's correlation id.

  Returns
  -------
  str
    The bound value, or a freshly minted one when nothing is bound — which
    happens only outside a request (a CLI command, a test importing a
    renderer directly). An error page never renders an empty reference.
  """
  return _CORRELATION_ID.get() or new_correlation_id()


class JsonLinesFormatter(logging.Formatter):
  """Render a record as one JSON object holding exactly :data:`RECORD_KEYS`."""

  def format(self, record: logging.LogRecord) -> str:
    """Return the record as a single JSON line.

    Parameters
    ----------
    record : logging.LogRecord
      A record carrying this module's payload, or any other record that
      reached the root logger.

    Returns
    -------
    str
      A JSON object with the nine contracted keys and no others.

    Notes
    -----
    A record from somewhere else — a library that logs to the root logger —
    is emitted with the same nine keys and null values rather than with its
    message. Dropping it silently would hide that something logged;
    printing its message would let an arbitrary third-party string into a
    stream this application promises to keep free of values.
    """
    payload: dict[str, Any] = dict(getattr(record, _PAYLOAD_ATTRIBUTE, {}) or {})
    emitted = {
      "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
      "level": record.levelname.lower(),
      "event": payload.get("event", "log"),
      "method": payload.get("method"),
      "path": payload.get("path"),
      "status": payload.get("status"),
      "duration_ms": payload.get("duration_ms"),
      "correlation_id": payload.get("correlation_id", ""),
      "actor_id": payload.get("actor_id"),
    }
    return json.dumps(emitted, separators=(",", ":"), ensure_ascii=False)


def configure_logging(stream: TextIO) -> None:
  """Install the one JSON-lines handler on the root logger.

  Parameters
  ----------
  stream : TextIO
    Where records go — ``sys.stdout`` in the served application. Never a
    file: there is no file handler anywhere in this application.

  Notes
  -----
  Existing root handlers are removed first, so a second call (a test, a
  reload) cannot double every line. uvicorn's own loggers do not propagate
  to the root logger, so its startup lines keep their own format and this
  handler only ever sees application records.
  """
  root = logging.getLogger()
  for existing in list(root.handlers):
    root.removeHandler(existing)
  handler = logging.StreamHandler(stream)
  handler.setFormatter(JsonLinesFormatter())
  root.addHandler(handler)
  root.setLevel(logging.INFO)


def log_request(
  *,
  method: str,
  path: str,
  status: int,
  duration_ms: float,
  correlation_id: str,
  actor_id: str | None,
) -> None:
  """Emit the one record for a completed request.

  Parameters
  ----------
  method : str
    The HTTP method.
  path : str
    ``request.url.path`` — **never** the query string.
  status : int
    The status actually sent.
  duration_ms : float
    Wall time for the request, rounded to three decimals.
  correlation_id : str
    The id of :func:`new_correlation_id`.
  actor_id : str | None
    The authenticated user's id, or ``None`` for an anonymous request. An
    identifier, never an email address or a display name.
  """
  logging.getLogger(LOGGER_NAME).info(
    "",
    extra={
      _PAYLOAD_ATTRIBUTE: {
        "event": "request",
        "method": method,
        "path": path,
        "status": status,
        "duration_ms": round(duration_ms, 3),
        "correlation_id": correlation_id,
        "actor_id": actor_id,
      }
    },
  )


def log_unhandled(
  *,
  method: str,
  path: str,
  duration_ms: float,
  correlation_id: str,
  exception_class: str,
) -> None:
  """Emit the record for a request that ended in an unhandled exception.

  Parameters
  ----------
  method : str
    The HTTP method.
  path : str
    ``request.url.path``.
  duration_ms : float
    Wall time until the failure.
  correlation_id : str
    The id shown on the ``500`` page the user receives.
  exception_class : str
    The exception's **class name only**. Never ``str(exception)``, which
    for a database error is the server's message and can name a value, and
    never a traceback, which names file paths and locals.

  Notes
  -----
  The class name is carried in ``event`` as ``unhandled:<ClassName>`` so the
  record still holds exactly the nine contracted keys.
  """
  logging.getLogger(LOGGER_NAME).error(
    "",
    extra={
      _PAYLOAD_ATTRIBUTE: {
        "event": f"unhandled:{exception_class}",
        "method": method,
        "path": path,
        "status": 500,
        "duration_ms": round(duration_ms, 3),
        "correlation_id": correlation_id,
        "actor_id": None,
      }
    },
  )
