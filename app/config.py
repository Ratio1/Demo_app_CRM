"""The only module in ``app`` that reads the process environment.

Spec §4 allows exactly four operator-supplied variables, with the port carried
inside ``DB_SERVER``; decision D-K adds an optional ``DB_PORT`` defaulting to
5432, so that a file written by ``_tools/pgsql/pg env`` — which emits the four
names and no ``DB_PORT`` — works unchanged while a container environment may
still set the port separately. If both carry a port and they disagree, startup
fails rather than silently preferring one.

Everything else is a code constant. There is no ``DATABASE_URL``, no signing
secret, no ``APP_URL`` and no ``PORT``: the public HTTPS origin lives in the
database, and the TLS trust anchor is the build-time bundle named by
:data:`CA_BUNDLE_PATH`.

The environment is read inside :func:`load_config` and never at import time.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
  "CA_BUNDLE_PATH",
  "CLIENT_ENCODING",
  "CONNECT_TIMEOUT_S",
  "DEFAULT_DB_PORT",
  "ENV_NAMES",
  "GSSENCMODE",
  "SSLMODE",
  "SSL_MIN_PROTOCOL_VERSION",
  "Config",
  "ConfigError",
  "load_config",
]

DEFAULT_DB_PORT: int = 5432

#: Resolved from this package's own location (delta **D2**), not from the
#: working directory: ``scripts/manage``, a ``python -c`` probe and a test
#: subprocess do not all run from the submodule root, and a cwd-relative
#: bundle silently becomes "no trust anchor" — which ``sslmode=verify-full``
#: then reports as a connection failure rather than as a misconfiguration.
#: Kept a ``str`` because it is handed straight to libpq.
CA_BUNDLE_PATH: str = str(Path(__file__).resolve().parent / "certs" / "ca-bundle.pem")

CONNECT_TIMEOUT_S: int = 5

#: The four TLS/encoding constants of delta **D1** (ruling **R34**). Each is a
#: code constant; none is an environment variable, and none may be relaxed
#: without a contract step. ``R2``'s spelling ``sslminprotocolversion`` is
#: invalid — libpq rejects it outright — and ``R34`` corrects it to the
#: spelling below.
SSLMODE: str = "verify-full"
SSL_MIN_PROTOCOL_VERSION: str = "TLSv1.2"
GSSENCMODE: str = "disable"
CLIENT_ENCODING: str = "UTF8"
ENV_NAMES: tuple[str, ...] = ("DB_SERVER", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME")

_REQUIRED_NAMES: tuple[str, ...] = ("DB_SERVER", "DB_USER", "DB_PASSWORD", "DB_NAME")
_ASCII_DIGITS = frozenset("0123456789")
_MAX_PORT_DIGITS = 5
_MIN_PORT = 1
_MAX_PORT = 65535
# Spec §4: "No URL/query/TLS options." A host is a name or an IP literal.
# The comma is in the set because libpq reads `host=a,b` as a multi-host
# failover list, which is another way to reach a server the operator did not
# name; spec §4 says `host[:port]`, singular.
_FORBIDDEN_HOST_CHARS = frozenset("/?#@=,\\'\"[]")


class ConfigError(ValueError):
  """Raised when the five-name environment contract is not satisfied.

  The message names the offending variable and the class of fault only; it
  never contains a value, so it is safe to log and to surface as a sanitized
  error. That includes the port-disagreement case: the message says the two
  names disagree without repeating either number.
  """


@dataclass(frozen=True, slots=True)
class Config:
  """Immutable database configuration built from exactly five variable names.

  Attributes
  ----------
  host : str
    Hostname or IP literal; brackets stripped from an IPv6 literal.
  port : int
    TCP port, 1-65535.
  user : str
    Database role name.
  password : str
    Excluded from ``repr`` and therefore from ``str``. ``dataclasses.asdict``
    and ``astuple`` WOULD expose it: never call them on a ``Config``.
    ``connect_kwargs`` is the only sanctioned exporter.
  dbname : str
    Existing, dedicated application database.
  """

  host: str
  port: int
  user: str
  password: str = field(repr=False)
  dbname: str

  def connect_kwargs(self) -> dict[str, object]:
    """Return the explicit libpq parameters used for every connection.

    Returns
    -------
    dict[str, object]
      Delta **D1**'s twelve keys, exactly: ``host``, ``port``, ``user``,
      ``password``, ``dbname``, ``sslmode="verify-full"``,
      ``sslrootcert=CA_BUNDLE_PATH``, ``connect_timeout=CONNECT_TIMEOUT_S``,
      ``options=""``, ``ssl_min_protocol_version="TLSv1.2"``,
      ``gssencmode="disable"`` and ``client_encoding="UTF8"``.

    Notes
    -----
    Every parameter is passed explicitly so libpq never falls back to
    ``PGSERVICE``, ``PGSERVICEFILE``, ``PGSSLMODE``, ``PGSSLROOTCERT``,
    ``PGHOST``, ``PGPASSFILE`` or ``PGOPTIONS``. No key is added without a
    contract step. ``statement_timeout`` is applied by the pool's configure
    hook, not here, because ``options`` must stay empty.

    The last three are delta **D1** / ruling **R34**, each closing a
    downgrade an explicit value would otherwise leave open: a TLS floor
    below 1.2, a GSSAPI encryption negotiation this deployment never wants,
    and a client encoding libpq would otherwise take from the environment's
    locale. ``sslrootcert`` is resolved from the package (delta **D2**), so
    the trust anchor does not depend on the working directory.
    """
    return {
      "host": self.host,
      "port": self.port,
      "user": self.user,
      "password": self.password,
      "dbname": self.dbname,
      "sslmode": SSLMODE,
      "sslrootcert": CA_BUNDLE_PATH,
      "connect_timeout": CONNECT_TIMEOUT_S,
      "options": "",
      "ssl_min_protocol_version": SSL_MIN_PROTOCOL_VERSION,
      "gssencmode": GSSENCMODE,
      "client_encoding": CLIENT_ENCODING,
    }


def _require(source: Mapping[str, str], name: str) -> str:
  """Return a non-empty value for ``name`` or raise :class:`ConfigError`.

  Parameters
  ----------
  source : Mapping[str, str]
    The environment mapping being read.
  name : str
    The variable name.

  Returns
  -------
  str
    The value exactly as supplied; never stripped, so a password is preserved
    byte for byte.

  Raises
  ------
  ConfigError
    If the name is absent or its value is the empty string.
  """
  value = source.get(name)
  if value is None:
    raise ConfigError(f"{name} is not set")
  if not value:
    raise ConfigError(f"{name} is empty")
  return value


def _parse_port(text: str, *, origin: str) -> int:
  """Parse a decimal TCP port, rejecting every non-canonical spelling.

  Parameters
  ----------
  text : str
    Candidate port text.
  origin : str
    The variable the text came from, used in the error message only.

  Returns
  -------
  int
    The port, 1-65535.

  Raises
  ------
  ConfigError
    If the text is not ASCII decimal digits, is not in canonical form, or is
    out of range. ``int`` alone would accept ``+5432``, ``" 5432"``, ``5_432``
    and non-ASCII digits such as ``٥٤٣٢``, so the character set is checked
    first; a leading zero is then rejected so that one port has exactly one
    spelling and two values can be compared as written.
  """
  if not text or not all(character in _ASCII_DIGITS for character in text):
    raise ConfigError(f"{origin} port is not a decimal number")
  if len(text) > _MAX_PORT_DIGITS:
    raise ConfigError(f"{origin} port is out of the range 1-65535")
  port = int(text)
  if str(port) != text:
    raise ConfigError(f"{origin} port is not in canonical form")
  if not _MIN_PORT <= port <= _MAX_PORT:
    raise ConfigError(f"{origin} port is out of the range 1-65535")
  return port


def _split_server(raw: str) -> tuple[str, str | None]:
  """Split ``DB_SERVER`` into a host and an optional port text.

  Parameters
  ----------
  raw : str
    The raw ``DB_SERVER`` value: ``host``, ``host:port``, ``[v6]`` or
    ``[v6]:port``.

  Returns
  -------
  tuple[str, str | None]
    The host with any IPv6 brackets removed, and the port text if one was
    supplied.

  Raises
  ------
  ConfigError
    If the value is unparsable: an unterminated or empty bracket, trailing
    characters after ``]``, an empty host or port, an unbracketed value with
    more than one ``:`` (an IPv6 address that must be bracketed), or any URL,
    query or option syntax, which spec §4 forbids.
  """
  if raw.startswith("["):
    closing = raw.find("]")
    if closing < 0:
      raise ConfigError("DB_SERVER has an unterminated IPv6 bracket")
    host = raw[1:closing]
    remainder = raw[closing + 1 :]
    if not remainder:
      return _checked_host(host), None
    if not remainder.startswith(":"):
      raise ConfigError("DB_SERVER has trailing characters after the IPv6 literal")
    port_text = remainder[1:]
    if not port_text:
      raise ConfigError("DB_SERVER has an empty port")
    return _checked_host(host), port_text

  colons = raw.count(":")
  if colons == 0:
    return _checked_host(raw), None
  if colons > 1:
    raise ConfigError("DB_SERVER is ambiguous: an IPv6 address must be bracketed")
  host, _, port_text = raw.partition(":")
  if not port_text:
    raise ConfigError("DB_SERVER has an empty port")
  return _checked_host(host), port_text


def _checked_host(host: str) -> str:
  """Validate the host part of ``DB_SERVER``.

  Parameters
  ----------
  host : str
    Host text with any IPv6 brackets already removed.

  Returns
  -------
  str
    The same host.

  Raises
  ------
  ConfigError
    If the host is empty, contains whitespace, or contains a character that
    belongs to URL, query or connection-option syntax rather than to a
    hostname or an IP literal.
  """
  if not host:
    raise ConfigError("DB_SERVER has an empty host")
  if any(character.isspace() for character in host):
    raise ConfigError("DB_SERVER host contains whitespace")
  if any(character in _FORBIDDEN_HOST_CHARS for character in host):
    raise ConfigError("DB_SERVER must be host[:port] with no URL or option syntax")
  return host


def load_config(environ: Mapping[str, str] | None = None) -> Config:
  """Build a :class:`Config` from a mapping, defaulting to ``os.environ``.

  Parameters
  ----------
  environ : Mapping[str, str] | None
    Source mapping. ``None`` means ``os.environ`` **resolved inside this call**,
    so importing this module never reads the environment.

  Returns
  -------
  Config

  Raises
  ------
  ConfigError
    If ``DB_SERVER``, ``DB_USER``, ``DB_PASSWORD`` or ``DB_NAME`` is missing or
    empty; if ``DB_SERVER`` is unparsable; if a port is not 1-65535 decimal
    digits; or if ``DB_SERVER`` and ``DB_PORT`` both carry a port and disagree.

  Notes
  -----
  ``DB_SERVER`` accepts ``host``, ``host:port``, ``[2001:db8::1]`` and
  ``[2001:db8::1]:26257``. An unbracketed value containing more than one ``:``
  is a ``ConfigError`` (ambiguous). ``DB_PORT`` is optional: absent **or empty**
  means ``DEFAULT_DB_PORT`` unless ``DB_SERVER`` carries a port; identical
  values agree and are not an error. No other environment name is read anywhere
  in ``app/``, and a test asserts exactly ``ENV_NAMES``.
  """
  source: Mapping[str, str] = os.environ if environ is None else environ

  server = _require(source, "DB_SERVER")
  user = _require(source, "DB_USER")
  password = _require(source, "DB_PASSWORD")
  dbname = _require(source, "DB_NAME")

  host, server_port_text = _split_server(server)
  server_port = (
    None if server_port_text is None else _parse_port(server_port_text, origin="DB_SERVER")
  )

  explicit_port = source.get("DB_PORT")
  env_port = (
    _parse_port(explicit_port, origin="DB_PORT")
    if explicit_port is not None and explicit_port != ""
    else None
  )

  if server_port is not None and env_port is not None and server_port != env_port:
    raise ConfigError("DB_SERVER and DB_PORT disagree on the port")

  port = server_port if server_port is not None else env_port
  if port is None:
    port = DEFAULT_DB_PORT

  return Config(host=host, port=port, user=user, password=password, dbname=dbname)
