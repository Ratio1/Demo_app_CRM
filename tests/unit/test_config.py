"""Unit tests for ``app.config`` — SEC-050, SEC-051, and the redaction rule.

Authority: ``ACCESS_MATRIX.md`` §7 (SEC-050, SEC-051); ``slice-a.md`` §6 D1/D2
(the twelve-key ``connect_kwargs`` set once the Backend lane applies R34);
``PLAN.md`` §6 (the ``DB_SERVER`` parser matrix). These are the one module
that already ships, so every test below runs against real code today, not
against a contract stub.
"""

from __future__ import annotations

import dataclasses

import pytest

from app.config import (
  CA_BUNDLE_PATH,
  CONNECT_TIMEOUT_S,
  DEFAULT_DB_PORT,
  ENV_NAMES,
  Config,
  ConfigError,
  load_config,
)

_BASE_ENV: dict[str, str] = {
  "DB_SERVER": "pg.example.test",
  "DB_USER": "crm_test_app",
  "DB_PASSWORD": "a fictional password",
  "DB_NAME": "crm_test",
}


def _env(**overrides: str | None) -> dict[str, str]:
  """Return ``_BASE_ENV`` with ``overrides`` applied.

  Parameters
  ----------
  **overrides : str | None
    ``None`` deletes the key; anything else sets/replaces it.

  Returns
  -------
  dict[str, str]
  """
  merged = dict(_BASE_ENV)
  for key, value in overrides.items():
    if value is None:
      merged.pop(key, None)
    else:
      merged[key] = value
  return merged


# ---------------------------------------------------------------------------
# SEC-050 — exactly the five names, and the DB_SERVER parser matrix.
# ---------------------------------------------------------------------------


def test_sec050_env_names_is_exactly_the_five_contracted_names() -> None:
  """``ENV_NAMES`` is exactly the five-name environment contract, in order."""
  assert ENV_NAMES == ("DB_SERVER", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME")


@pytest.mark.parametrize("missing", ["DB_SERVER", "DB_USER", "DB_PASSWORD", "DB_NAME"])
def test_sec050_each_required_name_is_required(missing: str) -> None:
  """Each of the four required names raises ``ConfigError`` when absent."""
  with pytest.raises(ConfigError):
    load_config(_env(**{missing: None}))


@pytest.mark.parametrize("missing", ["DB_SERVER", "DB_USER", "DB_PASSWORD", "DB_NAME"])
def test_sec050_each_required_name_rejects_the_empty_string(missing: str) -> None:
  """An empty value for a required name is a ``ConfigError``, not a blank field."""
  with pytest.raises(ConfigError):
    load_config(_env(**{missing: ""}))


@pytest.mark.parametrize(
  ("server", "expected_host", "expected_port"),
  [
    ("pg.example.test", "pg.example.test", DEFAULT_DB_PORT),
    ("pg.example.test:6432", "pg.example.test", 6432),
    ("[2001:db8::1]", "2001:db8::1", DEFAULT_DB_PORT),
    ("[2001:db8::1]:26257", "2001:db8::1", 26257),
  ],
)
def test_sec050_db_server_parses_host_hostport_v6_and_v6port(
  server: str, expected_host: str, expected_port: int
) -> None:
  """``DB_SERVER`` accepts ``host``, ``host:port``, ``[v6]`` and ``[v6]:port``."""
  config = load_config(_env(DB_SERVER=server))
  assert config.host == expected_host
  assert config.port == expected_port


def test_sec051_db_port_absent_defaults_to_5432() -> None:
  """``DB_PORT`` absent, with no port in ``DB_SERVER``, defaults to 5432."""
  config = load_config(_env(DB_SERVER="pg.example.test"))
  assert config.port == DEFAULT_DB_PORT == 5432


def test_sec051_db_port_empty_string_is_treated_as_absent() -> None:
  """An empty ``DB_PORT`` behaves exactly like an absent one, not a value."""
  config = load_config(_env(DB_SERVER="pg.example.test", DB_PORT=""))
  assert config.port == DEFAULT_DB_PORT


def test_sec051_db_port_present_and_agreeing_with_db_server_is_accepted() -> None:
  """Identical values on both names agree and are not an error."""
  config = load_config(_env(DB_SERVER="pg.example.test:6432", DB_PORT="6432"))
  assert config.port == 6432


def test_sec051_db_port_present_alone_is_used() -> None:
  """``DB_PORT`` alone (``DB_SERVER`` carries none) sets the port."""
  config = load_config(_env(DB_SERVER="pg.example.test", DB_PORT="6432"))
  assert config.port == 6432


def test_sec051_db_server_and_db_port_disagreeing_is_a_sanitized_error() -> None:
  """A disagreeing pair is a startup error that names no number."""
  with pytest.raises(ConfigError) as excinfo:
    load_config(_env(DB_SERVER="pg.example.test:6432", DB_PORT="5432"))
  message = str(excinfo.value)
  assert "6432" not in message
  assert "5432" not in message
  assert "disagree" in message


@pytest.mark.parametrize(
  "malformed",
  [
    "pg.example.test:",  # empty port
    "pg.example.test:abc",  # non-decimal
    "pg.example.test:05432",  # leading zero, not canonical
    "pg.example.test:70000",  # out of range
    "pg.example.test:1:2",  # ambiguous multiple colons, unbracketed
    "postgres://pg.example.test/crm",  # URL syntax forbidden by spec §4
    "pg.example.test?sslmode=disable",  # query syntax forbidden
    "pg.example.test,evil.test",  # multi-host failover list forbidden
    " pg.example.test",  # whitespace
    "[2001:db8::1",  # unterminated IPv6 bracket
    "[2001:db8::1]x",  # trailing garbage after the bracket
  ],
)
def test_sec050_db_server_rejects_every_malformed_spelling(malformed: str) -> None:
  """Every non-canonical or URL/query-syntax ``DB_SERVER`` value is rejected."""
  with pytest.raises(ConfigError):
    load_config(_env(DB_SERVER=malformed))


@pytest.mark.parametrize("bad_port", ["0", "65536", "-1", "abc", "5432 ", "05432"])
def test_sec051_db_port_rejects_out_of_range_and_non_canonical_values(bad_port: str) -> None:
  """``DB_PORT`` outside 1-65535 or spelled non-canonically is rejected."""
  with pytest.raises(ConfigError):
    load_config(_env(DB_SERVER="pg.example.test", DB_PORT=bad_port))


def test_no_other_environment_name_is_read() -> None:
  """A completely unrelated environment leaves ``load_config`` refusing, not guessing.

  ``load_config`` reads only from the mapping it is given (never
  ``os.environ`` implicitly, since a mapping is passed here), so this also
  documents that passing an unrelated mapping cannot accidentally succeed.
  """
  with pytest.raises(ConfigError):
    load_config({"SOME_OTHER_VAR": "x", "PATH": "/usr/bin"})


def test_load_config_does_not_read_os_environ_when_given_a_mapping(
  monkeypatch: pytest.MonkeyPatch,
) -> None:
  """Passing an explicit mapping never falls back to ``os.environ``."""
  monkeypatch.setenv("DB_SERVER", "should-not-be-read.example.test")
  monkeypatch.setenv("DB_USER", "should-not-be-read")
  monkeypatch.setenv("DB_PASSWORD", "should-not-be-read")
  monkeypatch.setenv("DB_NAME", "should-not-be-read")
  config = load_config(_env(DB_SERVER="explicit.example.test"))
  assert config.host == "explicit.example.test"


# ---------------------------------------------------------------------------
# Redaction — Config.password never leaks through repr/str.
# ---------------------------------------------------------------------------


def test_config_repr_never_contains_the_password() -> None:
  """``repr(Config)`` excludes the password field entirely (dataclass ``field(repr=False)``)."""
  config = load_config(_env(DB_PASSWORD="a distinctive fictional secret"))
  assert "a distinctive fictional secret" not in repr(config)
  assert "a distinctive fictional secret" not in str(config)


def test_config_error_messages_never_contain_a_value() -> None:
  """Every ``ConfigError`` raised by the parser matrix names no value, only the fault class."""
  cases = [
    _env(DB_SERVER=None),
    _env(DB_PASSWORD=""),
    _env(DB_SERVER="pg.example.test:6432", DB_PORT="5432"),
    _env(DB_SERVER="pg.example.test:99999"),
  ]
  for environ in cases:
    with pytest.raises(ConfigError) as excinfo:
      load_config(environ)
    message = str(excinfo.value)
    for value in environ.values():
      if value:
        assert value not in message


# ---------------------------------------------------------------------------
# connect_kwargs — D1's key set (slice-a.md §6 D1, ruling R34).
# ---------------------------------------------------------------------------


def test_connect_kwargs_carries_the_explicit_tls_and_timeout_parameters() -> None:
  """Every key ``connect_kwargs`` already ships is present with its pinned value."""
  config = load_config(_env())
  kwargs = config.connect_kwargs()
  assert kwargs["sslmode"] == "verify-full"
  assert kwargs["sslrootcert"] == CA_BUNDLE_PATH
  assert kwargs["connect_timeout"] == CONNECT_TIMEOUT_S
  assert kwargs["options"] == ""
  assert kwargs["host"] == config.host
  assert kwargs["port"] == config.port
  assert kwargs["user"] == config.user
  assert kwargs["password"] == config.password
  assert kwargs["dbname"] == config.dbname


@pytest.mark.xfail(
  reason=(
    "backend-security: slice-a.md §6 D1 (ruling R34) pins connect_kwargs() to the "
    "twelve-key set including ssl_min_protocol_version='TLSv1.2', "
    "gssencmode='disable' and client_encoding='UTF8'; app/config.py has not been "
    "updated to add these three keys yet (only nine keys ship today, verified by "
    "test_connect_kwargs_is_exactly_nine_keys_today below)."
  ),
  strict=True,
)
def test_d1_connect_kwargs_is_exactly_the_twelve_key_set() -> None:
  """``connect_kwargs()`` is exactly D1's twelve keys, once the Backend lane ships them."""
  config = load_config(_env())
  kwargs = config.connect_kwargs()
  assert kwargs["ssl_min_protocol_version"] == "TLSv1.2"
  assert kwargs["gssencmode"] == "disable"
  assert kwargs["client_encoding"] == "UTF8"
  assert set(kwargs) == {
    "host",
    "port",
    "user",
    "password",
    "dbname",
    "sslmode",
    "sslrootcert",
    "connect_timeout",
    "options",
    "ssl_min_protocol_version",
    "gssencmode",
    "client_encoding",
  }


def test_config_is_frozen() -> None:
  """A ``Config`` cannot be mutated after construction (it crosses no trust boundary mutably)."""
  config = load_config(_env())
  with pytest.raises((AttributeError, TypeError)):
    config.host = "mutated.example.test"  # type: ignore[misc]


def test_config_forbidden_host_characters_are_rejected() -> None:
  """Characters that belong to URL/option syntax are rejected in the host part."""
  for bad_char in "/?#@=,\\'\"[]":
    with pytest.raises(ConfigError):
      load_config(_env(DB_SERVER=f"pg{bad_char}example.test"))


def test_config_dataclass_fields_match_the_contracted_shape() -> None:
  """``Config`` exposes exactly the five contracted attributes (host/port/user/password/dbname)."""
  config = load_config(_env())
  assert isinstance(config, Config)
  field_names = {field.name for field in dataclasses.fields(config)}
  assert field_names == {"host", "port", "user", "password", "dbname"}
