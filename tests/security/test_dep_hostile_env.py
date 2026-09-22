"""DEP-004 (hostile ``PG*`` environment) and DEP-013 (TLS negative pair).

Authority: ``ACCESS_MATRIX.md`` §7 (DEP-004, DEP-013); ``slice-a.md`` §8.1,
§8.3 (the live evidence this module re-derives independently) and §6 delta
**D9** (the ``PG*`` scrub, ruling **R35**).

Unlike most of ``tests/security``, these do **not** need ``app.main`` or a
live server: ``app.config`` and a direct ``psycopg`` connection already
exist, so the connection-level halves below run against real code and the
real ``crm_test`` database today.

Credential discipline
----------------------
Every probe here runs as a ``python -c`` **subprocess** under
``scripts/with-env`` so this test process never itself holds a credential.
Each probe script prints exactly one machine-parseable ``RESULT ...`` line
containing only booleans, an exception *class* name, or TLS session
metadata (``ssl``, negotiated version) — never a host, port, user, database
name or password, none of which this module or its assertions ever touch,
per ``AGENTS.md``'s "never print credentials or env values." The full
subprocess output is additionally saved to a ``tmp_path`` log file that
nothing here reads or asserts on, for a human to open by hand if needed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Final

import pytest

SUBMODULE_ROOT: Final[Path] = Path(__file__).resolve().parent.parent.parent
VENV_PYTHON: Final[Path] = SUBMODULE_ROOT / ".venv" / "bin" / "python"
WITH_ENV: Final[Path] = SUBMODULE_ROOT / "scripts" / "with-env"
RUNTIME_ENV_FILE: Final[str] = ".env.test.local"

#: DEP-004's exact hostile set, minus PGSERVICE/PGSERVICEFILE — which the
#: register itself notes are a *separate*, availability-only claim (a
#: nonexistent service name is a hard connection failure even with every
#: parameter explicit) and must not be conflated with the downgrade/redirect
#: claim this half tests.
_HOSTILE_PG_ENV: Final[dict[str, str]] = {
  "PGSSLMODE": "disable",
  "PGHOST": "evil.invalid",
  "PGSSLROOTCERT": "/tmp/evil-does-not-exist.pem",  # noqa: S108 — the hostile value itself
  "PGOPTIONS": "-c",
  "PGSSLMINPROTOCOLVERSION": "TLSv1",
  "PGGSSENCMODE": "prefer",
}


def _run_probe(
  argv: list[str],
  *,
  extra_env: dict[str, str],
  log_path: Path,
  timeout: float = 30.0,
) -> str:
  """Run a ``python -c`` probe under ``with-env`` and return its ``RESULT`` line.

  Parameters
  ----------
  argv : list[str]
    The full command, already including ``scripts/with-env <file> --``.
  extra_env : dict[str, str]
    Variables layered on top of ``os.environ`` for this call only (the
    hostile ``PG*`` set, or nothing).
  log_path : Path
    Where the full combined output is saved; never read by this function.
  timeout : float
    Seconds before the subprocess is killed.

  Returns
  -------
  str
    The single line beginning with ``"RESULT "``, stripped of that prefix.

  Raises
  ------
  AssertionError
    If no such line was produced — the full log is on disk at ``log_path``
    for a human to inspect; its contents are not repeated here.
  """
  env = {**os.environ, **extra_env}
  completed = subprocess.run(  # noqa: S603
    argv,
    cwd=SUBMODULE_ROOT,
    env=env,
    capture_output=True,
    text=True,
    timeout=timeout,
    check=False,
  )
  log_path.write_text(
    f"argv={argv[:3]}...\nreturncode={completed.returncode}\n"
    f"--- stdout ---\n{completed.stdout}\n--- stderr ---\n{completed.stderr}\n",
    encoding="utf-8",
  )
  for line in completed.stdout.splitlines():
    if line.startswith("RESULT "):
      return line.removeprefix("RESULT ").strip()
  pytest.fail(f"no RESULT line from probe (exit {completed.returncode}); see {log_path}")


# ---------------------------------------------------------------------------
# DEP-004(a) — explicit kwargs reach crm_test under a hostile PG* environment.
#
# Ruling R53: `scripts/with-env` scrubs every `PG*` variable **before**
# `exec`-ing the child (D9/R35), so setting the hostile set as `extra_env` on
# the *launcher* subprocess (the previous shape of this test) is scrubbed
# away before the child interpreter even starts — the child never sees a
# hostile environment at all, and the test would pass regardless of whether
# `connect_kwargs()` actually resists one. The probe below instead injects
# the hostile `PG*` set with `os.environ.update(...)` **inside** the running
# child process, immediately before `load_config()`/`connect` — after the
# scrub, but exactly where a real hostile environment would sit — so a
# connection succeeding here is real evidence, not a vacuous pass.
# ---------------------------------------------------------------------------

_TLS_SESSION_PROBE = """
import asyncio
from typing import Any, cast
from psycopg import AsyncConnection
from app.config import load_config

async def main() -> None:
  kwargs = cast('dict[str, Any]', load_config().connect_kwargs())
  conn = await AsyncConnection.connect(**kwargs)
  try:
    cur = await conn.execute(
      "SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
    )
    row = await cur.fetchone()
    print(f"RESULT connected=True ssl={row[0]} version={row[1]}")
  finally:
    await conn.close()

asyncio.run(main())
"""

#: Same as :data:`_TLS_SESSION_PROBE`, plus (1) an in-child ``os.environ.update``
#: of the hostile ``PG*`` set — substituted by ``repr()``, never ``.format()``,
#: so nothing here collides with the f-string braces already inside the
#: script (the same reason ``conftest.insert_test_user_row`` uses
#: ``.replace``, not ``.format`` — see its docstring); and (2) a
#: ``host_matches_config`` boolean that proves the *negotiated* connection
#: used ``connect_kwargs()``'s own ``host``, without ever printing the
#: value itself (credential discipline, module docstring).
_HOSTILE_ENV_TLS_PROBE = """
import asyncio
import os
from typing import Any, cast
from psycopg import AsyncConnection
from app.config import load_config

os.environ.update(__HOSTILE_ENV__)

async def main() -> None:
  kwargs = cast('dict[str, Any]', load_config().connect_kwargs())
  conn = await AsyncConnection.connect(**kwargs)
  try:
    cur = await conn.execute(
      "SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
    )
    row = await cur.fetchone()
    host_matches_config = conn.info.host == kwargs.get('host')
    print(
      "RESULT connected=True ssl=" + str(row[0]) + " version=" + str(row[1])
      + " host_matches_config=" + str(host_matches_config)
    )
  finally:
    await conn.close()

asyncio.run(main())
"""


def test_dep004a_hostile_pg_env_still_reaches_crm_test_over_tls(tmp_path: Path) -> None:
  """A hostile ``PG*`` set injected **inside** the connecting process still yields ``verify-full``.

  Scope, exactly as the register pins it: every contracted kwarg is already
  explicit in ``connect_kwargs()`` (``host``, ``port``, ``user``,
  ``password``, ``dbname``, ``sslmode=verify-full``, ``sslrootcert``,
  ``connect_timeout``, ``options=""``), so libpq has no gap to fall back
  into for *those* — this is the "cannot override" half. Today, before D1
  lands, ``ssl_min_protocol_version``/``gssencmode``/``client_encoding`` are
  not yet among them (tracked separately by
  ``tests/unit/test_config.py::test_d1_connect_kwargs_is_exactly_the_twelve_key_set``);
  this test only asserts what the *current* nine-key set already guarantees:
  a real TLS session still negotiates against the configured host, despite
  ``PGSSLMODE=disable`` and a nonexistent ``PGSSLROOTCERT`` sitting in
  ``os.environ`` at connect time (R53 — injected inside the child so
  ``with-env``'s own scrub, which would otherwise make this vacuous, is
  irrelevant here).
  """
  # `-c`, not a script path: a script *path* puts the script's own directory
  # on sys.path[0], not the cwd, so `import app` would fail regardless of
  # `cwd=SUBMODULE_ROOT` — the same reason slice-a.md §10(e) uses `-c`.
  script = _HOSTILE_ENV_TLS_PROBE.replace("__HOSTILE_ENV__", repr(_HOSTILE_PG_ENV))
  argv = [str(WITH_ENV), RUNTIME_ENV_FILE, "--", str(VENV_PYTHON), "-B", "-c", script]
  # No `extra_env` on the launcher: R53's whole point is that a hostile set
  # placed there is scrubbed by `with-env` before the child ever starts.
  result = _run_probe(argv, extra_env={}, log_path=tmp_path / "probe.log")
  assert "connected=True" in result
  assert "ssl=True" in result
  assert "host_matches_config=True" in result


def test_dep004a_baseline_without_hostile_env_also_connects_over_tls(tmp_path: Path) -> None:
  """Control case: the same (non-hostile) probe shape, for comparison."""
  argv = [str(WITH_ENV), RUNTIME_ENV_FILE, "--", str(VENV_PYTHON), "-B", "-c", _TLS_SESSION_PROBE]
  result = _run_probe(argv, extra_env={}, log_path=tmp_path / "probe.log")
  assert "connected=True" in result
  assert "ssl=True" in result


# ---------------------------------------------------------------------------
# DEP-004(b) — the D9 scrub in scripts/with-env (ruling R35).
# ---------------------------------------------------------------------------

_PG_STAR_SURVIVAL_PROBE = (
  "import os, sys; "
  'leaked = sorted(k for k in os.environ if k.startswith("PG")); '
  'print("RESULT leaked=" + (",".join(leaked) if leaked else "none"))'
)


def test_dep004b_with_env_scrubs_every_pg_star_variable_before_exec(tmp_path: Path) -> None:
  """After ``scripts/with-env`` execs, no ``PG*`` variable survives into the child (D9/R35)."""
  argv = [str(WITH_ENV), RUNTIME_ENV_FILE, "--", str(VENV_PYTHON), "-B", "-c"]
  completed = subprocess.run(  # noqa: S603
    [*argv, _PG_STAR_SURVIVAL_PROBE],
    cwd=SUBMODULE_ROOT,
    env={**os.environ, "PGSERVICE": "x", "PGSERVICEFILE": "/nonexistent"},
    capture_output=True,
    text=True,
    timeout=30.0,
    check=False,
  )
  (tmp_path / "probe.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
  result_line = next(
    (line for line in completed.stdout.splitlines() if line.startswith("RESULT ")), None
  )
  assert result_line is not None, f"no RESULT line (exit {completed.returncode})"
  assert result_line == "RESULT leaked=none"


# ---------------------------------------------------------------------------
# DEP-013 — the verify-full negative pair: wrong CA, wrong hostname.
# ---------------------------------------------------------------------------

_WRONG_CA_PROBE = """
import asyncio
from typing import Any, cast
import psycopg
from psycopg import AsyncConnection
from app.config import load_config

async def main() -> None:
  kwargs = cast('dict[str, Any]', load_config().connect_kwargs())
  kwargs['sslrootcert'] = {foreign_cert!r}
  try:
    conn = await AsyncConnection.connect(**kwargs)
    await conn.close()
    print("RESULT rejected=False")
  except psycopg.OperationalError:
    print("RESULT rejected=True error_class=OperationalError")

asyncio.run(main())
"""

_WRONG_HOSTNAME_PROBE = """
import asyncio
from typing import Any, cast
import psycopg
from psycopg import AsyncConnection
from app.config import load_config

async def main() -> None:
  kwargs = cast('dict[str, Any]', load_config().connect_kwargs())
  kwargs['hostaddr'] = '127.0.0.1' if not kwargs['host'][0].isdigit() else kwargs['host']
  kwargs['host'] = 'not-the-cert-name.invalid'
  try:
    conn = await AsyncConnection.connect(**kwargs)
    await conn.close()
    print("RESULT rejected=False")
  except psycopg.OperationalError:
    print("RESULT rejected=True error_class=OperationalError")

asyncio.run(main())
"""


def test_dep013_a_foreign_root_certificate_fails_closed(tmp_path: Path) -> None:
  """``verify-full`` against a valid-but-foreign CA is rejected, not silently trusted."""
  foreign_key = tmp_path / "foreign.key"
  foreign_cert = tmp_path / "foreign.crt"
  openssl = shutil.which("openssl")
  assert openssl is not None, "openssl not found on PATH"
  subprocess.run(  # noqa: S603
    [
      openssl,
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "1",
      "-keyout",
      str(foreign_key),
      "-out",
      str(foreign_cert),
      "-subj",
      "/CN=foreign-ca",
    ],
    cwd=tmp_path,
    capture_output=True,
    check=True,
    timeout=30.0,
  )
  script = _WRONG_CA_PROBE.format(foreign_cert=str(foreign_cert))
  argv = [str(WITH_ENV), RUNTIME_ENV_FILE, "--", str(VENV_PYTHON), "-B", "-c", script]
  result = _run_probe(argv, extra_env={}, log_path=tmp_path / "probe.log")
  assert "rejected=True" in result


def test_dep013_a_hostname_absent_from_the_certificate_san_fails_closed(tmp_path: Path) -> None:
  """``verify-full`` against a hostname the server certificate does not cover is rejected."""
  argv = [
    str(WITH_ENV),
    RUNTIME_ENV_FILE,
    "--",
    str(VENV_PYTHON),
    "-B",
    "-c",
    _WRONG_HOSTNAME_PROBE,
  ]
  result = _run_probe(argv, extra_env={}, log_path=tmp_path / "probe.log")
  assert "rejected=True" in result
