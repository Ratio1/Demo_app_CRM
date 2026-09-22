"""``import app.main`` with all five names absent attempts no connection — DEP-003.

Authority: ``ACCESS_MATRIX.md`` §7 (DEP-003); ``slice-a.md`` §1.1 (lifespan
order: ``load_config() -> create_pool(config, open=False) -> ...`` — nothing
connects at import or at lifespan *start*; ``open_pool`` runs lazily on the
first acquisition).

Runs a **fresh subprocess** interpreter (never the pytest process's own,
which may already have cached ``app.main`` from an earlier test in the same
session) with every ``DB_*`` name absent from its environment and a short
timeout: if the import attempted a real connection, it would either raise
``ConfigError`` immediately (also acceptable — proves no earlier, silent
attempt) or hang past the timeout trying to reach a host that was never
configured. A clean, fast exit is the only outcome consistent with "no
connection is attempted at import time."
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Final

SUBMODULE_ROOT: Final[Path] = Path(__file__).resolve().parent.parent.parent
VENV_PYTHON: Final[Path] = SUBMODULE_ROOT / ".venv" / "bin" / "python"

_PROBE = "import app.main"


def test_dep003_import_app_main_with_all_five_db_names_absent(tmp_path: Path) -> None:
  """A fresh interpreter with ``DB_SERVER/PORT/USER/PASSWORD/NAME`` unset imports cleanly."""
  env = {
    "PATH": "/usr/bin:/bin",
    "HOME": str(tmp_path),
  }
  completed = subprocess.run(  # noqa: S603
    [str(VENV_PYTHON), "-B", "-c", _PROBE],
    cwd=SUBMODULE_ROOT,
    env=env,
    capture_output=True,
    text=True,
    timeout=10.0,
    check=False,
  )
  assert completed.returncode == 0, (
    f"import app.main failed or attempted a connection (exit {completed.returncode}); "
    f"stderr tail: {completed.stderr[-2000:]}"
  )


def test_dep001_import_app_main_contacts_no_database_even_with_a_deliberately_unreachable_host(
  tmp_path: Path,
) -> None:
  """Setting the five names to an unreachable host still imports fast — proving no eager connect.

  If ``import app.main`` opened a connection eagerly, this would hang for
  the libpq connect timeout (contracted at 5 s, ``CONNECT_TIMEOUT_S``) or
  longer; a bare import returns near-instantly regardless of whether the
  configured host is reachable, because nothing reads the five names until
  ``load_config()`` is actually called inside ``create_app``/lifespan.
  """
  env = {
    "PATH": "/usr/bin:/bin",
    "HOME": str(tmp_path),
    "DB_SERVER": "10.255.255.1",  # a non-routed address (RFC 5737-adjacent), never reachable
    "DB_USER": "unreachable_probe",
    "DB_PASSWORD": "unreachable_probe",
    "DB_NAME": "unreachable_probe",
  }
  completed = subprocess.run(  # noqa: S603
    [str(VENV_PYTHON), "-B", "-c", _PROBE],
    cwd=SUBMODULE_ROOT,
    env=env,
    capture_output=True,
    text=True,
    timeout=3.0,  # well under CONNECT_TIMEOUT_S=5; a real attempt would exceed this
    check=False,
  )
  assert completed.returncode == 0, (
    f"import app.main failed (exit {completed.returncode}); stderr tail: {completed.stderr[-2000:]}"
  )
