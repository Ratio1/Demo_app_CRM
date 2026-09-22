"""``shellcheck`` over ``scripts/*``, the only place the app touches the shell.

``scripts/start`` and ``scripts/with-env`` already ship and are checked for
real. ``scripts/dev-run.sh`` is planned but does not exist yet; that case
fails loudly, naming the missing file, rather than being silently skipped.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SUBMODULE_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = SUBMODULE_ROOT / "scripts"


def _shellcheck_path() -> str:
  """Return the ``shellcheck`` executable path, or fail with a clear reason."""
  path = shutil.which("shellcheck")
  if path is None:
    pytest.fail("shellcheck is not on PATH; the shell scripts cannot be checked")
  return path


@pytest.mark.parametrize("script_name", ["start", "with-env"])
def test_shipped_script_is_shellcheck_clean(script_name: str) -> None:
  """``shellcheck`` reports no findings for a script that already ships."""
  script_path = SCRIPTS_DIR / script_name
  assert script_path.is_file(), f"{script_path} does not exist"
  completed = subprocess.run(  # noqa: S603
    [_shellcheck_path(), "--severity=style", str(script_path)],
    cwd=SUBMODULE_ROOT,
    capture_output=True,
    text=True,
    timeout=30.0,
    check=False,
  )
  assert completed.returncode == 0, (
    f"shellcheck found issues in {script_name}:\n{completed.stdout}\n{completed.stderr}"
  )


def test_dev_run_sh_is_shellcheck_clean_once_it_exists() -> None:
  """``scripts/dev-run.sh``: not shipped yet — fails loudly, not silently."""
  script_path = SCRIPTS_DIR / "dev-run.sh"
  assert script_path.is_file(), f"{script_path} does not exist yet"
  completed = subprocess.run(  # noqa: S603
    [_shellcheck_path(), "--severity=style", str(script_path)],
    cwd=SUBMODULE_ROOT,
    capture_output=True,
    text=True,
    timeout=30.0,
    check=False,
  )
  assert completed.returncode == 0, (
    f"shellcheck found issues in dev-run.sh:\n{completed.stdout}\n{completed.stderr}"
  )
