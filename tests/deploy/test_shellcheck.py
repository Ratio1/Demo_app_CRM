"""``shellcheck`` over ``scripts/*`` — QLY-005.

Authority: ``ACCESS_MATRIX.md`` §7 (QLY-005: "``shellcheck`` clean over
``scripts/*``, the only place the app touches the shell").

``scripts/start`` and ``scripts/with-env`` already ship and are checked for
real. ``scripts/dev-run.sh`` is contracted (``slice-a.md`` §1.2, delta D8)
but does not exist yet; that case fails loudly, naming the Backend lane,
rather than being silently skipped.
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
    pytest.fail("shellcheck is not on PATH; QLY-005 cannot be measured")
  return path


@pytest.mark.parametrize("script_name", ["start", "with-env"])
def test_qly005_shipped_script_is_shellcheck_clean(script_name: str) -> None:
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


def test_qly005_dev_run_sh_is_shellcheck_clean_once_it_exists() -> None:
  """``scripts/dev-run.sh`` (slice-a.md §1.2, D8): not shipped yet — fails loudly, not silently."""
  script_path = SCRIPTS_DIR / "dev-run.sh"
  assert script_path.is_file(), (
    f"{script_path} does not exist yet (Backend lane pending, slice-a.md §1.2 D8)"
  )
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
