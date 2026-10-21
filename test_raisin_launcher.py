"""The `raisin` launcher runs raisin.py inside the virtual environment it selects.

A fake interpreter stands in for Python and prints the PATH and VIRTUAL_ENV it
was started with, so each test sees what raisin.py and the tools it runs
(cmake, and through it sphinx-build) would see.
"""

from pathlib import Path
import shutil
import subprocess

import pytest

LAUNCHER = Path(__file__).resolve().parent / "raisin"
SYSTEM_PATH = "/usr/bin:/bin"


def make_python(bin_dir: Path) -> Path:
    bin_dir.mkdir(parents=True)
    python = bin_dir / "python"
    python.write_text('#!/bin/sh\nprintf "%s\\n" "$PATH" "${VIRTUAL_ENV-}"\n')
    python.chmod(0o755)
    return python


@pytest.fixture
def workspace(tmp_path):
    """A RAISIN repo with the launcher, and a HOME without a raisin venv."""
    repo = tmp_path / "raisin_master"
    (repo / "commands").mkdir(parents=True)
    (repo / "raisin.py").touch()
    shutil.copy(LAUNCHER, repo / "raisin")
    home = tmp_path / "home"
    home.mkdir()
    return repo, home


def run_launcher(repo: Path, home: Path, **env) -> list:
    result = subprocess.run(
        ["bash", str(repo / "raisin"), "build"],
        cwd=repo,
        env={"HOME": str(home), "PATH": SYSTEM_PATH, **env},
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


def test_default_venv_is_activated_without_the_shell_function(workspace):
    repo, home = workspace
    venv = home / ".venvs" / "raisin_master"
    make_python(venv / "bin")
    (venv / "pyvenv.cfg").touch()

    path, virtual_env = run_launcher(repo, home)

    assert path == f"{venv}/bin:{SYSTEM_PATH}"
    assert virtual_env == str(venv)


def test_already_active_venv_is_left_as_is(workspace):
    repo, home = workspace
    venv = home / ".venvs" / "raisin_master"
    make_python(venv / "bin")
    (venv / "pyvenv.cfg").touch()
    active_path = f"{venv}/bin:{SYSTEM_PATH}"

    path, virtual_env = run_launcher(
        repo, home, PATH=active_path, VIRTUAL_ENV=str(venv)
    )

    assert path == active_path
    assert virtual_env == str(venv)


def test_system_python_leaves_path_unchanged(workspace, tmp_path):
    repo, home = workspace
    python = make_python(tmp_path / "system" / "bin")

    path, virtual_env = run_launcher(repo, home, RAISIN_PYTHON=str(python))

    assert path == SYSTEM_PATH
    assert virtual_env == ""
