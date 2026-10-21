"""The workspace root install_dependencies.sh and scripts/install_package_deps.sh.

The scripts run for real in temporary workspaces. Where apt would be reached, the shared
installer is replaced by a stub that records its argument; the real one runs only on
packages that declare no apt package, so it never calls apt or sudo.
"""

from pathlib import Path
import shutil
import subprocess

REPO = Path(__file__).resolve().parent
RUNNER = REPO / "install_dependencies.sh"
SHARED_INSTALLER = REPO / "scripts" / "install_package_deps.sh"


def _run(*args, cwd):
    return subprocess.run(
        ["bash", *map(str, args)], cwd=cwd, capture_output=True, text=True, check=False
    )


def _workspace_with_stub_installer(tmp_path):
    workspace = tmp_path / "ws"
    (workspace / "scripts").mkdir(parents=True)
    shutil.copy(RUNNER, workspace / "install_dependencies.sh")
    record = tmp_path / "shared_installer_calls"
    (workspace / "scripts" / "install_package_deps.sh").write_text(
        f'#!/usr/bin/env bash\necho "$1" >> "{record}"\n'
    )
    return workspace, record


def test_runner_installs_deps_of_a_source_package_without_its_own_script(tmp_path):
    workspace, record = _workspace_with_stub_installer(tmp_path)
    (workspace / "src" / "only_deps" / "deps").mkdir(parents=True)

    result = _run("install_dependencies.sh", cwd=workspace)

    assert result.returncode == 0, result.stdout + result.stderr
    assert record.read_text().splitlines() == [f"{workspace}/src/only_deps/"]


def test_runner_runs_a_source_package_script_and_not_the_shared_installer(tmp_path):
    workspace, record = _workspace_with_stub_installer(tmp_path)
    package = workspace / "src" / "own_script"
    (package / "deps").mkdir(parents=True)
    ran = tmp_path / "own_script_ran"
    (package / "install_dependencies.sh").write_text(f'#!/usr/bin/env bash\ntouch "{ran}"\n')

    result = _run("install_dependencies.sh", cwd=workspace)

    assert result.returncode == 0, result.stdout + result.stderr
    assert ran.exists()
    assert not record.exists()


def test_runner_skips_a_source_package_that_declares_nothing(tmp_path):
    workspace, record = _workspace_with_stub_installer(tmp_path)
    (workspace / "src" / "nothing").mkdir(parents=True)

    result = _run("install_dependencies.sh", cwd=workspace)

    assert result.returncode == 0, result.stdout + result.stderr
    assert not record.exists()
    assert "No package dependency installers found" in result.stdout


def test_shared_installer_reads_the_package_directory_it_is_given(tmp_path):
    package = tmp_path / "pkg"
    (package / "deps").mkdir(parents=True)
    (package / "deps" / "apt.txt").write_text("# nothing yet\n")

    result = _run(SHARED_INSTALLER, package, cwd=tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert f"No apt packages declared in {package}/deps/" in result.stdout


def test_shared_installer_copied_into_a_package_reads_the_deps_next_to_it(tmp_path):
    # `raisin publish` copies it into the install tree, where robots run it without arguments.
    package = tmp_path / "install_tree"
    (package / "deps").mkdir(parents=True)
    shutil.copy(SHARED_INSTALLER, package / "install_dependencies.sh")

    result = _run(package / "install_dependencies.sh", cwd=tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert f"No apt packages declared in {package}/deps/" in result.stdout
