"""Run the real shell aggregator with inert temporary package installers only.

No sudo, package manager, network or installed workspace is used. This protects
the failure-status fix in f575d7c, not managed worker completion or cgroup drain.
"""

import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess

import pytest

SOURCE = Path(__file__).with_name("install_dependencies.sh")
TOOLS = {name: shutil.which(name) for name in ("bash", "dirname", "basename", "uname")}
BASH = TOOLS["bash"]
pytestmark = pytest.mark.skipif(
    platform.system() != "Linux" or not all(TOOLS.values()),
    reason="dependency runner integration requires Linux, Bash and basic coreutils",
)
ENVIRONMENT = {
    "PATH": os.pathsep.join(
        dict.fromkeys(
            [str(Path(path).parent) for path in TOOLS.values() if path]
            + os.defpath.split(os.pathsep)
        )
    ),
    "LC_ALL": "C",
}


def platform_parts(detected, architecture):
    architecture = {"aarch64": "arm64", "amd64": "x86_64"}.get(
        architecture, architecture
    )
    parts = (*detected.splitlines(), architecture)
    if len(parts) != 3 or any(
        value in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_.-]+", value)
        for value in parts
    ):
        raise ValueError("unsafe dependency runner fixture platform")
    return parts


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "workspace with spaces"
    root.mkdir()
    runner = root / SOURCE.name
    runner.write_bytes(SOURCE.read_bytes())
    return root


def package(workspace, name, origin, *, executable, status=0):
    if origin == "source":
        directory = workspace / "src" / name
    else:
        # Read the same host platform as the script, without inheriting shell
        # startup hooks. No platform is injected into the code under test.
        detected = subprocess.run(
            [
                BASH,
                "--noprofile",
                "--norc",
                "-c",
                "if [[ -f /etc/os-release ]]; then . /etc/os-release; "
                'printf "%s\\n%s" "${ID:-linux}" "${VERSION_ID:-unknown}"; '
                'else printf "linux\\nunknown"; fi',
            ],
            env=ENVIRONMENT,
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        ).stdout
        parts = platform_parts(detected, platform.machine())
        directory = workspace / "release" / "install" / name / Path(*parts) / "release"
    directory.mkdir(parents=True)
    marker = workspace / (name + "-" + origin + ".called")
    installer = directory / "install_dependencies.sh"
    installer.write_text(
        "#!/usr/bin/env bash\n"
        + "printf 'called\\n' > "
        + shlex.quote(str(marker))
        + "\n"
        + "exit "
        + str(status)
        + "\n",
        encoding="utf-8",
    )
    installer.chmod(0o755 if executable else 0o644)
    return marker


def run(workspace, tmp_path):
    return subprocess.run(
        [BASH, str(workspace / SOURCE.name), "-y"],
        cwd=tmp_path,
        env=ENVIRONMENT,
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize("origin", ["source", "release"])
@pytest.mark.parametrize("executable", [False, True])
@pytest.mark.parametrize("status", [0, 7])
def test_package_status_reaches_aggregate_exit(
    workspace, tmp_path, origin, executable, status
):
    marker = package(workspace, "inert", origin, executable=executable, status=status)
    result = run(workspace, tmp_path)
    assert marker.read_text() == "called\n", result.stdout + result.stderr
    assert result.returncode == (0 if status == 0 else 1), result.stdout + result.stderr


def test_empty_workspace_remains_successful_without_executing_any_package(
    workspace, tmp_path
):
    result = run(workspace, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "No package dependency installers found" in result.stdout
    assert list(workspace.iterdir()) == [workspace / SOURCE.name]


@pytest.mark.parametrize("origin", ["source", "release"])
def test_failure_is_not_erased_by_a_later_success(workspace, tmp_path, origin):
    failed = package(workspace, "a_failed", origin, executable=False, status=7)
    later = package(workspace, "z_success", origin, executable=True)
    result = run(workspace, tmp_path)
    assert failed.read_text() == later.read_text() == "called\n"
    assert result.returncode == 1, result.stdout + result.stderr
    assert "2 installer(s) found, 1 failed" in result.stdout


def test_failed_source_provider_is_not_hidden_by_successful_release_provider(
    workspace, tmp_path
):
    source = package(workspace, "same_package", "source", executable=True, status=7)
    release = package(workspace, "same_package", "release", executable=True)
    result = run(workspace, tmp_path)
    assert source.read_text() == "called\n"
    assert not release.exists()
    assert result.returncode == 1, result.stdout + result.stderr
    assert "1 installer(s) found, 1 failed" in result.stdout


@pytest.mark.parametrize(
    "detected,architecture,expected",
    [
        ("ubuntu\n24.04", "x86_64", ("ubuntu", "24.04", "x86_64")),
        ("arch\nunknown", "amd64", ("arch", "unknown", "x86_64")),
        ("linux\nunknown", "aarch64", ("linux", "unknown", "arm64")),
    ],
)
def test_fixture_platform_components_match_runner_fallbacks(
    detected, architecture, expected
):
    assert platform_parts(detected, architecture) == expected


@pytest.mark.parametrize(
    "detected,architecture",
    [
        ("/\n24.04", "x86_64"),
        ("ubuntu\n../", "x86_64"),
        ("", "x86_64"),
        ("ubuntu\n24.04\nextra", "x86_64"),
        ("ubuntu\n24.04", ".."),
        ("..\n24.04", "x86_64"),
    ],
)
def test_fixture_platform_cannot_escape_private_workspace(detected, architecture):
    with pytest.raises(ValueError):
        platform_parts(detected, architecture)


def test_subprocesses_use_resolved_bash_without_inherited_shell_hooks(
    workspace, tmp_path, monkeypatch
):
    bash = shutil.which("bash")
    original, calls = subprocess.run, []
    monkeypatch.setenv("BASH_ENV", str(tmp_path / "untrusted-startup-hook"))

    def checked(argv, **kwargs):
        assert argv[0] == bash and Path(argv[0]).is_absolute()
        assert "BASH_ENV" not in kwargs["env"]
        calls.append(argv)
        return original(argv, **kwargs)

    monkeypatch.setattr(subprocess, "run", checked)
    marker = package(workspace, "absolute_bash", "release", executable=True)
    result = run(workspace, tmp_path)
    assert result.returncode == 0 and marker.read_text() == "called\n"
    assert len(calls) == 2
