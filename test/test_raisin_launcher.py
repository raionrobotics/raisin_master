"""The `raisin` launcher runs raisin.py inside the virtual environment it selects.

A fake interpreter stands in for Python and prints the PATH and VIRTUAL_ENV it
was started with, so each test sees what raisin.py and the tools it runs
(cmake, and through it sphinx-build) would see.
"""

from pathlib import Path
import shutil
import subprocess

import pytest

LAUNCHER = Path(__file__).resolve().parent.parent / "raisin"
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


def run_install(repo: Path, home: Path, tmp_path: Path, sys_deps_exit: int):
    """`raisin --install` with a stand-in install_system_deps.sh and a python3 without pip.

    The python3 makes creating the virtual environment fail, the step that a failed
    install_system_deps.sh breaks on a new PC (it installs python3-pip and python3-virtualenv).
    """
    (repo / "install_system_deps.sh").write_text(f"echo 'ERROR: stand-in failure' >&2\nexit {sys_deps_exit}\n")
    bin_dir = tmp_path / "nopip" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "python3").write_text("#!/bin/sh\nexit 1\n")
    (bin_dir / "python3").chmod(0o755)
    return subprocess.run(
        ["bash", str(repo / "raisin"), "--install"],
        cwd=repo,
        env={"HOME": str(home), "PATH": f"{bin_dir}:{SYSTEM_PATH}"},
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )


def test_install_repeats_a_system_deps_failure_when_a_later_step_stops_it(workspace, tmp_path):
    repo, home = workspace

    result = run_install(repo, home, tmp_path, sys_deps_exit=1)

    assert result.returncode == 1  # creating the virtual environment failed
    tail = result.stderr[result.stderr.index("failed to create virtual environment"):]
    assert "install_system_deps.sh failed (its error is above)" in tail


def test_install_says_nothing_about_system_deps_when_they_installed(workspace, tmp_path):
    repo, home = workspace

    result = run_install(repo, home, tmp_path, sys_deps_exit=0)

    assert result.returncode == 1
    assert "install_system_deps.sh failed" not in result.stderr


def run_install_to_the_hook(repo: Path, home: Path, tmp_path: Path):
    """`raisin --install` that gets past the virtual environment, in a git repository.

    Python is a stand-in that succeeds, and the venv already exists, so the install reaches the
    step that enables the commit hook. stdin is closed: the step must not wait for an answer.
    """
    (repo / "install_system_deps.sh").write_text("exit 0\n")
    shutil.copytree(LAUNCHER.parent / ".githooks", repo / ".githooks")
    bin_dir = tmp_path / "okpython" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "python3").write_text("#!/bin/sh\nexit 0\n")
    (bin_dir / "python3").chmod(0o755)
    # The pre-commit the hook finds at commit time; it succeeds, so a commit's result is the kept hook's.
    (bin_dir / "pre-commit").write_text("#!/bin/sh\nexit 0\n")
    (bin_dir / "pre-commit").chmod(0o755)
    venv = home / ".venvs" / "raisin_master"
    make_python(venv / "bin")
    (venv / "pyvenv.cfg").touch()
    env = {"HOME": str(home), "PATH": f"{bin_dir}:{SYSTEM_PATH}", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    subprocess.run(["git", "init", "-q", str(repo)], env=env, check=True)
    return env, lambda: subprocess.run(
        ["bash", str(repo / "raisin"), "--install"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )


def hooks_path(repo: Path, env: dict) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "config", "--get", "core.hooksPath"],
        env=env, capture_output=True, text=True,
    ).stdout.strip()


def write_hook(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


def commit(repo: Path, env: dict) -> subprocess.CompletedProcess:
    (repo / "f").write_text("x\n")
    subprocess.run(["git", "-C", str(repo), "add", "f"], env=env, check=True)
    return subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "m"],
                          env=env, capture_output=True, text=True)


def test_install_links_the_commit_hook_into_git_hooks(workspace, tmp_path):
    repo, home = workspace
    env, install = run_install_to_the_hook(repo, home, tmp_path)

    result = install()

    assert result.returncode == 0, result.stdout + result.stderr
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert hook.resolve() == (repo / ".githooks" / "pre-commit").resolve()
    assert hooks_path(repo, env) == ""


def test_install_leaves_an_existing_pre_commit_hook_and_says_how_to_run_the_raisin_hook(workspace, tmp_path):
    repo, home = workspace
    env, install = run_install_to_the_hook(repo, home, tmp_path)
    ran = tmp_path / "mine-ran"
    hook = repo / ".git" / "hooks" / "pre-commit"
    write_hook(hook, f"touch {ran}")
    before = hook.read_text()

    first, second = install(), install()

    for result in (first, second):  # it says so at every run until the hook runs the raisin hook
        assert result.returncode == 0, result.stdout + result.stderr
        assert "A pre-commit hook is already there" in result.stdout
    assert not hook.is_symlink() and hook.read_text() == before
    assert not hook.with_name("pre-commit.legacy").exists()
    assert commit(repo, env).returncode == 0
    assert ran.exists()


def raisin_hook_line(install_output: str) -> str:
    """The line --install prints for a developer to add to their own pre-commit hook."""
    lines = install_output.splitlines()
    return lines[next(i for i, line in enumerate(lines) if "right after its first line" in line) + 1].strip()


def test_the_line_install_prints_runs_the_raisin_hook_from_the_developers_hook(workspace, tmp_path):
    repo, home = workspace
    env, install = run_install_to_the_hook(repo, home, tmp_path)
    mine, ours = tmp_path / "mine-ran", tmp_path / "raisin-ran"
    (tmp_path / "okpython" / "bin" / "pre-commit").write_text(f"#!/bin/sh\ntouch {ours}\n")
    hook = repo / ".git" / "hooks" / "pre-commit"
    write_hook(hook, f"touch {mine}")
    shebang, rest = hook.read_text().split("\n", 1)
    hook.write_text(f"{shebang}\n{raisin_hook_line(install().stdout)}\n{rest}")

    result = install()

    assert "runs the raisin_master commit hook" in result.stdout
    assert commit(repo, env).returncode == 0
    assert mine.exists() and ours.exists()


REAL_PRE_COMMIT = shutil.which("pre-commit")


@pytest.mark.skipif(REAL_PRE_COMMIT is None, reason="pre-commit is not installed")
def test_install_leaves_a_hook_written_by_pre_commit_install_and_commits_pass(workspace, tmp_path):
    # Such a hook runs pre-commit.legacy next to itself; moved there, it ran itself and pre-commit
    # failed every commit ("installed in migration mode"). It also reads the root
    # .pre-commit-config.yaml, which is the developer's own: the raisin_master config is elsewhere.
    repo, home = workspace
    env, install = run_install_to_the_hook(repo, home, tmp_path)
    ran = tmp_path / "mine-ran"
    (repo / ".pre-commit-config.yaml").write_text(
        "repos:\n- repo: local\n  hooks:\n  - id: mine\n    name: mine\n"
        f"    entry: touch {ran}\n    language: system\n    pass_filenames: false\n"
    )
    subprocess.run([REAL_PRE_COMMIT, "install"], cwd=repo, env=env, check=True, capture_output=True)
    hook = repo / ".git" / "hooks" / "pre-commit"
    before = hook.read_text()

    result = install()

    assert result.returncode == 0, result.stdout + result.stderr
    assert "A pre-commit hook is already there" in result.stdout
    assert hook.read_text() == before
    committed = commit(repo, env)
    assert committed.returncode == 0, committed.stdout + committed.stderr
    assert ran.exists()


def test_install_leaves_a_developers_hooks_path_alone(workspace, tmp_path):
    repo, home = workspace
    env, install = run_install_to_the_hook(repo, home, tmp_path)
    subprocess.run(["git", "config", "--global", "core.hooksPath", "/opt/hooks"], env=env, check=True)

    result = install()

    assert result.returncode == 0, result.stdout + result.stderr
    assert "core.hooksPath is set (/opt/hooks)" in result.stdout
    assert hooks_path(repo, env) == "/opt/hooks"
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()
