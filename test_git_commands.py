import subprocess
from pathlib import Path
from unittest.mock import patch

from commands import git_commands


def _make_lfs_repo(tmp_path: Path, pointer=False) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".gitattributes").write_text(
        "*.bin filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8"
    )
    content = b"version https://git-lfs.github.com/spec/v1\n" if pointer else b"payload"
    (repo / "asset.bin").write_bytes(content)
    return repo


def _pull_command_result(command, lfs_fetch_result="downloaded"):
    command = tuple(command)
    responses = {
        ("git", "remote", "-v"): "origin https://github.com/acme/repo.git (fetch)",
        ("git", "symbolic-ref", "--short", "HEAD"): "main",
        ("git", "pull", "origin", "main", "--ff-only"): "Already up to date.",
        (
            "git",
            "ls-files",
            "--cached",
            "--",
            ".gitattributes",
            ":(glob)**/.gitattributes",
        ): ".gitattributes",
        ("git", "lfs", "version"): "git-lfs/3.4.1",
        ("git", "lfs", "install", "--local"): "Updated Git hooks.",
        ("git", "lfs", "fetch", "origin", "main"): lfs_fetch_result,
        ("git", "lfs", "checkout"): "Checking out LFS objects: 100%",
        ("git", "lfs", "ls-files", "--name-only"): "asset.bin",
    }
    return responses.get(command, "")


def test_pull_does_not_run_lfs_commands_for_non_lfs_repo(tmp_path):
    commands = []

    def run(command, cwd):
        commands.append(tuple(command))
        if command[:3] == ["git", "ls-files", "--cached"]:
            return ""
        return _pull_command_result(command)

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        result = git_commands.process_repo(str(tmp_path), pull_mode=True)

    assert result["status"] == "Success"
    assert result["message"] == "Already up to date."
    assert not any(command[:2] == ("git", "lfs") for command in commands)


def test_pull_recovers_lfs_objects_when_git_is_already_up_to_date(tmp_path):
    repo = _make_lfs_repo(tmp_path)
    commands = []

    def run(command, cwd):
        commands.append(tuple(command))
        return _pull_command_result(command)

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        result = git_commands.process_repo(str(repo), pull_mode=True)

    assert result["status"] == "Success"
    assert result["message"] == "Already up to date. Git LFS synced."
    assert ("git", "lfs", "fetch", "origin", "main") in commands
    assert ("git", "lfs", "checkout") in commands


def test_pull_reports_missing_git_lfs_with_recovery_command(tmp_path):
    repo = _make_lfs_repo(tmp_path)

    def run(command, cwd):
        if command == ["git", "lfs", "version"]:
            return None
        return _pull_command_result(command)

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        result = git_commands.process_repo(str(repo), pull_mode=True)

    assert result["status"] == "Fail"
    assert "Git LFS is required but unavailable" in result["message"]
    assert "git lfs install --local" in result["message"]
    assert "git lfs fetch origin main" in result["message"]


def test_pull_reports_lfs_download_failure(tmp_path):
    repo = _make_lfs_repo(tmp_path)

    def run(command, cwd):
        if command == ["git", "lfs", "fetch", "origin", "main"]:
            return None
        return _pull_command_result(command)

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        result = git_commands.process_repo(str(repo), pull_mode=True)

    assert result["status"] == "Fail"
    assert "Git LFS object download failed" in result["message"]
    assert "Check remote credentials" in result["message"]


def test_pull_fails_when_pointer_file_remains_after_checkout(tmp_path):
    repo = _make_lfs_repo(tmp_path, pointer=True)

    with patch.object(
        git_commands, "_run_git_command", side_effect=_pull_command_result
    ):
        result = git_commands.process_repo(str(repo), pull_mode=True)

    assert result["status"] == "Fail"
    assert "pointer files remain: asset.bin" in result["message"]


def test_fetch_downloads_lfs_objects_without_checkout(tmp_path, capsys):
    repo = _make_lfs_repo(tmp_path)
    (repo / ".git").mkdir()
    workspace = tmp_path / "workspace"
    src = workspace / "src"
    src.mkdir(parents=True)
    repo.rename(src / "repo")
    commands = []

    def run(command, cwd):
        commands.append(tuple(command))
        if command[:3] == ["git", "ls-files", "--cached"]:
            return ".gitattributes"
        return "ok"

    with (
        patch.object(git_commands.g, "script_directory", str(workspace)),
        patch.object(git_commands, "_run_git_command", side_effect=run),
    ):
        git_commands.git_fetch_command(remote="upstream")

    assert ("git", "lfs", "fetch", "upstream") in commands
    assert ("git", "lfs", "checkout") not in commands
    assert "Git LFS objects fetched" in capsys.readouterr().out


def test_checkout_syncs_and_verifies_lfs_worktree(tmp_path, capsys):
    repo = _make_lfs_repo(tmp_path)
    (repo / ".git").mkdir()
    workspace = tmp_path / "workspace"
    src = workspace / "src"
    src.mkdir(parents=True)
    repo.rename(src / "repo")
    commands = []

    def run(command, cwd):
        commands.append(tuple(command))
        if command[:3] == ["git", "ls-files", "--cached"]:
            return ".gitattributes"
        if command == ["git", "lfs", "ls-files", "--name-only"]:
            return "asset.bin"
        return "ok"

    with (
        patch.object(git_commands.g, "script_directory", str(workspace)),
        patch.object(
            git_commands.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0),
        ),
        patch.object(git_commands, "_run_git_command", side_effect=run),
    ):
        git_commands.git_checkout_command("feature")

    assert ("git", "lfs", "fetch") in commands
    assert ("git", "lfs", "checkout") in commands
    assert "Git LFS synced" in capsys.readouterr().out


def test_push_installs_lfs_hook_before_git_push(tmp_path):
    repo = _make_lfs_repo(tmp_path)
    (repo / ".git").mkdir()
    workspace = tmp_path / "workspace"
    src = workspace / "src"
    src.mkdir(parents=True)
    repo.rename(src / "repo")
    commands = []

    def run(command, cwd):
        commands.append(tuple(command))
        if command[:3] == ["git", "ls-files", "--cached"]:
            return ".gitattributes"
        if command == ["git", "symbolic-ref", "--short", "HEAD"]:
            return "main"
        return "ok"

    with (
        patch.object(git_commands.g, "script_directory", str(workspace)),
        patch.object(git_commands, "_run_git_command", side_effect=run),
    ):
        git_commands.git_push_current_command()

    install_index = commands.index(("git", "lfs", "install", "--local"))
    push_index = commands.index(("git", "push", "origin", "main:main"))
    assert install_index < push_index


def test_status_reports_remaining_lfs_pointer_files(tmp_path):
    repo = _make_lfs_repo(tmp_path, pointer=True)

    def run(command, cwd):
        if command[:3] == ["git", "ls-files", "--cached"]:
            return ".gitattributes"
        if command == ["git", "lfs", "version"]:
            return "git-lfs/3.4.1"
        if command == ["git", "lfs", "ls-files", "--name-only"]:
            return "asset.bin"
        return ""

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        status = git_commands._get_lfs_worktree_status(str(repo))

    assert status == "1 LFS pointer file(s) remain"


def test_status_reports_missing_git_lfs(tmp_path):
    repo = _make_lfs_repo(tmp_path)

    def run(command, cwd):
        if command[:3] == ["git", "ls-files", "--cached"]:
            return ".gitattributes"
        if command == ["git", "lfs", "version"]:
            return None
        return ""

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        status = git_commands._get_lfs_worktree_status(str(repo))

    assert status == "Git LFS unavailable"
