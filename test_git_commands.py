import subprocess
from pathlib import Path
from unittest.mock import patch

from commands import git_commands


LFS_POINTER = (
    b"version https://git-lfs.github.com/spec/v1\n"
    b"oid sha256:" + b"a" * 64 + b"\n"
    b"size 3946984\n"
)


def _make_lfs_repo(tmp_path: Path, pointer=False) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".gitattributes").write_text(
        "*.bin filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8"
    )
    (repo / "asset.bin").write_bytes(LFS_POINTER if pointer else b"payload")
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


def _tracked(*paths):
    """Mimic the NUL separated output of git ls-files -z."""
    return "\0".join(paths)


def test_pointer_scan_works_without_the_git_lfs_binary(tmp_path):
    repo = _make_lfs_repo(tmp_path, pointer=True)

    def run(command, cwd):
        if command == ["git", "ls-files", "-z"]:
            return _tracked(".gitattributes", "asset.bin")
        return None  # every "git lfs ..." call fails: the binary is absent

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        pointers = git_commands.find_lfs_pointer_files(str(repo))

    assert pointers == ["asset.bin"]


def test_pointer_scan_passes_a_materialized_asset(tmp_path):
    repo = _make_lfs_repo(tmp_path)

    def run(command, cwd):
        if command == ["git", "ls-files", "-z"]:
            return _tracked(".gitattributes", "asset.bin")
        return None

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        pointers = git_commands.find_lfs_pointer_files(str(repo))

    assert pointers == []


def test_pointer_scan_ignores_a_large_file_that_starts_like_a_pointer(tmp_path):
    repo = _make_lfs_repo(tmp_path)
    (repo / "asset.bin").write_bytes(LFS_POINTER + b"x" * 2048)

    def run(command, cwd):
        if command == ["git", "ls-files", "-z"]:
            return _tracked("asset.bin")
        return None

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        pointers = git_commands.find_lfs_pointer_files(str(repo))

    assert pointers == []


def test_pointer_scan_ignores_a_document_that_only_quotes_the_spec_url(tmp_path):
    repo = _make_lfs_repo(tmp_path)
    (repo / "asset.bin").write_bytes(
        b"version https://git-lfs.github.com/spec/v1\n"
        b"is the first line of every pointer file.\n"
    )

    def run(command, cwd):
        if command == ["git", "ls-files", "-z"]:
            return _tracked("asset.bin")
        return None

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        pointers = git_commands.find_lfs_pointer_files(str(repo))

    assert pointers == []


def test_pointer_scan_reads_paths_with_spaces_and_non_ascii_names(tmp_path):
    repo = _make_lfs_repo(tmp_path)
    awkward = "resource/모형 파일.STL"
    (repo / "resource").mkdir()
    (repo / awkward).write_bytes(LFS_POINTER)

    def run(command, cwd):
        if command == ["git", "ls-files", "-z"]:
            return _tracked("asset.bin", awkward)
        return None

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        pointers = git_commands.find_lfs_pointer_files(str(repo))

    assert pointers == [awkward]


def test_pointer_scan_reports_failure_instead_of_an_empty_result(tmp_path):
    _make_lfs_repo(tmp_path, pointer=True)

    with patch.object(git_commands, "_run_git_command", return_value=None):
        pointers = git_commands.find_lfs_pointer_files(str(tmp_path / "repo"))

    assert pointers is None


def _make_src_repo(src: Path, name: str, git_as_file=False) -> Path:
    repo = src / name
    repo.mkdir(parents=True)
    if git_as_file:
        (repo / ".git").write_text("gitdir: ../../.git/worktrees/" + name, encoding="utf-8")
    else:
        (repo / ".git").mkdir()
    (repo / ".gitattributes").write_text(
        "*.bin filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8"
    )
    (repo / "asset.bin").write_bytes(LFS_POINTER)
    return repo


def test_repo_scan_reports_and_skips_ignored_repositories(tmp_path):
    src = tmp_path / "src"
    for name in ("kept", "skipped"):
        _make_src_repo(src, name)

    def run(command, cwd):
        if command[:3] == ["git", "ls-files", "-z"] and len(command) > 3:
            return _tracked(".gitattributes")
        if command == ["git", "ls-files", "-z"]:
            return _tracked("asset.bin")
        return None

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        affected, unreadable = git_commands.find_repos_with_lfs_pointers(
            str(tmp_path), repos_to_ignore=["skipped"]
        )

    assert affected == [("kept", ["asset.bin"])]
    assert unreadable == []


def test_repo_scan_sees_a_worktree_whose_git_is_a_file(tmp_path):
    src = tmp_path / "src"
    _make_src_repo(src, "worktree", git_as_file=True)

    def run(command, cwd):
        if command[:3] == ["git", "ls-files", "-z"] and len(command) > 3:
            return _tracked(".gitattributes")
        if command == ["git", "ls-files", "-z"]:
            return _tracked("asset.bin")
        return None

    with patch.object(git_commands, "_run_git_command", side_effect=run):
        affected, unreadable = git_commands.find_repos_with_lfs_pointers(str(tmp_path))

    assert affected == [("worktree", ["asset.bin"])]


def test_repo_scan_reports_a_repository_it_could_not_read(tmp_path):
    src = tmp_path / "src"
    _make_src_repo(src, "broken")

    with patch.object(git_commands, "_run_git_command", return_value=None):
        affected, unreadable = git_commands.find_repos_with_lfs_pointers(str(tmp_path))

    assert affected == []
    assert unreadable == [("broken", "git ls-files failed")]

# ---------------------------------------------------------------------------
# gh_tokens -> credential helper
#
# This is the only consumer of gh_tokens left in the codebase, and the only
# `raisin git` behaviour that depends on load_configuration()'s tuple SHAPE
# rather than on _run_git_command, which every other test in this file mocks
# away. Without these two, transposing a field in _ensure_github_token() leaves
# the whole suite green and hands git an ignore list instead of a token.
# ---------------------------------------------------------------------------


def _write_config(tmp_path):
    """A config whose four fields are mutually distinguishable, so a wrong
    index is a wrong VALUE and not merely an empty one."""
    (tmp_path / "configuration_setting.yaml").write_text(
        "user_type: devel\n"
        "gh_tokens:\n"
        "  raionrobotics: sentinel-token\n"
        "packages_to_ignore:\n"
        "  - sentinel-package\n"
        "repos_to_ignore:\n"
        "  - sentinel-repo\n",
        encoding="utf-8",
    )


def test_ensure_github_token_returns_gh_tokens_not_a_neighbouring_field(
    tmp_path, monkeypatch
):
    from commands import globals as g

    _write_config(tmp_path)
    monkeypatch.setattr(g, "script_directory", str(tmp_path))

    assert git_commands._ensure_github_token() == {"raionrobotics": "sentinel-token"}


def test_the_configured_token_reaches_the_credential_helper(tmp_path, monkeypatch):
    from commands import globals as g

    _write_config(tmp_path)
    monkeypatch.setattr(g, "script_directory", str(tmp_path))

    seen = {}

    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def _spy(command, **kwargs):
        seen.update(kwargs.get("env") or {})
        return _Result()

    monkeypatch.setattr(git_commands.subprocess, "run", _spy)
    git_commands._run_git_command(["git", "status", "--porcelain"], str(tmp_path))

    assert seen["GIT_CONFIG_KEY_0"] == "credential.https://github.com.helper"
    assert "sentinel-token" in seen["GIT_CONFIG_VALUE_0"]
