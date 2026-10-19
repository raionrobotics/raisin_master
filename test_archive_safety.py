"""Real ZIP/filesystem regressions; every target is a temporary fixture."""

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import zipfile

import pytest

from raisin_ota import build_machine, client


def package(path, entries):
    with zipfile.ZipFile(path, "w") as contents:
        for name, payload, mode in entries:
            header = zipfile.ZipInfo(name)
            header.create_system = 3
            header.external_attr = mode << 16
            contents.writestr(header, payload)


@pytest.mark.parametrize("caller", ["client", "build-machine"])
@pytest.mark.parametrize(
    "name",
    [
        "absolute",
        "../victim",
        "sub/../../victim",
        "C:/victim",
        "C:relative",
        "\\server\\share\\victim",
        "sub\\..\\victim",
        "bin/\x7ftool",
        "bin/\x85tool",
    ],
)
def test_unsafe_names_refuse_before_content_or_permission_effects(
    tmp_path, caller, name
):
    victim = tmp_path / "victim"
    victim.write_bytes(b"outside content")
    victim.chmod(0o700)
    into = tmp_path / "into"
    into.mkdir()
    sentinel = into / "sentinel"
    sentinel.write_bytes(b"keep previous tree")
    name = str(victim) if name == "absolute" else name
    path = tmp_path / "package.zip"
    package(
        path,
        [
            ("release.yaml", b"version: 1.0.0\ndependencies: []\n", 0o100644),
            ("bin/tool", b"not extracted before refusal", 0o100755),
            (name, b"outside overwrite attempt", 0o100600),
        ],
    )
    if caller == "client":
        assert (
            client._extract_and_read_deps(path, into, "fixture", "1.0.0", strict=True)
            is None
        )
    else:
        with pytest.raises(build_machine.FetchRefused):
            build_machine._unpack(path, into)
    assert victim.read_bytes() == b"outside content"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o700
    assert sentinel.read_bytes() == b"keep previous tree"
    assert not (into / "bin").exists()


@pytest.mark.parametrize("alias", ["file-symlink", "parent-symlink", "hardlink"])
def test_builder_refuses_preexisting_aliases_before_writing_external_inode(
    tmp_path, alias
):
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "tool"
    victim.write_bytes(b"outside")
    victim.chmod(0o700)
    into = tmp_path / "into"
    into.mkdir()
    if alias == "parent-symlink":
        (into / "bin").symlink_to(outside, target_is_directory=True)
    else:
        (into / "bin").mkdir()
        if alias == "file-symlink":
            (into / "bin" / "tool").symlink_to(victim)
        else:
            os.link(victim, into / "bin" / "tool")
    path = tmp_path / "package.zip"
    package(path, [("bin/tool", b"must not overwrite external alias", 0o100644)])
    with pytest.raises(build_machine.FetchRefused):
        build_machine._unpack(path, into)
    assert victim.read_bytes() == b"outside"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o700


def test_direct_mode_restoration_validates_all_names_before_first_chmod(tmp_path):
    into = tmp_path / "into"
    into.mkdir()
    local = into / "tool"
    local.write_bytes(b"local")
    local.chmod(0o700)
    victim = tmp_path / "victim"
    victim.write_bytes(b"outside")
    victim.chmod(0o700)
    path = tmp_path / "package.zip"
    package(path, [("tool", b"local", 0o100600), (str(victim), b"outside", 0o100600)])
    with zipfile.ZipFile(path) as contents:
        with pytest.raises(zipfile.BadZipFile):
            client.restore_modes(contents, into)
    assert stat.S_IMODE(local.stat().st_mode) == 0o700
    assert stat.S_IMODE(victim.stat().st_mode) == 0o700


def test_normalized_duplicate_file_names_are_refused_before_extraction(tmp_path):
    into = tmp_path / "into"
    into.mkdir()
    path = tmp_path / "package.zip"
    package(
        path, [("bin/tool", b"first", 0o100755), ("bin/./tool", b"second", 0o100644)]
    )
    with pytest.raises(build_machine.FetchRefused):
        build_machine._unpack(path, into)
    assert list(into.iterdir()) == []


def test_valid_dot_prefix_and_permission_mask_keep_existing_contract(tmp_path):
    into = tmp_path / "into"
    path = tmp_path / "package.zip"
    package(
        path,
        [
            ("./release.yaml", b"version: 1.0.0\ndependencies: []\n", 0o100644),
            ("./bin/tool", b"new executable", 0o104777),
            ("lib/plain", b"plain", 0o100644),
        ],
    )
    assert client._extract_and_read_deps(path, into, "fixture", "1.0.0", strict=True)
    assert (into / "bin" / "tool").read_bytes() == b"new executable"
    assert stat.S_IMODE((into / "bin" / "tool").stat().st_mode) == 0o755
    assert stat.S_IMODE((into / "lib" / "plain").stat().st_mode) == 0o644


@pytest.mark.parametrize("kind", ["fifo", "parent-file", "target-directory"])
def test_builder_preflight_rejects_special_or_incompatible_existing_nodes(
    tmp_path, kind
):
    into = tmp_path / "into"
    into.mkdir()
    if kind == "parent-file":
        (into / "bin").write_bytes(b"not a directory")
    else:
        (into / "bin").mkdir()
        if kind == "fifo":
            os.mkfifo(into / "bin" / "tool")
        else:
            (into / "bin" / "tool").mkdir()
    path = tmp_path / "package.zip"
    package(path, [("bin/tool", b"new", 0o100755)])
    # Preflight only while RED: do not let extractall block opening a FIFO.
    with zipfile.ZipFile(path) as contents:
        with pytest.raises(build_machine.FetchRefused):
            build_machine._entries_within(contents, into)


@pytest.mark.parametrize("error", [PermissionError, OSError])
def test_mode_preflight_io_error_warns_and_other_files_still_restore(
    tmp_path, monkeypatch, capsys, error
):
    into = tmp_path / "into"
    into.mkdir()
    bad = into / "unreadable"
    bad.write_bytes(b"bad")
    good = into / "good"
    good.write_bytes(b"good")
    good.chmod(0o600)
    path = tmp_path / "package.zip"
    package(path, [("unreadable", b"bad", 0o100755), ("good", b"good", 0o100755)])
    original = Path.lstat

    def lstat(self, *args, **kwargs):
        if self == bad:
            raise error("fixture I/O refusal")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    with zipfile.ZipFile(path) as contents:
        client.restore_modes(contents, into)
    assert "Could not set the mode" in capsys.readouterr().out
    assert stat.S_IMODE(good.stat().st_mode) == 0o755


def write_only_fixture(root):
    assert os.geteuid() != 0
    into = root / "into"
    into.mkdir()
    target = into / "tool"
    target.write_bytes(b"old")
    target.chmod(0o200)
    path = root / "package.zip"
    package(path, [("tool", b"new", 0o100755)])
    build_machine._unpack(path, into)
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert target.read_bytes() == b"new"


def test_owned_write_only_builder_file_regains_executable_mode(tmp_path):
    if os.geteuid() != 0:
        write_only_fixture(tmp_path)
    else:
        # Root would bypass read restrictions. Exercise a real unprivileged
        # child in its own private temporary fixture instead of skipping.
        with tempfile.TemporaryDirectory(prefix="raisin-zip-mode-") as scratch:
            os.chown(scratch, 2001, 2001)
            script = (
                "from pathlib import Path; import sys; "
                "from test_archive_safety import write_only_fixture; "
                "write_only_fixture(Path(sys.argv[1]))"
            )
            result = subprocess.run(
                [sys.executable, "-c", script, scratch],
                user=2001,
                group=2001,
                extra_groups=[],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert result.returncode == 0, result.stderr


def test_non_descriptor_platform_retains_mode_restoration(tmp_path, monkeypatch):
    from raisin_ota import archive_safety

    into = tmp_path / "into"
    into.mkdir()
    target = into / "tool"
    target.write_bytes(b"content")
    target.chmod(0o200)
    path = tmp_path / "package.zip"
    package(path, [("tool", b"content", 0o100755)])
    monkeypatch.setattr(archive_safety, "_DESCRIPTOR_CHMOD", False, raising=False)

    def unsupported(*args, **kwargs):
        raise AssertionError("platform does not provide nofollow directory FDs")

    monkeypatch.setattr(archive_safety.os, "open", unsupported)
    with zipfile.ZipFile(path) as contents:
        client.restore_modes(contents, into)
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


@pytest.mark.parametrize(
    "name", ["bin/tool:stream", "bin/CON", "bin/trailing.", "bin/trailing "]
)
def test_windows_normalization_aliases_are_rejected_before_effects(
    tmp_path, monkeypatch, name
):
    from raisin_ota import archive_safety

    monkeypatch.setattr(archive_safety, "_WINDOWS_NAMES", True, raising=False)
    into = tmp_path / "into"
    into.mkdir()
    sentinel = into / "sentinel"
    sentinel.write_bytes(b"keep")
    path = tmp_path / "package.zip"
    package(path, [(name, b"bad", 0o100755)])
    assert client._extract_and_read_deps(path, into, "fixture", "1.0.0") is None
    assert sentinel.read_bytes() == b"keep"
