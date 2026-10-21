"""Real managed prefix copies; no unit, network, root grant or activation."""

import os
from pathlib import Path
import stat
import struct

import pytest

from raisin_ota import runtime_prefix as runtime
from raisin_ota.client import OtaContext
from raisin_ota import install_tree


def identity(path):
    info = path.lstat()
    return tuple(
        getattr(info, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def snapshot(root):
    result, pending = {}, [root]
    while pending:
        path = pending.pop()
        if not path.exists() and not path.is_symlink():
            continue
        info = path.lstat()
        content = (
            os.readlink(path)
            if stat.S_ISLNK(info.st_mode)
            else path.read_bytes() if stat.S_ISREG(info.st_mode) else None
        )
        result[str(path)] = identity(path), content
        if stat.S_ISDIR(info.st_mode):
            pending.extend(path.iterdir())
    return result


def write(root, name, data=b"payload"):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o644)
    return path


@pytest.fixture
def marked(tmp_path):
    from types import SimpleNamespace

    workspace, home = tmp_path / "workspace", tmp_path / "home"
    workspace.mkdir()
    home.mkdir()
    prefix = workspace / "install"
    prefix.mkdir(mode=0o700)
    marker = prefix / ".incomplete"
    marker.touch(mode=0o600)
    context = OtaContext(workspace, "ubuntu", "24.04", "x86_64")
    selected = workspace / "release/versions/0002-chosen"
    selected.mkdir(parents=True)
    for name in ("primary", "library"):
        for build in ("release", "debug"):
            package = context.package_dir(selected, name, build)
            write(package, "lib/" + name + ".so", (name + "-" + build).encode())
            write(package, "release.txt", name.encode())
    binary = context.package_dir(selected, "primary", "release")
    write(binary, "bin/node", b"not executed")
    write(binary, "scripts/primary/start.sh", b"not executed")
    write(binary, "resource/primary/resource/params.yaml", b"default")
    write(home, ".raisin/primary/resource/params.yaml", b"local")
    write(home, ".raisin/other/resource/custom.yaml", b"other device")
    write(home, ".raisin/unrelated.json", b"not an overlay")
    write(selected, ".staging", b"")
    old = workspace / "release/versions/0001-old"
    old.mkdir()
    (workspace / "release/install").symlink_to("versions/0001-old")
    write(workspace, "src/primary/lib/forbidden.so", b"source ignored")
    return SimpleNamespace(
        context=context,
        workspace=workspace,
        home=home,
        prefix=prefix,
        marker=marker,
        selected=selected,
        package=binary,
    )


def populate(lab, **changes):
    options = dict(
        selected_path=lab.selected,
        prefix=lab.prefix,
        build_type="release",
        home=lab.home,
    )
    options.update(changes)
    return runtime.populate_marked(lab.context, **options)


def test_explicit_generation_build_and_overrides_preserve_owned_root_and_marker(marked):
    root, marker = identity(marked.prefix)[:5], identity(marked.marker)
    before = snapshot(marked.selected), snapshot(marked.home)
    result = populate(marked)
    assert result == [
        marked.context.package_dir(marked.selected, name, "release")
        for name in ("library", "primary")
    ]
    assert identity(marked.prefix)[:5] == root and identity(marked.marker) == marker
    assert marked.marker.read_bytes() == b""
    assert (marked.prefix / "lib/primary.so").read_bytes() == b"primary-release"
    assert (marked.prefix / "lib/library.so").read_bytes() == b"library-release"
    assert (marked.prefix / "release.txt").read_bytes() == b"primary"
    assert (
        marked.prefix / "resource/primary/resource/params.yaml"
    ).read_bytes() == b"local"
    assert (
        marked.prefix / "resource/other/resource/custom.yaml"
    ).read_bytes() == b"other device"
    assert stat.S_IMODE((marked.prefix / "bin/node").stat().st_mode) == 0o755
    assert (
        stat.S_IMODE((marked.prefix / "scripts/primary/start.sh").stat().st_mode)
        == 0o755
    )
    assert not (marked.prefix / "lib/forbidden.so").exists()
    assert (
        not (marked.prefix / ".staging").exists()
        and not (marked.prefix / "unrelated.json").exists()
    )
    assert (snapshot(marked.selected), snapshot(marked.home)) == before


@pytest.mark.parametrize(
    "fault",
    [
        "missing-prefix",
        "missing-marker",
        "nonempty-prefix",
        "prefix-mode",
        "marker-mode",
        "marker-content",
        "marker-hardlink",
        "prefix-link",
        "missing-build",
        "source-link",
        "source-hardlink",
        "source-fifo",
        "marker-collision",
        "resource-link",
        "resource-directory-link",
        "platform-escape",
        "build-escape",
        "selected-escape",
        "selected-file",
        "empty-selection",
    ],
)
def test_invalid_plan_refuses_before_any_prefix_write(marked, fault):
    changes = {}
    if fault == "missing-prefix":
        marked.marker.unlink()
        marked.prefix.rmdir()
    elif fault == "missing-marker":
        marked.marker.unlink()
    elif fault == "nonempty-prefix":
        write(marked.prefix, "foreign", b"preserve")
    elif fault == "prefix-mode":
        marked.prefix.chmod(0o755)
    elif fault == "marker-mode":
        marked.marker.chmod(0o644)
    elif fault == "marker-content":
        marked.marker.write_bytes(b"not empty")
    elif fault == "marker-hardlink":
        os.link(marked.marker, marked.workspace / "alias")
    elif fault == "prefix-link":
        retained = marked.workspace / "retained"
        marked.prefix.rename(retained)
        marked.prefix.symlink_to(retained)
    elif fault == "missing-build":
        source = marked.context.package_dir(marked.selected, "primary", "release")
        source.rename(source.with_name("other-build"))
    elif fault.startswith("source-"):
        path = marked.package / "unsafe"
        if fault == "source-link":
            path.symlink_to(marked.home)
        elif fault == "source-hardlink":
            os.link(marked.package / "release.txt", path)
        else:
            os.mkfifo(path)
    elif fault == "marker-collision":
        write(marked.package, ".incomplete", b"")
    elif fault == "resource-link":
        path = marked.home / ".raisin/primary/resource/link"
        path.symlink_to(marked.package)
    elif fault == "resource-directory-link":
        path = marked.home / ".raisin/primary/resource"
        path.rename(path.with_name("real"))
        path.symlink_to("real")
    elif fault == "platform-escape":
        marked.context = OtaContext(marked.workspace, "../escape", "24.04", "x86_64")
    elif fault == "build-escape":
        changes["build_type"] = "../release"
    elif fault == "selected-escape":
        changes["selected_path"] = marked.home
    elif fault == "selected-file":
        write(marked.selected, "unexpected-file")
    else:
        empty = marked.workspace / "release/versions/0003-empty"
        empty.mkdir()
        changes["selected_path"] = empty
    before = snapshot(marked.prefix)
    with pytest.raises((ValueError, OSError)):
        populate(marked, **changes)
    assert snapshot(marked.prefix) == before


@pytest.mark.parametrize("fault", ["copy", "permission", "cancel"])
def test_partial_io_failure_never_removes_negative_evidence(marked, monkeypatch, fault):
    root, marker = identity(marked.prefix)[:5], identity(marked.marker)
    real_copy, real_chmod, injected = runtime.shutil.copy2, Path.chmod, []

    def copy(source, target, *args, **kwargs):
        result = real_copy(source, target, *args, **kwargs)
        if not injected:
            injected.append(True)
            if fault == "cancel":
                raise KeyboardInterrupt("fixture cancellation")
            if fault == "copy":
                raise OSError("fixture partial copy")
        return result

    def chmod(path, mode, *args, **kwargs):
        if str(path).endswith("/scripts/primary/start.sh") and mode & 0o111:
            injected.append(True)
            raise OSError("fixture script permission failure")
        return real_chmod(path, mode, *args, **kwargs)

    if fault == "permission":
        # pathlib3.9 caches its accessor: inject at the API actually called.
        monkeypatch.setattr(Path, "chmod", chmod)
    else:
        monkeypatch.setattr(runtime.shutil, "copy2", copy)
    error = KeyboardInterrupt if fault == "cancel" else OSError
    with pytest.raises(error):
        populate(marked)
    assert injected and len(list(marked.prefix.iterdir())) > 1
    assert identity(marked.prefix)[:5] == root and identity(marked.marker) == marker


def test_input_changed_during_copy_cannot_be_reported_as_success(marked, monkeypatch):
    original, changed = runtime.shutil.copy2, []

    def copy(source, target, *args, **kwargs):
        result = original(source, target, *args, **kwargs)
        if not changed:
            changed.append(True)
            write(
                marked.home, ".raisin/other/resource/custom.yaml", b"changed in flight"
            )
        return result

    monkeypatch.setattr(runtime.shutil, "copy2", copy)
    marker = identity(marked.marker)
    with pytest.raises(ValueError):
        populate(marked)
    assert changed and identity(marked.marker) == marker


@pytest.mark.parametrize("kind", ["ignored-files", "resource-less-directories"])
def test_discovery_also_spends_the_bounded_scan_budget(marked, monkeypatch, kind):
    monkeypatch.setattr(runtime, "_MANAGED_MAX_ENTRIES", 128, raising=False)
    for index in range(256):
        path = marked.home / ".raisin" / ("unrelated-" + str(index))
        if kind == "ignored-files":
            path.write_bytes(b"unrelated")
        else:
            path.mkdir()
    before = snapshot(marked.prefix)
    with pytest.raises(ValueError):
        populate(marked)
    assert snapshot(marked.prefix) == before


def test_actual_legacy_hardlink_clone_is_not_a_fresh_managed_candidate(marked):
    release = marked.workspace / "release"
    install_tree.commit_version(release, "chosen")
    clone = install_tree.stage_version(release, "next")
    payload = marked.context.package_dir(clone, "primary", "release") / "release.txt"
    original = marked.package / "release.txt"
    assert (
        payload.stat().st_nlink > 1 and payload.stat().st_ino == original.stat().st_ino
    )
    before = snapshot(marked.prefix)
    with pytest.raises(ValueError):
        populate(marked, selected_path=clone)
    assert snapshot(marked.prefix) == before


def test_debug_request_does_not_copy_release_files(marked):
    populate(marked, build_type="debug")
    assert (marked.prefix / "lib/primary.so").read_bytes() == b"primary-debug"
    assert not (marked.prefix / "bin/node").exists()
    assert marked.marker.read_bytes() == b""


@pytest.mark.parametrize("name", [".sh", "nested/.sh", "start.sh"])
def test_shell_pattern_includes_dot_sh_but_not_other_scripts(marked, name):
    write(marked.package, "scripts/" + name, b"not executed")
    write(marked.package, "scripts/keep.txt", b"not executable")
    populate(marked)
    assert stat.S_IMODE((marked.prefix / "scripts" / name).stat().st_mode) == 0o755
    assert stat.S_IMODE((marked.prefix / "scripts/keep.txt").stat().st_mode) == 0o644


def test_unselected_build_payload_is_not_followed(marked):
    debug = marked.context.package_dir(marked.selected, "primary", "debug")
    (debug / "ignored-link").symlink_to(marked.home)
    populate(marked)
    assert (marked.prefix / "lib/primary.so").read_bytes() == b"primary-release"
    assert not (marked.prefix / "ignored-link").exists()


@pytest.mark.parametrize("kind", ["no-base", "no-resource", "nested-only"])
def test_optional_resource_discovery_remains_one_level(marked, kind):
    base = marked.home / ".raisin"
    if kind == "no-base":
        base.rename(marked.home / "saved-resources")
    else:
        for package in ("primary", "other"):
            path = base / package / "resource"
            path.rename(path.with_name("saved"))
        if kind == "nested-only":
            write(base, "backup/nested/resource/forbidden", b"not an overlay")
    populate(marked)
    assert (
        marked.prefix / "resource/primary/resource/params.yaml"
    ).read_bytes() == b"default"
    assert not (marked.prefix / "resource/other").exists()
    assert not (marked.prefix / "resource/nested").exists()


@pytest.mark.parametrize(
    "fault",
    ["home-overlap", "empty-build", "marker-link", "prefix-owner", "no-acl-capability"],
)
def test_additional_preflight_failures_do_not_write(marked, monkeypatch, fault):
    changes = {}
    if fault == "home-overlap":
        changes["home"] = marked.prefix
    elif fault == "empty-build":
        source = marked.package
        source.rename(source.with_name("saved"))
        source.mkdir()
    elif fault == "marker-link":
        target = marked.workspace / "other-marker"
        marked.marker.rename(target)
        marked.marker.symlink_to(target)
    elif fault == "prefix-owner":
        current = os.geteuid()
        monkeypatch.setattr(os, "geteuid", lambda: current + 1)
    else:
        monkeypatch.delattr(os, "listxattr")
    before = snapshot(marked.prefix)
    with pytest.raises((ValueError, OSError)):
        populate(marked, **changes)
    assert snapshot(marked.prefix) == before


@pytest.mark.parametrize("where", ["source", "prefix"])
def test_extended_acl_is_refused_without_repairs(marked, where):
    target = marked.package if where == "source" else marked.prefix
    acl = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", *part)
        for part in (
            (1, 7, 0xFFFFFFFF),
            (2, 0, os.geteuid() + 1),
            (4, 0, 0xFFFFFFFF),
            (16, 0, 0xFFFFFFFF),
            (32, 0, 0xFFFFFFFF),
        )
    )
    os.setxattr(target, "system.posix_acl_default", acl)
    before = snapshot(marked.prefix)
    with pytest.raises(ValueError):
        populate(marked)
    assert snapshot(marked.prefix) == before
    assert os.getxattr(target, "system.posix_acl_default") == acl


def test_file_directory_merge_conflict_never_becomes_silent_nested_copy(marked):
    library = marked.context.package_dir(marked.selected, "library", "release")
    write(library, "collision/keep", b"first package")
    write(marked.package, "collision", b"file cannot replace directory")
    before = identity(marked.marker)
    with pytest.raises((ValueError, OSError)):
        populate(marked)
    assert identity(marked.marker) == before
    assert not (marked.prefix / "collision/collision").exists()


def test_source_change_before_first_write_is_not_rebaselined(marked, monkeypatch):
    original, changed = runtime._managed_prefix, []

    def check(*args, **kwargs):
        result = original(*args, **kwargs)
        if not changed:
            changed.append(True)
        elif len(changed) == 1:
            changed.append(True)
            write(
                marked.home,
                ".raisin/other/resource/custom.yaml",
                b"changed before copies",
            )
        return result

    monkeypatch.setattr(runtime, "_managed_prefix", check)
    with pytest.raises(ValueError):
        populate(marked)
    assert len(changed) == 2 and marked.marker.is_file()


@pytest.mark.parametrize("directory", ["bin", "scripts"])
def test_output_scan_permission_error_cannot_skip_executable_normalization(
    marked, monkeypatch, directory
):
    original, injected = os.scandir, []
    target = marked.prefix / directory
    root, marker = identity(marked.prefix)[:5], identity(marked.marker)
    inputs = snapshot(marked.selected), snapshot(marked.home)

    def scandir(path):
        if Path(path) == target:
            injected.append(True)
            raise PermissionError("fixture output scan denied")
        return original(path)

    monkeypatch.setattr(os, "scandir", scandir)
    with pytest.raises(OSError):
        populate(marked)
    assert injected and identity(marked.marker) == marker
    assert identity(marked.prefix)[:5] == root
    assert (snapshot(marked.selected), snapshot(marked.home)) == inputs
