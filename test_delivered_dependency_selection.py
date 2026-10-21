"""Exact delivered-only selection, exercising the real shell aggregator."""

import ctypes
import errno
import os
import subprocess

import pytest

from test_dependency_runner_exit import (
    BASH,
    ENVIRONMENT,
    SOURCE,
    package,
    pytestmark,
    workspace,
)


def run(workspace, tmp_path, *options):
    return subprocess.run(
        [BASH, str(workspace / SOURCE.name), *options],
        cwd=tmp_path,
        env=ENVIRONMENT,
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize("executable", [False, True])
def test_explicit_delivery_never_executes_conflicting_source(
    workspace, tmp_path, executable
):
    source = package(workspace, "same", "source", executable=True, status=7)
    selected = package(workspace, "same", "release", executable=executable)
    result = run(workspace, tmp_path, "-y", "--delivered-build-type=release")
    assert result.returncode == 0, result.stdout + result.stderr
    assert selected.read_text() == "called\n"
    assert not source.exists()


@pytest.mark.parametrize("selected_type", ["debug", "release"])
def test_explicit_build_type_is_not_lexically_first_other_type(
    workspace, tmp_path, selected_type
):
    debug = package(workspace, "same", "release", executable=True, build_type="debug")
    release = package(
        workspace, "same", "release", executable=False, build_type="release"
    )
    result = run(workspace, tmp_path, "--delivered-build-type=" + selected_type)
    selected, other = (
        (release, debug) if selected_type == "release" else (debug, release)
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert selected.read_text() == "called\n"
    assert not other.exists()


def test_absent_exact_type_never_falls_back_to_available_debug(workspace, tmp_path):
    debug = package(workspace, "same", "release", executable=True, build_type="debug")
    result = run(workspace, tmp_path, "--delivered-build-type=release")
    assert result.returncode == 0, result.stdout + result.stderr
    assert not debug.exists()


@pytest.mark.parametrize("selection", ["missing", "dangling", "file"])
def test_missing_selection_refuses_before_source_execution(
    workspace, tmp_path, selection
):
    source = package(workspace, "same", "source", executable=True)
    if selection != "missing":
        delivered = workspace / "release/install"
        delivered.parent.mkdir()
        if selection == "dangling":
            delivered.symlink_to("versions/absent")
        else:
            delivered.write_text("not a directory")
    result = run(workspace, tmp_path, "--delivered-build-type=release")
    assert result.returncode == 2, result.stdout + result.stderr
    assert not source.exists()


def test_existing_empty_selection_means_no_declared_script_work(workspace, tmp_path):
    (workspace / "release/install").mkdir(parents=True)
    result = run(workspace, tmp_path, "--delivered-build-type=release")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "No package dependency installers found" in result.stdout


@pytest.mark.parametrize(
    "value",
    [
        "",
        ".",
        "..",
        "../release",
        "a/b",
        "r*",
        "r?",
        "[r]",
        "a b",
        "a\tb",
        "a\nb",
        "-release",
        "a" * 65,
        "rélease",
        "Kernel",
        "ｒelease",
    ],
)
def test_unsafe_selector_refuses_before_any_installer(workspace, tmp_path, value):
    source = package(workspace, "same", "source", executable=True)
    selected = package(workspace, "same", "release", executable=True)
    result = run(workspace, tmp_path, "--delivered-build-type=" + value)
    assert result.returncode == 2, result.stdout + result.stderr
    assert result.stderr == "Invalid delivered dependency selection\n"
    assert not source.exists() and not selected.exists()


@pytest.mark.parametrize(
    "options",
    [
        ("--delivered-build-type", "release"),
        ("--delivered-build-typex=release",),
        ("--delivered-build-type=release", "--delivered-build-type=release"),
        ("--delivered-build-type=release", "--delivered-build-type=debug"),
        ("--unexpected", "--delivered-build-type=release"),
        ("--delivered-build-type=release", "--unexpected"),
    ],
)
def test_malformed_duplicate_or_unknown_explicit_options_have_zero_effects(
    workspace, tmp_path, options
):
    source = package(workspace, "same", "source", executable=True)
    selected = package(workspace, "same", "release", executable=True)
    result = run(workspace, tmp_path, *options)
    assert result.returncode == 2, result.stdout + result.stderr
    assert not source.exists() and not selected.exists()


@pytest.mark.parametrize("value", ["0", "RelWithDebInfo", "release-asan_1.2", "a" * 64])
def test_safe_literal_build_type_component_is_used_exactly(workspace, tmp_path, value):
    selected = package(workspace, "same", "release", executable=True, build_type=value)
    result = run(workspace, tmp_path, "--delivered-build-type=" + value, "-y")
    assert result.returncode == 0, result.stdout + result.stderr
    assert selected.read_text() == "called\n"


def test_selected_package_failure_is_not_masked_by_source_or_later_success(
    workspace, tmp_path
):
    source = package(workspace, "a_failed", "source", executable=True)
    failed = package(workspace, "a_failed", "release", executable=False, status=7)
    later = package(workspace, "z_success", "release", executable=True)
    result = run(workspace, tmp_path, "--delivered-build-type=release")
    assert result.returncode == 1, result.stdout + result.stderr
    assert failed.read_text() == later.read_text() == "called\n"
    assert not source.exists()


def test_legacy_source_precedence_and_ignored_options_stay_unchanged(
    workspace, tmp_path
):
    source = package(workspace, "same", "source", executable=True, status=7)
    selected = package(workspace, "same", "release", executable=True)
    result = run(workspace, tmp_path, "-y", "previously-ignored-argument")
    assert result.returncode == 1, result.stdout + result.stderr
    assert source.read_text() == "called\n"
    assert not selected.exists()


def test_legacy_still_uses_first_available_build_type(workspace, tmp_path):
    first = package(
        workspace, "same", "release", executable=True, status=7, build_type="debug"
    )
    later = package(workspace, "same", "release", executable=True)
    result = run(workspace, tmp_path, "-y")
    assert result.returncode == 1, result.stdout + result.stderr
    assert first.read_text() == "called\n"
    assert not later.exists()


def test_explicit_selection_consumes_the_real_release_selector(workspace, tmp_path):
    selected = package(workspace, "same", "release", executable=True)
    delivered = workspace / "release/install"
    generation = workspace / "release/versions/0001-inert-1.0.0"
    generation.parent.mkdir()
    delivered.rename(generation)
    delivered.symlink_to("versions/0001-inert-1.0.0")
    result = run(workspace, tmp_path, "--delivered-build-type=release")
    assert result.returncode == 0, result.stdout + result.stderr
    assert selected.read_text() == "called\n"
    assert delivered.is_symlink()


@pytest.mark.parametrize("workspace_first", [False, True])
def test_detached_runner_uses_only_explicit_workspace(
    workspace, tmp_path, workspace_first
):
    selected_root = tmp_path / "selected-workspace"
    selected_root.mkdir()
    selected = package(selected_root, "same", "release", executable=False)
    source = package(selected_root, "same", "source", executable=True, status=7)
    unrelated = package(workspace, "same", "release", executable=True, status=7)
    options = [
        "--delivered-build-type=release",
        "--delivered-workspace=" + str(selected_root),
    ]
    if workspace_first:
        options.reverse()
    result = run(workspace, tmp_path, *options)
    assert result.returncode == 0, result.stdout + result.stderr
    assert selected.read_text() == "called\n"
    assert not source.exists() and not unrelated.exists()


@pytest.mark.parametrize(
    "suffix", ["", "/", "/.", "/..", "//child", "/missing", "/a b", "/a\nb", "/é"]
)
def test_noncanonical_or_missing_workspace_refuses_before_work(
    workspace, tmp_path, suffix
):
    marker = package(workspace, "same", "release", executable=True)
    root = tmp_path / "selected-workspace"
    root.mkdir()
    value = "" if not suffix else str(root) + suffix
    result = run(
        workspace,
        tmp_path,
        "--delivered-build-type=release",
        "--delivered-workspace=" + value,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert result.stderr == "Invalid delivered dependency selection\n"
    assert not marker.exists()


@pytest.mark.parametrize(
    "kind", ["relative", "root", "symlink", "file", "long", "deep"]
)
def test_unsafe_workspace_kind_refuses_before_work(workspace, tmp_path, kind):
    marker = package(workspace, "same", "release", executable=True)
    target = tmp_path / "target"
    target.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    regular = tmp_path / "not-directory"
    regular.write_text("fixture")
    deep = tmp_path.joinpath(*(["a"] * 64))
    deep.mkdir(parents=True)
    values = {
        "relative": "target",
        "root": "/",
        "symlink": str(alias),
        "file": str(regular),
        "long": "/" + "a" * 2048,
        "deep": str(deep),
    }
    result = run(
        workspace,
        tmp_path,
        "--delivered-build-type=release",
        "--delivered-workspace=" + values[kind],
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert result.stderr == "Invalid delivered dependency selection\n"
    assert not marker.exists()


@pytest.mark.parametrize(
    "options",
    [
        ("--delivered-workspace=/tmp",),
        ("--delivered-workspace", "/tmp", "--delivered-build-type=release"),
        ("--delivered-workspacex=/tmp", "--delivered-build-type=release"),
        (
            "--delivered-workspace=/tmp",
            "--delivered-workspace=/tmp",
            "--delivered-build-type=release",
        ),
    ],
)
def test_workspace_options_need_build_type_and_exact_single_spelling(
    workspace, tmp_path, options
):
    source = package(workspace, "same", "source", executable=True)
    selected = package(workspace, "same", "release", executable=True)
    result = run(workspace, tmp_path, *options)
    assert result.returncode == 2, result.stdout + result.stderr
    assert not source.exists() and not selected.exists()


def test_sealed_runner_snapshot_ignores_replaced_workspace_script(workspace, tmp_path):
    import fcntl  # Linux-only test; preserve collection on other supported hosts.

    selected_root = tmp_path / "selected-workspace"
    selected_root.mkdir()
    selected = package(selected_root, "same", "release", executable=True)
    replaced = selected_root / SOURCE.name
    replaced.write_bytes(SOURCE.read_bytes())
    with open(replaced, "rb") as original:
        raw = original.read()
    # This Python3.9 test build omits memfd/seal names despite a capable kernel.
    # Call libc with Linux UAPI values; no alternate execution or skipped proof.
    create = ctypes.CDLL(None, use_errno=True).memfd_create
    create.argtypes = (ctypes.c_char_p, ctypes.c_uint)
    create.restype = ctypes.c_int
    fd = create(b"dependency-runner-test", 0x0001 | 0x0002)
    assert fd >= 0, os.strerror(ctypes.get_errno())
    try:
        assert os.write(fd, raw) == len(raw)
        fcntl.fcntl(fd, 1033, 0x000F)  # F_ADD_SEALS: WRITE/GROW/SHRINK/SEAL
        assert fcntl.fcntl(fd, 1034) == 0x000F  # F_GET_SEALS
        with pytest.raises(OSError) as sealed:
            os.pwrite(fd, b"X", 0)
        assert sealed.value.errno == errno.EPERM
        replacement = selected_root / "replacement.sh"
        replacement.write_text("exit 73\n")
        replacement.replace(replaced)
        result = subprocess.run(
            [
                BASH,
                "/proc/self/fd/" + str(fd),
                "--delivered-build-type=release",
                "--delivered-workspace=" + str(selected_root),
                "-y",
            ],
            cwd=tmp_path,
            env=ENVIRONMENT,
            capture_output=True,
            text=True,
            timeout=10,
            pass_fds=(fd,),
        )
    finally:
        os.close(fd)
    assert result.returncode == 0, result.stdout + result.stderr
    assert selected.read_text() == "called\n"
    assert replaced.read_text() == "exit 73\n"
