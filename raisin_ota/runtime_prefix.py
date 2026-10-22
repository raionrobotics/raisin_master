"""The runtime prefix, assembled from the packages OTA delivered.

`release/install` holds what was delivered, one tree per package and platform;
nothing executes from it. `<workspace>/install` is what a node runs: every
package merged into one prefix, with the device's own configuration laid on top.
This module builds the second from the first.

It knows nothing about `src/` or compiling, and that is the boundary it exists
to hold. `raisin setup` used to be the only way to build this prefix, and setup
also prepares a source build, so an agent that ran it inherited every source
check: a robot with a leftover `src/` failed its install in the guard that
compares sources against binaries. A robot runs what it was delivered, whatever
else is in the workspace.

Two callers, deliberately the same code:

- the agent calls `assemble`, and nothing else;
- `raisin setup` calls the pieces, with its source overlay between them, and
  passes the repositories it builds from source as `skip`.

Here rather than in `commands/`, because the agent can only call what is
installed with it. `commands/` is not packaged, and the checkout on a robot is
whatever provisioning cloned, never updated by OTA; this package is pinned by
the agent and arrives with it.
"""

import glob
import os
import shutil
import stat
from pathlib import Path
from typing import Collection, List

from .client import OtaContext, safe_component

MANAGED_PREFIX_MAX_ENTRIES = 65536
_MANAGED_ACL = {"system.posix_acl_access", "system.posix_acl_default"}
_MANAGED_REASONS = frozenset({
    "invalid_input", "unsafe_entry", "hardlinked_input", "extended_acl",
    "acl_unavailable", "invalid_prefix", "invalid_marker", "invalid_build",
    "missing_build", "no_packages", "entry_limit", "input_changed", "output_changed",
})


class RuntimePrefixError(ValueError):
    """A fixed, path-free refusal at the managed population boundary."""

    def __init__(self, reason_code="invalid_input"):
        self.reason_code = (
            reason_code if type(reason_code) is str and reason_code in _MANAGED_REASONS
            else "invalid_input"
        )
        super().__init__("runtime_prefix_unverified:" + self.reason_code)


def deploy_packages(
    context: OtaContext, prefix: Path, skip: Collection[str] = ()
) -> List[Path]:
    """Copy every delivered package built for this platform into `prefix`.

    Build types of one package are merged into the same prefix. Packages named
    in `skip` are left out.

    Raises on the first copy that fails. A prefix missing packages and
    reported as deployed is a node that starts on half a release.

    Returns:
        The package directories copied, in the order they were copied.
    """
    pattern = os.path.join(
        context.workspace,
        "release",
        "install",
        "*",
        context.os_type,
        context.os_version,
        context.architecture,
        "*",
    )
    deployed = []
    for source in glob.glob(pattern):
        source = Path(source)
        if not source.is_dir():
            continue
        # .../install/<package>/<os>/<os_version>/<arch>/<build_type>
        if source.parents[3].name in skip:
            continue
        shutil.copytree(source, prefix, dirs_exist_ok=True)
        deployed.append(source)

    _make_executable(prefix / "bin")
    return deployed


def make_scripts_executable(prefix: Path) -> None:
    """Mark every `*.sh` under `<prefix>/scripts` executable."""
    scripts_root = prefix / "scripts"
    if not scripts_root.is_dir():
        return
    for script_path in scripts_root.rglob("*.sh"):
        if script_path.is_file():
            try:
                mode = script_path.stat().st_mode
                script_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except OSError:
                print(f"⚠️  Failed to set executable: {script_path}")


def copy_device_resources(prefix: Path, home: Path) -> None:
    """Lay `<home>/.raisin/<name>/resource` over `<prefix>/resource/<name>/resource`.

    `.raisin/<name>/resource` holds the files changed on this one machine
    (raisin_robot_properties/README.md, "Shared resources"), so it goes in
    after the packages and replaces their defaults. Only the first level names
    a package: a `resource` folder inside an override is part of it, not
    another package. A name no package ships a resource for still gets its
    folder. `home` is passed rather than read because the agent's own HOME is
    not the workspace owner's.
    """
    for source_dir in sorted((Path(home) / ".raisin").glob("*/resource")):
        if not source_dir.is_dir():
            continue
        dest_dir = Path(prefix) / "resource" / source_dir.parent.name / "resource"
        shutil.copytree(source_dir, dest_dir, dirs_exist_ok=True)


def assemble(context: OtaContext, home: Path) -> List[Path]:
    """Build `<workspace>/install` from scratch out of the delivered packages.

    What a node needs and nothing a compiler needs: no generated headers, no
    CMake files, and no reading of `src/`.

    Returns:
        The package directories copied.
    """
    prefix = Path(context.workspace) / "install"
    if prefix.exists():
        shutil.rmtree(prefix)
    prefix.mkdir(parents=True)

    deployed = deploy_packages(context, prefix)
    make_scripts_executable(prefix)
    copy_device_resources(prefix, home)
    return deployed


def _make_executable(directory: Path) -> None:
    if not directory.exists():
        return
    for root, _dirs, files in os.walk(directory):
        for file in files:
            os.chmod(os.path.join(root, file), 0o755)


def _managed_require(condition, reason="invalid_input"):
    if not condition:
        raise RuntimePrefixError(reason)


def _managed_identity(info):
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


def _managed_node(path):
    info = path.lstat()
    _managed_require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "unsafe_entry")
    _managed_require(not stat.S_ISREG(info.st_mode) or info.st_nlink == 1, "hardlinked_input")
    _managed_require(
        not _MANAGED_ACL & set(os.listxattr(path, follow_symlinks=False)), "extended_acl"
    )
    return info


def _managed_real_directory(path):
    _managed_require(path.is_absolute() and stat.S_ISDIR(_managed_node(path).st_mode))
    try:
        _managed_require(path.resolve(strict=True) == path)
    except RuntimeError:  # pathlib3.9/3.12 reports resolution loops this way.
        raise RuntimePrefixError("unsafe_entry") from None


def _managed_prefix(context, prefix, *, empty):
    _managed_require(callable(getattr(os, "listxattr", None)), "acl_unavailable")
    _managed_real_directory(Path(context.workspace))
    _managed_require(prefix == Path(context.workspace) / "install", "invalid_prefix")
    _managed_real_directory(prefix)
    root = _managed_identity(prefix.lstat())
    owner = os.geteuid(), os.getegid()
    _managed_require(root[2] == stat.S_IFDIR | 0o700 and root[3:5] == owner, "invalid_prefix")
    if empty:
        with os.scandir(prefix) as entries:
            names = []
            for entry in entries:
                names.append(entry.name)
                _managed_require(len(names) <= 1, "invalid_prefix")
        _managed_require(names == [".incomplete"], "invalid_marker")
    marker = _managed_identity(_managed_node(prefix / ".incomplete"))
    _managed_require(
        marker[2] == stat.S_IFREG | 0o600 and marker[3:5] == owner and marker[6] == 0,
        "invalid_marker",
    )
    return root[:5], marker


def _managed_plan(context, selected, prefix, home, build_type):
    """Bound discovery as well as copied inputs; metadata, not authentication."""
    facts, copies, packages, overlays = {}, [], [], []
    inspected = set()

    def inspect(path, *, optional=False):
        if path not in inspected:
            _managed_require(len(inspected) < MANAGED_PREFIX_MAX_ENTRIES, "entry_limit")
            inspected.add(path)
        try:
            info = _managed_node(path)
        except FileNotFoundError:
            if not optional:
                raise
            info = None
        return info

    def remember(path, kind, value):
        key = path, kind
        _managed_require(key not in facts or facts[key] == value, "input_changed")
        facts[key] = value

    def observe(path):
        info = inspect(path)
        remember(path, "metadata", _managed_identity(info))
        return info

    def children(path):
        result = []
        with os.scandir(path) as entries:
            for entry in entries:
                child = Path(entry.path)
                inspect(child)  # Budget and safety checks also cover ignored entries.
                result.append(child)
        return sorted(result)

    def directory(path, anchor):
        _managed_real_directory(path)
        current = anchor
        _managed_require(path == anchor or anchor in path.parents)
        remember(current, "identity", _managed_identity(inspect(current))[:5])
        for part in path.relative_to(anchor).parts:
            current /= part
            info = inspect(current)
            _managed_require(stat.S_ISDIR(info.st_mode), "unsafe_entry")
            remember(current, "identity", _managed_identity(info)[:5])

    def tree(path):
        _managed_require(
            path != prefix and prefix not in path.parents and path not in prefix.parents
        )
        pending = [path]
        while pending:
            current = pending.pop()
            if stat.S_ISDIR(observe(current).st_mode):
                pending.extend(children(current))

    workspace = Path(context.workspace)
    _managed_require(selected.parent == workspace / "release/versions")
    directory(selected, workspace)
    selected_children = children(selected)
    remember(selected, "members", tuple(path.name for path in selected_children))
    for package in selected_children:
        if package.name == ".staging":
            info = observe(package)
            _managed_require(stat.S_ISREG(info.st_mode) and info.st_size == 0)
            continue
        safe_component(package.name, "package name")
        source = context.package_dir(selected, package.name, build_type)
        try:
            directory(source, workspace)
        except FileNotFoundError:
            raise RuntimePrefixError("missing_build") from None
        top = children(source)
        _managed_require(top and all(child.name != ".incomplete" for child in top))
        tree(source)
        packages.append(source)
        copies.extend((child, prefix / child.name) for child in top)
    _managed_require(packages, "no_packages")
    _managed_require(home != prefix and prefix not in home.parents)
    directory(home, home)
    base = home / ".raisin"
    if inspect(base, optional=True) is not None:
        directory(base, home)
        for package in children(base):
            if not stat.S_ISDIR(inspect(package).st_mode):
                continue
            safe_component(package.name, "resource package name")
            source = package / "resource"
            if inspect(source, optional=True) is None:
                continue
            directory(source, home)
            tree(source)
            overlays.append((source, prefix / "resource" / package.name / "resource"))
    return packages, copies, overlays, tuple(sorted(facts.items()))


def _managed_copy_file(source, target):
    source, target = Path(source), Path(target)
    _managed_require(stat.S_ISREG(_managed_node(source).st_mode))
    try:
        _managed_require(stat.S_ISREG(_managed_node(target).st_mode))
    except FileNotFoundError:
        pass
    return shutil.copy2(source, target)


class _ManagedCopyFailure(Exception):
    """Carry an original file I/O error through copytree's string aggregation."""

    def __init__(self, error):
        self.error = error


def _managed_copy(source, target):
    info = _managed_node(source)
    try:
        _managed_require(
            stat.S_ISDIR(_managed_node(target).st_mode) == stat.S_ISDIR(info.st_mode)
        )
    except FileNotFoundError:
        pass
    if stat.S_ISDIR(info.st_mode):
        def copy_file(source, target):
            try:
                return _managed_copy_file(source, target)
            except OSError as error:
                raise _ManagedCopyFailure(error) from None
        try:
            shutil.copytree(source, target, dirs_exist_ok=True, copy_function=copy_file)
        except _ManagedCopyFailure as failure:
            raise failure.error from None
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        _managed_copy_file(source, target)


def _managed_executables(prefix):
    # os.walk/rglob can suppress scan errors; this gate must propagate them.
    inspected = 0
    for name in ("bin", "scripts"):
        root = prefix / name
        try:
            info = _managed_node(root)
        except FileNotFoundError:
            continue
        _managed_require(stat.S_ISDIR(info.st_mode))
        pending = [root]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    inspected += 1
                    _managed_require(inspected <= MANAGED_PREFIX_MAX_ENTRIES, "entry_limit")
                    path = Path(entry.path)
                    info = _managed_node(path)
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(path)
                    elif name == "bin":
                        path.chmod(0o755)
                    elif path.name.endswith(".sh"):
                        path.chmod(stat.S_IMODE(info.st_mode) | 0o111)


def populate_marked(
    context: OtaContext,
    *,
    selected_path: Path,
    prefix: Path,
    build_type: str,
    home: Path,
) -> List[Path]:
    """Populate an owned0700 marked prefix without selecting/releasing/starting.

    Caller retains core exclusion and verified original operation/candidate/root
    lifetime. Exact source generation/build and device home are explicit. This
    validates a supported fresh, single-link POSIX input profile, not identity or
    installation authority. Partial output stays incomplete on every error.
    Whole validation, durable sync and explicit recovery still belong to owner.
    """
    prefix, selected_path, home = Path(prefix), Path(selected_path), Path(home)
    original = _managed_prefix(context, prefix, empty=True)
    _managed_require(build_type in ("debug", "release"), "invalid_build")
    for component in (context.os_type, context.os_version, context.architecture):
        safe_component(component, "platform component")
        _managed_require(component not in (".", ".."))
    plan = _managed_plan(context, selected_path, prefix, home, build_type)
    _managed_require(_managed_prefix(context, prefix, empty=True) == original, "output_changed")
    packages, copies, overlays, _ = plan
    for source, target in copies:
        _managed_copy(source, target)
    _managed_executables(prefix)
    for source, target in overlays:
        _managed_copy(source, target)
    _managed_require(
        _managed_plan(context, selected_path, prefix, home, build_type) == plan,
        "input_changed",
    )
    _managed_require(_managed_prefix(context, prefix, empty=False) == original, "output_changed")
    return packages
