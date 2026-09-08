"""
SDK build commands for RAISIN.

Each platform registers a command under build_sdk with its own toolchain
options and packaging. Android currently builds the communication-only core.
SDK builds reuse source preparation and message generation. CMake generation,
compilation and packaging use templates/sdk/<platform>/ independently of the
host build command and its templates/CMakeLists.txt.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Dict, Optional

import click
import yaml

from commands import globals as g
from commands.sdk_target_config import (
    TargetConfig,
    TargetConfigError,
    load_profiles,
    resolve_android_target,
)
from commands.utils import delete_directory, get_build_jobs

SDK_NAME = "raisin_android_sdk"
PROTOCOL_SOURCE = "src/raisin/raisin_network/include/raisin_network/network.hpp"
CORE_RELEASE_YAML = "src/raisin/release.yaml"


# ============================================================================
# Provenance
# ============================================================================


def read_protocol_version(script_directory: str) -> int:
    """Read Network::version_ from the core source. Never hand-written."""
    source = Path(script_directory) / PROTOCOL_SOURCE
    if not source.is_file():
        raise click.ClickException(f"cannot read protocol version: {source} missing")
    match = re.search(r"version_\s*=\s*(\d+)", source.read_text(encoding="utf-8"))
    if not match:
        raise click.ClickException(f"cannot find 'version_ = <n>' in {source}")
    return int(match.group(1))


def read_sdk_version(script_directory: str) -> str:
    release = Path(script_directory) / CORE_RELEASE_YAML
    if release.is_file():
        with open(release, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return str(data.get("version", "0.0.0"))
    return "0.0.0"


def _git(repo: Path, *args) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def collect_source_revisions(script_directory: str, packages, source_repositories=()) -> Dict[str, dict]:
    """Commit and dirty state for the workspace and every src repo we compiled."""
    repos = {"raisin_master": Path(script_directory)}
    src_root = Path(script_directory) / "src"
    for repository in source_repositories:
        repos[repository] = src_root / repository
    for package in packages:
        for candidate in src_root.glob(f"*/**/{package}"):
            repo = candidate
            while repo != src_root and repo.parent != repo:
                if (repo / ".git").exists():
                    repos[repo.name] = repo
                    break
                repo = repo.parent
            break

    revisions = {}
    for name, path in sorted(repos.items()):
        commit = _git(path, "rev-parse", "HEAD")
        status = _git(path, "status", "--porcelain=v1", "--untracked-files=normal")
        revisions[name] = {
            "commit": commit or "unknown",
            "dirty": None if status is None else bool(status.strip()),
        }
    return revisions


def hash_tree(root: Path) -> Dict[str, str]:
    digests = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        digests[path.relative_to(root).as_posix()] = h.hexdigest()
    return digests


# ============================================================================
# Build
# ============================================================================


def generate_sdk_cmake(target: TargetConfig, project_directories) -> Path:
    """Generate an SDK root from its platform template and selected packages."""
    from commands.setup import build_dependency_graph, topological_sort

    graph = build_dependency_graph(project_directories)
    ordered = list(graph)
    for _ in range(2):
        ordered = topological_sort(graph, ordered)
    projects = {Path(directory).name: Path(directory) for directory in project_directories}
    subdirectories = [
        f'add_subdirectory("{projects[name].as_posix()}" "{name}")'
        for name in ordered
    ]
    settings = [
        f'# Profile {target.profile}: commands/sdk_{target.platform}_profile.yaml',
    ]
    for key, value in sorted(target.cmake_options.items()):
        settings.append(f'set({key} {value} CACHE BOOL "" FORCE)')
    values = {
        "SCRIPT_DIR": Path(g.script_directory).as_posix(),
        "GENERATED_INCLUDE": (target.generated_dir() / "include").as_posix(),
        "SDK_PREFIX": target.install_dir().as_posix(),
        "TARGET_SETTINGS": "\n".join(settings),
        "SUB_PROJECT": "\n".join(subdirectories),
    }
    content = _render_template(target.platform, "CMakeLists.txt", values)
    destination = target.cmake_root_dir() / "CMakeLists.txt"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    click.echo(f"📂 Generated SDK CMakeLists.txt at {destination} with {len(projects)} projects.")
    return destination


def configure_and_build(target: TargetConfig) -> None:
    binary_dir = target.cmake_binary_dir()
    binary_dir.mkdir(parents=True, exist_ok=True)

    cmake_command = [
        "cmake",
        "-S",
        str(target.cmake_root_dir()),
        "-B",
        str(binary_dir),
        "-G",
        "Ninja",
        f"-DCMAKE_BUILD_TYPE={target.build_type}",
        f"-DCMAKE_INSTALL_PREFIX={target.install_dir()}",
        f"-DRAISIN_MARCH={target.march}",
        "-DRAISIN_BUILD_TEST=OFF",
    ]
    cmake_command.extend(target.cmake_args())

    click.echo("🛠️  configuring: " + " ".join(cmake_command))
    subprocess.run(cmake_command, check=True, text=True)

    jobs = get_build_jobs()
    click.echo(f"🔩 building with {jobs} jobs")
    subprocess.run(
        ["ninja", "install", f"-j{jobs}"], cwd=binary_dir, check=True, text=True
    )


# ============================================================================
# Packaging
# ============================================================================


def _render_template(platform: str, name: str, values: Dict[str, str]) -> str:
    template = Path(g.script_directory) / "templates" / "sdk" / platform / name
    text = template.read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace(f"@{key}@", str(value))
    remaining = re.findall(r"@[A-Z_]+@", text)
    if remaining:
        raise click.ClickException(
            f"template {name} has unresolved placeholders: {sorted(set(remaining))}"
        )
    return text


def package_sdk(target: TargetConfig, interface_sources: Dict[str, dict]) -> Path:
    prefix = target.install_dir()
    sdk_version = read_sdk_version(g.script_directory)
    protocol_version = read_protocol_version(g.script_directory)

    # IDL: the app mounts this directory as Android assets, so the layout must
    # stay messages/<package>/{msg,srv}/*.
    idl_dir = prefix / "idl"
    delete_directory(idl_dir)
    messages_dir = prefix / "messages"
    if not messages_dir.is_dir():
        raise click.ClickException(f"no message definitions were installed in {prefix}")
    idl_dir.mkdir(parents=True, exist_ok=True)
    shutil.move(str(messages_dir), str(idl_dir / "messages"))

    # `generated/` is the host redeploy channel for release archives and would be
    # a second, drift-prone copy of the headers already installed under include/.
    delete_directory(prefix / "generated")

    # Shared libraries in the layout Gradle's jniLibs expects.
    jni_dir = prefix / "jniLibs" / target.abi
    delete_directory(prefix / "jniLibs")
    jni_dir.mkdir(parents=True, exist_ok=True)
    shared_libraries = sorted((prefix / "lib").glob("*.so"))
    if not shared_libraries:
        raise click.ClickException(f"no shared libraries were installed in {prefix}/lib")
    for library in shared_libraries:
        shutil.copy2(library, jni_dir / library.name)

    # Umbrella CMake package.
    config_dir = prefix / "lib" / "cmake" / SDK_NAME
    config_dir.mkdir(parents=True, exist_ok=True)
    values = {
        "SDK_NAME": SDK_NAME,
        "SDK_VERSION": sdk_version,
        "PROTOCOL_VERSION": protocol_version,
        "PROFILE": target.profile,
        "ABI": target.abi,
        "API_LEVEL": target.api_level,
        "STL": target.stl,
        "NDK_VERSION": target.ndk_version,
        "BUILD_TYPE": target.build_type,
        "BUNDLED_PACKAGES": ";".join(
            sorted(p.parent.name for p in (prefix / "lib/cmake").glob("*/*Config.cmake")
                   if p.parent.name != SDK_NAME)
        ),
        "COMPILE_DEFINITIONS": ";".join(
            f"{k}={1 if v == 'ON' else 0}" for k, v in sorted(target.cmake_options.items()) if k.startswith("RAISIN_")
        ),
    }
    (config_dir / f"{SDK_NAME}Config.cmake").write_text(
        _render_template(target.platform, "raisin_android_sdk-config.cmake.in", values), encoding="utf-8"
    )
    (config_dir / f"{SDK_NAME}ConfigVersion.cmake").write_text(
        _render_template(target.platform, "raisin_android_sdk-config-version.cmake.in", values),
        encoding="utf-8",
    )

    # Metadata last, so its hashes cover everything else.
    metadata = {
        "sdk": {
            "name": SDK_NAME,
            "version": sdk_version,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "protocol_version": protocol_version,
        "target": target.metadata(),
        "features": dict(sorted(target.cmake_options.items())),
        "packages": list(target.packages),
        "message_packages": list(target.message_packages),
        "interface_sources": interface_sources,
        "sources": collect_source_revisions(
            g.script_directory, target.packages,
            source_repositories=[name for name, info in interface_sources.items()
                                 if info.get("kind") == "source"],
        ),
        "symbols": (
            f"{target.build_type} build; unstripped shared libraries in lib/ are the "
            "debug-symbol source. Gradle strips its own copies when packaging the APK."
        ),
    }
    # Hashes cover every shipped file. The metadata file cannot hash itself.
    metadata["files"] = hash_tree(prefix)
    metadata_path = prefix / "raisin_sdk.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    click.secho(f"📦 SDK installed at {prefix}", fg="green")
    return prefix


def archive_sdk(target: TargetConfig) -> Path:
    prefix = target.install_dir()
    sdk_version = read_sdk_version(g.script_directory)
    archive_dir = target.archive_dir()
    archive_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{SDK_NAME}-{sdk_version}-{target.slug}"
    archive_path = archive_dir / f"{stem}.tar.gz"
    if archive_path.exists():
        archive_path.unlink()
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(prefix, arcname=stem)
    click.secho(f"🗜️  archive: {archive_path}", fg="green")
    return archive_path


# ============================================================================
# Click CLI
# ============================================================================


@click.group()
def build_sdk_group():
    """Build and package a Raisin SDK for the selected platform."""


def print_profiles(platform: str):
    """List the SDK profiles belonging to one platform."""
    for name, profile in sorted(load_profiles(platform=platform).items()):
        click.echo(f"{name}  [{profile.get('platform', '?')}]")
        description = (profile.get("description") or "").strip()
        if description:
            click.echo(f"    {' '.join(description.split())}")
        click.echo(f"    packages: {', '.join(profile.get('packages') or [])}")


@build_sdk_group.command(name="android")
@click.option("--list-profiles", is_flag=True,
              help="List Android SDK profiles without building or requiring an NDK")
@click.option("--profile", default="android_comm", show_default=True,
              help="Target profile from commands/sdk_android_profile.yaml")
@click.option("--abi", default="arm64-v8a", show_default=True, help="Android ABI")
@click.option("--api", "api_level", default=24, show_default=True, type=int,
              help="Minimum Android API level; must be <= the app's minSdk")
@click.option("--ndk", default="", help="NDK directory (default: ANDROID_NDK_HOME or $ANDROID_HOME/ndk/<newest>)")
@click.option("--stl", default="c++_shared", show_default=True,
              type=click.Choice(["c++_shared"]),
              help="C++ runtime; multiple shared libraries require c++_shared")
@click.option("--build-type", default="RelWithDebInfo", show_default=True,
              type=click.Choice(["Debug", "Release", "RelWithDebInfo", "MinSizeRel"]))
@click.option("--march", default="", help="Override the -march= baseline for the ABI")
@click.option("--archive/--no-archive", default=True, show_default=True,
              help="Write a .tar.gz of the SDK into sdk/android/archives/")
def build_android_sdk(profile, abi, api_level, ndk, stl, build_type, march, archive,
                      list_profiles):
    """
    Build, install and package the Android Raisin SDK.

    \b
    Examples:
        ./raisin build_sdk android
        ./raisin build_sdk android --abi arm64-v8a --api 24
        ./raisin build_sdk android --build-type Release --no-archive

    \b
    Host outputs are untouched: the target gets its own build directory
    (cmake-build-android-*), its own generated/ tree inside it, and its own
    install prefix under sdk/android/.
    """
    from commands.setup import TARGET_INTERFACE_SOURCES, setup

    try:
        if list_profiles:
            print_profiles("android")
            return
        target = resolve_android_target(
            profile_name=profile, abi=abi, api_level=api_level, ndk=ndk, stl=stl,
            build_type=build_type, march=march,
        )
    except TargetConfigError as e:
        raise click.ClickException(str(e))

    click.echo(f"🤖 NDK {target.ndk_version} at {target.ndk_dir}")
    click.echo(f"🎯 {target.slug}")

    g.build_pattern = []
    TARGET_INTERFACE_SOURCES.clear()
    try:
        project_directories = setup(
            build_dir=str(target.cmake_binary_dir()),
            build_test_enabled=False,
            target=target,
        )
    except TargetConfigError as error:
        raise click.ClickException(str(error)) from error

    generate_sdk_cmake(target, project_directories)
    configure_and_build(target)

    script_root = Path(g.script_directory)
    interface_sources = {
        name: {
            **info,
            "path": os.path.relpath(info.get("path", ""), script_root),
        }
        for name, info in TARGET_INTERFACE_SOURCES.items()
    }
    package_sdk(target, interface_sources)
    if archive:
        archive_sdk(target)

    click.secho("🎉 Android SDK ready.", fg="green")
