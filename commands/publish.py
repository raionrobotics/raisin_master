"""
Publish command for RAISIN.

Builds a package and archives it into release/. Uploading is CI's job.
"""

import os
import platform
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Optional

import click
import yaml

from commands import globals as g
from commands.cmake_definitions import cmake_definition_args
from commands.utils import (
    delete_directory,
    is_qemu_emulated,
    get_build_jobs,
    get_default_portable_march,
)
from commands.setup import (
    setup,
)


# ============================================================================
# Path Helpers
# ============================================================================


def _resolve_target_dir(script_dir: Path, target: str) -> Path:
    """Resolve a package root release.yaml, including packages nested in a repo."""
    source_root = (script_dir / "src").resolve()
    if not target or Path(target).name != target or target in {".", ".."}:
        raise ValueError("Invalid package target")

    direct = source_root / target
    direct_resolved = direct.resolve()
    try:
        direct_resolved.relative_to(source_root)
    except ValueError as exc:
        raise ValueError("Package target escapes the source directory") from exc
    if (direct / "release.yaml").is_file():
        return direct

    matches = []
    if source_root.is_dir():
        for release_file in source_root.rglob("release.yaml"):
            package_dir = release_file.parent
            if package_dir.name != target:
                continue
            resolved = package_dir.resolve()
            try:
                resolved.relative_to(source_root)
            except ValueError:
                continue
            if resolved != direct_resolved:
                matches.append(package_dir)

    if len(matches) > 1:
        paths = ", ".join(sorted(str(path) for path in matches))
        raise ValueError(f"Ambiguous package target '{target}': {paths}")
    return matches[0] if matches else direct


def _get_paths(target: str, build_type: str) -> dict:
    """Get all relevant paths for a publish operation.

    Returns dict with: script_dir, target_dir, install_dir, build_dir, release_dir
    """
    script_dir = Path(g.script_directory)
    return {
        "script_dir": script_dir,
        "target_dir": _resolve_target_dir(script_dir, target),
        "install_dir": (
            script_dir
            / "release"
            / "install"
            / target
            / g.os_type
            / g.os_version
            / g.architecture
            / build_type
        ),
        "build_dir": script_dir / "release" / "build" / target / build_type.lower(),
        "release_dir": script_dir / "release",
    }


# ============================================================================
# Validation
# ============================================================================


def _validate_target(target_dir: Path) -> Optional[dict]:
    """Validate target exists and has release.yaml.

    Returns release details dict on success, None on failure.
    """
    if not target_dir.is_dir():
        print(f"❌ Error: Target not found in '{target_dir}'.")
        return None

    release_file = target_dir / "release.yaml"
    if not release_file.is_file():
        print(f"❌ Error: 'release.yaml' not found in '{target_dir}'.")
        return None

    try:
        with open(release_file, "r") as f:
            details = yaml.safe_load(f)
            if not isinstance(details, dict):
                print(f"❌ Error: Invalid YAML structure in '{release_file}'.")
                return None
            return details
    except yaml.YAMLError as e:
        print(f"❌ Error parsing YAML: {e}")
        return None


# ============================================================================
# Build
# ============================================================================


def _get_publish_march() -> str:
    """Resolve the CPU target used for portable publish builds."""
    return os.environ.get("RAISIN_MARCH", get_default_portable_march())


def _build_linux(
    build_dir: Path,
    install_dir: Path,
    build_type: str,
    raisin_march: str,
    extra_cmake_args: list[str],
):
    """Run CMake + Ninja build on Linux."""
    cmake_cmd = [
        "cmake",
        "-S",
        g.script_directory,
        "-G",
        "Ninja",
        "-B",
        str(build_dir),
        f"-DCMAKE_INSTALL_PREFIX={install_dir}",
        f"-DCMAKE_BUILD_TYPE={build_type}",
        "-DRAISIN_RELEASE_BUILD=ON",
        f"-DRAISIN_MARCH={raisin_march}",
    ]
    cmake_cmd.extend(extra_cmake_args)

    # Under QEMU, use compiler wrappers that retry on segfault
    cmake_env = None
    use_retry = is_qemu_emulated() or os.environ.get("RAISIN_QEMU_RETRY") == "1"
    if use_retry:
        scripts_dir = Path(g.script_directory) / "scripts"
        cmake_env = {
            **os.environ,
            "CC": str(scripts_dir / "gcc-retry.sh"),
            "CXX": str(scripts_dir / "g++-retry.sh"),
        }
        print("🔄 QEMU retry wrapper enabled via CC/CXX")

    subprocess.run(cmake_cmd, check=True, text=True, env=cmake_env)
    print("✅ CMake configuration successful.")

    print("🛠️  Building with Ninja...")
    core_count = get_build_jobs()
    if is_qemu_emulated():
        print(f"🔩 QEMU detected — limiting to {core_count} parallel jobs.")
    else:
        print(f"🔩 Using {core_count} cores for the build.")

    max_attempts = 3 if is_qemu_emulated() else 1
    ninja_cmd = ["ninja", "install", f"-j{core_count}"]
    for attempt in range(1, max_attempts + 1):
        try:
            subprocess.run(ninja_cmd, cwd=build_dir, check=True, text=True)
            break
        except subprocess.CalledProcessError:
            if attempt < max_attempts:
                print(
                    f"⚠️  Build failed (attempt {attempt}/{max_attempts}), retrying (QEMU segfault likely)..."
                )
            else:
                raise


def _build_windows(
    build_dir: Path,
    install_dir: Path,
    build_type: str,
    extra_cmake_args: list[str],
):
    """Run CMake + build on Windows."""
    cmake_cmd = [
        "cmake",
        "--preset",
        f"windows-{build_type.lower()}",
        "-S",
        g.script_directory,
        "-B",
        str(build_dir),
        f"-DCMAKE_TOOLCHAIN_FILE={g.script_directory}/vcpkg/scripts/buildsystems/vcpkg.cmake",
        f"-DCMAKE_INSTALL_PREFIX={install_dir}",
        "-DRAISIN_RELEASE_BUILD=ON",
    ]
    cmake_cmd.extend(extra_cmake_args)
    if g.ninja_path:
        cmake_cmd.append(f"-DCMAKE_MAKE_PROGRAM={g.ninja_path}")

    subprocess.run(cmake_cmd, check=True, text=True, env=g.developer_env)
    print("✅ CMake configuration successful.")

    print("🛠️  Building...")
    subprocess.run(
        ["cmake", "--build", str(build_dir), "--parallel"],
        check=True,
        text=True,
        env=g.developer_env,
    )
    subprocess.run(
        ["cmake", "--install", str(build_dir)],
        check=True,
        text=True,
        env=g.developer_env,
    )


def _build_package(
    target: str,
    build_type: str,
    paths: dict,
    cmake_defines: tuple[str, ...] = (),
) -> bool:
    """Build the package using CMake + Ninja.

    Returns True on success, False on failure.
    """
    build_dir = paths["build_dir"]
    install_dir = paths["install_dir"]
    target_dir = paths["target_dir"]
    raisin_march = _get_publish_march()
    extra_cmake_args = cmake_definition_args(cmake_defines)

    # Clean stale build directory to prevent cached cmake paths from
    # interfering (e.g., system zstd vs install/ zstd).
    delete_directory(build_dir)

    # Clean the install tree too: it is what the archive contains, so a file
    # the package no longer installs must not survive from an earlier publish.
    delete_directory(install_dir)

    print(f"\n--- Setting up build for '{target}' ---")
    setup(
        package_name=target,
        package_source_dir=target_dir,
        build_type=build_type,
        build_dir=str(build_dir),
        build_test_enabled=False,
        raisin_march=raisin_march,
    )
    build_dir.mkdir(parents=True, exist_ok=True)

    print("⚙️  Running CMake...")
    if platform.system().lower() == "linux":
        _build_linux(build_dir, install_dir, build_type, raisin_march, extra_cmake_args)
    else:
        _build_windows(build_dir, install_dir, build_type, extra_cmake_args)

    print(f"✅ Build for '{target}' complete!")

    # Copy release.yaml and the dependency declaration to install dir
    install_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(target_dir / "release.yaml", install_dir / "release.yaml")
    _copy_dependency_declaration(target_dir, install_dir)
    return True


def _copy_dependency_declaration(target_dir: Path, install_dir: Path) -> None:
    """Carry a package's system-dependency declaration into its install tree.

    The declaration is `install_dependencies.sh` and, where the package has
    moved its apt list out of the script, the `deps/` directory next to it
    (`deps/apt.txt`, `deps/apt.ubuntu-<version>.txt`). The script reads
    `deps/` relative to its own location, so an archive that carried the
    script without the directory would install nothing. Both travel together.
    """
    deps_script = target_dir / "install_dependencies.sh"
    if deps_script.is_file():
        shutil.copy(deps_script, install_dir / "install_dependencies.sh")

    deps_dir = target_dir / "deps"
    if deps_dir.is_dir():
        shutil.copytree(deps_dir, install_dir / "deps", dirs_exist_ok=True)


# ============================================================================
# Archive
# ============================================================================


def _create_archive(
    target: str,
    version: str,
    build_type: str,
    paths: dict,
) -> Path:
    """Create a zip archive of the built package.

    Returns the path to the created archive (with .zip extension).
    """
    install_dir = paths["install_dir"]
    release_dir = paths["release_dir"]

    archive_name = (
        f"{target}-{g.os_type}-{g.os_version}-{g.architecture}-{build_type}-v{version}"
    )
    archive_base = release_dir / archive_name

    print("\n--- Creating Release Archive ---")
    print(f"📦 Compressing '{install_dir}'...")
    archive_path = Path(str(archive_base) + ".zip")
    _write_reproducible_zip(Path(install_dir), archive_path)
    print(f"✅ Successfully created archive: {archive_path}")
    return archive_path


# The earliest time a zip can record. Every entry carries it, because the OTA
# server names a build by the hash of its zip and lets a version tag point at one
# build only: a timestamp from the build clock would make two builds of the same
# sources two different packages. Installs extract with `extractall`, which does
# not restore zip times, so unpacked files still get the time they were written.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def _write_reproducible_zip(root: Path, archive_path: Path) -> None:
    """Zip `root` so that the bytes depend only on the files' names, contents and
    executable bits: entries are sorted, timestamps fixed and modes normalised.

    Like `shutil.make_archive`, it records every directory, follows symlinks to
    files and records a symlinked directory without descending into it.
    """
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for current, dirnames, filenames in os.walk(root):
            dirnames.sort()
            base = Path(current)
            for name in dirnames:
                info = zipfile.ZipInfo(
                    (base / name).relative_to(root).as_posix() + "/", _ZIP_EPOCH
                )
                # Unix on every platform: ZipInfo picks MS-DOS on Windows, and
                # unzip applies the stored modes only to Unix entries.
                info.create_system = 3
                info.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
                archive.writestr(info, b"")
            for name in sorted(filenames):
                path = base / name
                status = os.stat(path)
                mode = 0o755 if status.st_mode & 0o111 else 0o644
                info = zipfile.ZipInfo(path.relative_to(root).as_posix(), _ZIP_EPOCH)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                # Streamed, as make_archive did: libraries can be large.
                with path.open("rb") as source, archive.open(
                    info, "w", force_zip64=status.st_size > zipfile.ZIP64_LIMIT
                ) as target:
                    shutil.copyfileobj(source, target, 1024 * 1024)


# ============================================================================
# Main Publish Function
# ============================================================================


def publish(
    target: str,
    build_type: str,
    dry_run: bool = False,
    cmake_defines: tuple[str, ...] = (),
) -> bool:
    """Build a package and archive it into release/.

    This does not upload. The OTA server takes a manifest only from Jenkins:
    `sourceType` is constrained to that one producer, deliberately, because the
    field records whether a build came from CI or from someone's machine and
    those are different things to trust. So publishing is two jobs in two
    places -- this produces the archive, and raisin_package_builder's
    ota-upload.groovy uploads it.

    Args:
        target: Target package name
        build_type: Build type (debug/release)
        dry_run: Accepted and ignored. Kept so CI, which still passes it, keeps
            working; there is no upload left for it to suppress.
        cmake_defines: Package-owned CMake cache definitions as KEY=VALUE strings.

    Returns:
        True when the archive was produced. The caller turns a False into a
        non-zero exit -- CI reads that exit code, and this is the only thing
        that produces the archives the OTA upload stage consumes.
    """
    try:
        paths = _get_paths(target, build_type)

        # Validate target
        details = _validate_target(paths["target_dir"])
        if not details:
            return False

        print(f"✅ Found release file for '{target}'.")
        version = details.get("version", "0.0.0")

        # Build
        if not _build_package(
            target, build_type, paths, cmake_defines=cmake_defines,
        ):
            return False

        # Archive
        archive_path = _create_archive(target, version, build_type, paths)
        print(f"\n✅ Archived '{target}' v{version} to '{archive_path}'.")
        print("   Uploading is CI's job (ota-upload.groovy); this command does not.")
        return True

    except FileNotFoundError as e:
        print(
            f"❌ Command not found: '{e.filename}'. "
            "Is the required tool (cmake, ninja, zip) installed and in your PATH?"
        )
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"❌ A command failed with exit code {e.returncode}:\n{e.stderr}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
        sys.exit(1)


# ============================================================================
# Click CLI Command
# ============================================================================


@click.command()
@click.argument("target", required=True)
@click.option(
    "--type",
    "-t",
    "build_type",
    type=click.Choice(["debug", "release", "both"], case_sensitive=False),
    default="both",
    show_default=True,
    help="Build type",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Deprecated and ignored: this command never uploads.",
)
@click.option(
    "--cmake-define", "cmake_defines", multiple=True, metavar="KEY=VALUE",
    help="Pass a package CMake cache definition; repeat for multiple values",
)
def publish_command(target, build_type, dry_run, cmake_defines):
    """
    Build a package and archive it into release/ for CI to upload.

    \b
    Examples:
        raisin publish raisin_network                # Build and archive
        raisin publish raisin_network --type release # Release build only
        raisin publish my_package -t release --cmake-define ENABLE_EXAMPLES=ON
        raisin publish my_package -t release
    """
    try:
        cmake_definition_args(cmake_defines)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    build_types = (
        ["release", "debug"] if build_type.lower() == "both" else [build_type.lower()]
    )
    click.echo(f"📦 Publishing {target} ({', '.join(build_types)} builds)...")
    # Run every build type so the operator sees the full picture, then report a
    # failure in any of them. A zero exit from a publish that produced nothing
    # would let the pipeline's upload stage run against whatever happened to be
    # in release/ already.
    succeeded = True
    for bt in build_types:
        if not publish(
            target, bt, dry_run, cmake_defines=cmake_defines,
        ):
            succeeded = False
    if not succeeded:
        raise click.exceptions.Exit(code=1)
