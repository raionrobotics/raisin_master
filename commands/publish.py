"""
Publish command for RAISIN.

Builds a package and archives it into release/. Uploading is CI's job.
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import click
import yaml

from commands import globals as g
from commands.utils import (
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


def _get_paths(target: str, build_type: str) -> dict:
    """Get all relevant paths for a publish operation.

    Returns dict with: script_dir, target_dir, install_dir, build_dir, release_dir
    """
    script_dir = Path(g.script_directory)
    return {
        "script_dir": script_dir,
        "target_dir": script_dir / "src" / target,
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


def _build_windows(build_dir: Path, install_dir: Path, build_type: str):
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
) -> bool:
    """Build the package using CMake + Ninja.

    Returns True on success, False on failure.
    """
    build_dir = paths["build_dir"]
    install_dir = paths["install_dir"]
    target_dir = paths["target_dir"]
    raisin_march = _get_publish_march()

    # Clean stale build directory to prevent cached cmake paths from
    # interfering (e.g., system zstd vs install/ zstd).
    if build_dir.exists():
        shutil.rmtree(build_dir)

    print(f"\n--- Setting up build for '{target}' ---")
    setup(
        package_name=target,
        build_type=build_type,
        build_dir=str(build_dir),
        build_test_enabled=False,
        raisin_march=raisin_march,
    )
    build_dir.mkdir(parents=True, exist_ok=True)

    print("⚙️  Running CMake...")
    if platform.system().lower() == "linux":
        _build_linux(build_dir, install_dir, build_type, raisin_march)
    else:
        _build_windows(build_dir, install_dir, build_type)

    print(f"✅ Build for '{target}' complete!")

    # Copy release.yaml and install_dependencies.sh to install dir
    install_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(target_dir / "release.yaml", install_dir / "release.yaml")

    deps_script = target_dir / "install_dependencies.sh"
    if deps_script.is_file():
        shutil.copy(deps_script, install_dir / "install_dependencies.sh")

    return True


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
    shutil.make_archive(
        base_name=str(archive_base),
        format="zip",
        root_dir=str(install_dir),
    )
    archive_path = Path(str(archive_base) + ".zip")
    print(f"✅ Successfully created archive: {archive_path}")
    return archive_path


# ============================================================================
# Main Publish Function
# ============================================================================


def publish(target: str, build_type: str, dry_run: bool = False) -> bool:
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

    Returns:
        True when the archive was produced. The caller turns a False into a
        non-zero exit -- CI reads that exit code, and this is the only thing
        that produces the archives the OTA upload stage consumes.
    """
    paths = _get_paths(target, build_type)

    # Validate target
    details = _validate_target(paths["target_dir"])
    if not details:
        return False

    print(f"✅ Found release file for '{target}'.")
    version = details.get("version", "0.0.0")

    try:
        # Build
        if not _build_package(target, build_type, paths):
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
def publish_command(target, build_type, dry_run):
    """
    Build a package and archive it into release/ for CI to upload.

    \b
    Examples:
        raisin publish raisin_network                # Build and archive
        raisin publish raisin_network --type release # Release build only
        raisin publish my_package -t release
    """
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
        if not publish(target, bt, dry_run):
            succeeded = False
    if not succeeded:
        raise click.exceptions.Exit(code=1)
