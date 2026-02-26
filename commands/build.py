"""
Build command for RAISIN.

Builds the project using CMake and Ninja.
"""

import os
import sys
import platform
import subprocess
import shutil
import click
from pathlib import Path

# Import globals and utilities
from commands import globals as g
from commands.utils import delete_directory


def _is_qemu_emulated():
    """Detect if running under QEMU user-mode emulation (e.g., buildx cross-arch)."""
    try:
        with open("/proc/cpuinfo", "r") as f:
            cpuinfo = f.read()
        # Native ARM reports "CPU implementer", QEMU doesn't
        if platform.machine() in ("aarch64", "arm64"):
            return "CPU implementer" not in cpuinfo
    except OSError:
        pass
    return False


def _get_build_jobs():
    """Determine number of parallel build jobs.

    Priority:
    1. RAISIN_MAX_JOBS env var (user override)
    2. Auto-detect: 4 under QEMU, cpu_count/2 otherwise
    """
    env_jobs = os.environ.get("RAISIN_MAX_JOBS")
    if env_jobs:
        return int(env_jobs)
    if _is_qemu_emulated():
        return 4
    return int(os.cpu_count() / 2) or 4


def build_command(build_types, to_install=False):
    """
    Build the project with CMake and Ninja.

    Args:
        build_types (list): List of build types ('debug', 'release')
        to_install (bool): Whether to run install target after build
    """
    script_directory = g.script_directory
    developer_env = g.developer_env
    ninja_path = g.ninja_path

    # Default to debug if no build type specified
    if not build_types or (not "debug" in build_types and not "release" in build_types):
        build_types = ["debug"]

    for build_type in build_types:
        if build_type not in ["release", "debug"]:
            continue

        # Setup build directory
        # Preserve the pure_cmake directory by stashing it before cleaning the build directory.
        build_type = build_type.lower()
        build_dir = Path(script_directory) / f"cmake-build-{build_type}"
        build_type_capitalized = build_type.capitalize()
        stash_pure_cmake_build_dir(script_directory, build_dir, build_type)
        delete_directory(build_dir)
        build_dir.mkdir(parents=True, exist_ok=True)
        restore_pure_cmake_build_dir(script_directory, build_dir, build_type)
        print(f"building in {build_dir}, build type is {build_type_capitalized}")

        if platform.system().lower() == "linux":
            try:
                # CMake configuration
                cmake_command = [
                    "cmake",
                    "-S",
                    script_directory,
                    "-G",
                    "Ninja",
                    "-B",
                    str(build_dir),
                    f"-DCMAKE_BUILD_TYPE={build_type_capitalized}",
                ]
                # Under QEMU, wrap compiler with retry-on-segfault script
                if _is_qemu_emulated():
                    retry_script = str(Path(script_directory) / "scripts" / "retry-on-segfault.sh")
                    cmake_command.extend([
                        f"-DCMAKE_C_COMPILER_LAUNCHER={retry_script}",
                        f"-DCMAKE_CXX_COMPILER_LAUNCHER={retry_script}",
                    ])
                subprocess.run(cmake_command, check=True, text=True)
            except subprocess.CalledProcessError as e:
                # If the command fails, print its output to help with debugging
                print("--- CMake Command Failed ---", file=sys.stderr)
                print(f"Return Code: {e.returncode}", file=sys.stderr)
                print("\n--- STDOUT ---", file=sys.stderr)
                print(e.stdout, file=sys.stderr)
                print("\n--- STDERR ---", file=sys.stderr)
                print(e.stderr, file=sys.stderr)
                print("--------------------------", file=sys.stderr)
                sys.exit(1)

            print("✅ CMake configuration successful.")
            print("🛠️  Building with Ninja...")
            core_count = _get_build_jobs()
            if _is_qemu_emulated():
                print(f"🔩 QEMU detected — limiting to {core_count} parallel jobs.")
            else:
                print(f"🔩 Using {core_count} cores for the build.")

            # Build with Ninja (retry under QEMU for random segfaults)
            if to_install:
                build_command = ["ninja", "install", f"-j{core_count}"]
            else:
                build_command = ["ninja", f"-j{core_count}"]
            max_attempts = 3 if _is_qemu_emulated() else 1
            for attempt in range(1, max_attempts + 1):
                try:
                    subprocess.run(build_command, cwd=build_dir, check=True, text=True)
                    break
                except subprocess.CalledProcessError:
                    if attempt < max_attempts:
                        print(f"⚠️  Build failed (attempt {attempt}/{max_attempts}), retrying (QEMU segfault likely)...")
                    else:
                        raise

        else:  # Windows
            try:
                # CMake configuration
                cmake_command = [
                    "cmake",
                    "--preset",
                    f"windows-{build_type.lower()}",
                    "-S",
                    script_directory,
                    "-B",
                    str(build_dir),
                    f"-DCMAKE_TOOLCHAIN_FILE={script_directory}/vcpkg/scripts/buildsystems/vcpkg.cmake",
                    "-DRAISIN_RELEASE_BUILD=ON",
                ]
                subprocess.run(cmake_command, check=True, text=True, env=developer_env)

            except subprocess.CalledProcessError as e:
                # If the command fails, print its output to help with debugging
                print("--- CMake Command Failed ---", file=sys.stderr)
                print(f"Return Code: {e.returncode}", file=sys.stderr)
                print("\n--- STDOUT ---", file=sys.stderr)
                print(e.stdout, file=sys.stderr)
                print("\n--- STDERR ---", file=sys.stderr)
                print(e.stderr, file=sys.stderr)
                print("--------------------------", file=sys.stderr)
                sys.exit(1)

            print("✅ CMake configuration successful.")
            print("🛠️  Building with Ninja...")

            # Build with CMake
            subprocess.run(
                ["cmake", "--build", str(build_dir), "--parallel"],
                check=True,
                text=True,
                env=developer_env,
            )

            # Install if requested
            if to_install:
                subprocess.run(
                    ["cmake", "--install", str(build_dir)],
                    check=True,
                    text=True,
                    env=developer_env,
                )

    print("🎉🎉🎉 Building process finished successfully.")


def stash_pure_cmake_build_dir(script_directory, build_dir, build_type):
    pure_cmake_dir = build_dir / "pure_cmake"
    if not pure_cmake_dir.is_dir():
        return

    stash_dir = Path(script_directory) / ".cache" / "pure_cmake_build_stash" / build_type
    stash_dir.parent.mkdir(parents=True, exist_ok=True)
    if stash_dir.exists():
        shutil.rmtree(stash_dir)
    shutil.move(str(pure_cmake_dir), str(stash_dir))


def restore_pure_cmake_build_dir(script_directory, build_dir, build_type):
    pure_cmake_dir = build_dir / "pure_cmake"
    if pure_cmake_dir.exists():
        return

    stash_root = Path(script_directory) / ".cache" / "pure_cmake_build_stash"
    stash_dir = stash_root / build_type
    if not stash_dir.is_dir():
        return

    shutil.move(str(stash_dir), str(pure_cmake_dir))
    if stash_root.exists() and not any(stash_root.iterdir()):
        stash_root.rmdir()


# ============================================================================
# Click CLI Command
# ============================================================================


@click.command()
@click.option(
    "--type",
    "-t",
    "build_types",
    multiple=True,
    type=click.Choice(["debug", "release"], case_sensitive=False),
    help="Build type: debug or release (can specify multiple times)",
)
@click.option(
    "--install",
    "-i",
    is_flag=True,
    help="Install artifacts to install/ directory after building",
)
@click.argument("targets", nargs=-1)
def build_cli_command(build_types, install, targets):
    """
    Compile the project using CMake and Ninja.

    \b
    Examples:
        raisin build --type release                  # Build release only
        raisin build --type debug --install          # Build debug and install
        raisin build -t release -t debug -i          # Build both types and install
        raisin build -t release raisin_network       # Build specific target

    \b
    Note: This command first runs setup, then compiles.
    Run 'sudo bash install_dependencies.sh' to install package dependencies.
    """
    # Import here to avoid circular dependency
    from commands.setup import setup, process_build_targets

    targets = list(targets)

    process_build_targets(targets)

    if not g.build_pattern:
        click.echo("🛠️  building all patterns")
    else:
        click.echo(f"🛠️  building the following targets: {g.build_pattern}")

    setup()

    # Then build
    build_types = list(build_types) if build_types else []

    if not build_types:
        click.echo("❌ Error: Please specify at least one build type using --type")
        click.echo("   Example: raisin build --type release")
        sys.exit(1)

    build_command(build_types, to_install=install)
