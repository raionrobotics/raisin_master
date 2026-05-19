"""
Publish command for RAISIN.

Builds, archives, and uploads releases to GitHub or OTA server.
"""

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import click
import yaml

from commands import globals as g
from commands.utils import (
    load_configuration,
    is_qemu_emulated,
    get_build_jobs,
    get_default_portable_march,
)
from commands.setup import (
    setup,
    get_commit_hash,
    guard_require_version_bump_for_src_packages,
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


def _parse_dependency_name(dependency_spec: str) -> Optional[str]:
    """Extract the package name from a release.yaml dependency spec."""
    match = re.match(r"^\s*([a-zA-Z0-9_.-]+)", str(dependency_spec))
    return match.group(1) if match else None


def _get_release_install_prefix(package_name: str, build_type: str) -> Path:
    """Return the expected release/install prefix for one package."""
    return (
        Path(g.script_directory)
        / "release"
        / "install"
        / package_name
        / g.os_type
        / g.os_version
        / g.architecture
        / build_type
    )


def _get_missing_publish_dependencies(
    details: dict, build_type: str
) -> list[tuple[str, Path]]:
    """Return declared dependencies that are not installed as release artifacts."""
    missing = []
    for dependency_spec in details.get("dependencies") or []:
        package_name = _parse_dependency_name(dependency_spec)
        if not package_name:
            continue

        prefix = _get_release_install_prefix(package_name, build_type)
        if not prefix.is_dir() or not (prefix / "release.yaml").is_file():
            missing.append((str(dependency_spec), prefix))

    return missing


def _validate_publish_dependencies(details: dict, build_type: str) -> bool:
    """Ensure publish builds use installed release artifacts for dependencies."""
    missing = _get_missing_publish_dependencies(details, build_type)
    if not missing:
        return True

    print("❌ Error: Publish dependencies are not installed as release artifacts.")
    print(
        "   Run `raisin install` for the dependencies in release.yaml before "
        "publishing, so the build does not depend on mutable src checkouts."
    )
    for dependency_spec, prefix in missing:
        print(f"   - {dependency_spec}: missing {prefix / 'release.yaml'}")
    return False


# ============================================================================
# Build
# ============================================================================


def _get_publish_march() -> str:
    """Resolve the CPU target used for portable publish builds."""
    return os.environ.get("RAISIN_MARCH", get_default_portable_march())


def _get_release_install_prefixes(target: str, build_type: str) -> list[Path]:
    """Return installed release package prefixes available to a publish build."""
    release_install_root = Path(g.script_directory) / "release" / "install"
    if not release_install_root.is_dir():
        return []

    prefixes = []
    for child in sorted(release_install_root.iterdir()):
        if child.name == target:
            continue

        prefix = _get_release_install_prefix(child.name, build_type)
        if prefix.is_dir():
            prefixes.append(prefix)

    return prefixes


def _get_publish_cmake_prefix_path(
    target: str,
    build_type: str,
    install_dir: Path,
) -> str:
    """Build the CMAKE_PREFIX_PATH used while publishing one package."""
    prefixes = [Path(g.script_directory) / "install", install_dir]
    prefixes.extend(_get_release_install_prefixes(target, build_type))
    return ";".join(str(prefix) for prefix in prefixes)


def _build_linux(
    build_dir: Path,
    install_dir: Path,
    build_type: str,
    raisin_march: str,
    cmake_prefix_path: str,
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
        f"-DCMAKE_PREFIX_PATH={cmake_prefix_path}",
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


def _build_windows(
    build_dir: Path,
    install_dir: Path,
    build_type: str,
    cmake_prefix_path: str,
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
        f"-DCMAKE_PREFIX_PATH={cmake_prefix_path}",
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


def _discover_target_package_names(target_dir: Path) -> set[str]:
    """Return CMake/interface package names owned by a source repo."""
    package_names: set[str] = set()

    for root, dirs, files in os.walk(target_dir):
        root_path = Path(root)
        dirs[:] = [
            d
            for d in dirs
            if d
            not in {
                ".git",
                "build",
                "cmake-build-debug",
                "cmake-build-release",
                "generated",
                "install",
                "release",
                "temp",
                "__pycache__",
            }
        ]

        if "CMakeLists.txt" in files:
            package_names.add(root_path.name)
            is_release_repo_root = root_path == target_dir or (
                root_path.parent == target_dir
                and (root_path / "release.yaml").is_file()
            )
            if not is_release_repo_root:
                dirs.clear()
            continue

        if root_path.name in {"msg", "srv", "action"}:
            expected_suffix = f".{root_path.name}"
            if any(name.endswith(expected_suffix) for name in files):
                package_names.add(root_path.parent.name)
            dirs.clear()

    return package_names


def _prune_non_target_publish_artifacts(target_dir: Path, install_dir: Path) -> None:
    """Remove installed artifacts that are known to belong to other source repos."""
    package_names = _discover_target_package_names(target_dir)
    if not package_names:
        return

    source_package_names = _discover_target_package_names(target_dir.parent)
    non_target_source_package_names = source_package_names - package_names

    pruned = []
    generated_packages_to_prune = set()
    for rel_root in ("messages", "generated/include"):
        root = install_dir / rel_root
        if not root.is_dir():
            continue

        for child in root.iterdir():
            if not child.is_dir() or child.name in package_names:
                continue

            generated_packages_to_prune.add(child.name)
            shutil.rmtree(child)
            pruned.append(child.relative_to(install_dir).as_posix())

    include_root = install_dir / "include"
    if include_root.is_dir():
        include_packages_to_prune = (
            generated_packages_to_prune | non_target_source_package_names
        )
        for child in include_root.iterdir():
            if (
                not child.is_dir()
                or child.name in package_names
                or child.name not in include_packages_to_prune
            ):
                continue

            shutil.rmtree(child)
            pruned.append(child.relative_to(install_dir).as_posix())

    if pruned:
        print(
            f"🧹 Pruned {len(pruned)} non-target publish artifact directories from "
            f"'{install_dir}'."
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
    cmake_prefix_path = _get_publish_cmake_prefix_path(
        target,
        build_type,
        install_dir,
    )

    print(f"\n--- Setting up build for '{target}' ---")
    setup(
        package_name=target,
        build_type=build_type,
        build_dir=str(build_dir),
        raisin_march=raisin_march,
    )
    build_dir.mkdir(parents=True, exist_ok=True)

    print("⚙️  Running CMake...")
    if platform.system().lower() == "linux":
        _build_linux(
            build_dir,
            install_dir,
            build_type,
            raisin_march,
            cmake_prefix_path,
        )
    else:
        _build_windows(build_dir, install_dir, build_type, cmake_prefix_path)

    print(f"✅ Build for '{target}' complete!")
    _prune_non_target_publish_artifacts(target_dir, install_dir)

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
# Upload: OTA
# ============================================================================


def _upload_to_ota(
    archive_path: Path,
    target: str,
    version: str,
    build_type: str,
) -> bool:
    """Upload archive to OTA server.

    Returns True on success, False on failure.
    """
    print("\n--- Uploading to OTA Server ---")
    try:
        from commands.ota_client import upload_package as ota_upload

        success = ota_upload(
            archive_path=archive_path,
            package_name=target,
            version=version,
            build_type=build_type,
        )
        if success:
            print(f"✅ OTA upload successful for '{target}'.")
        else:
            print(f"❌ OTA upload failed for '{target}'.")
        return success
    except Exception as e:
        print(f"❌ OTA upload failed: {e}")
        return False


# ============================================================================
# Upload: GitHub
# ============================================================================


def _parse_github_repo(repo_url: str) -> Optional[str]:
    """Extract 'owner/repo' slug from git URL."""
    match = re.search(r"git@github\.com:(.*)\.git", repo_url)
    return match.group(1) if match else None


def _check_github_release(
    tag_name: str,
    repo_slug: str,
    auth_env: dict,
) -> tuple:
    """Check if a GitHub release exists.

    Returns (exists: bool, is_prerelease: bool, assets: list[str])
    """
    try:
        result = subprocess.run(
            [
                "gh",
                "release",
                "view",
                tag_name,
                "--repo",
                repo_slug,
                "--json",
                "assets,isPrerelease",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=auth_env,
        )
        data = json.loads(result.stdout)
        assets = [a["name"] for a in data.get("assets", [])]
        return (True, bool(data.get("isPrerelease")), assets)
    except subprocess.CalledProcessError as e:
        if "release not found" in e.stderr:
            return (False, False, [])
        raise


def _update_github_release_notes(
    tag_name: str,
    repo_slug: str,
    notes: str,
    auth_env: dict,
):
    """Update release notes for an existing GitHub release."""
    # Get release ID
    release_id = subprocess.run(
        ["gh", "api", f"repos/{repo_slug}/releases/tags/{tag_name}", "--jq", ".id"],
        check=True,
        capture_output=True,
        text=True,
        env=auth_env,
    ).stdout.strip()

    if not release_id:
        raise RuntimeError(f"Could not resolve release id for '{tag_name}'")

    # Patch release notes
    subprocess.run(
        [
            "gh",
            "api",
            "-X",
            "PATCH",
            f"repos/{repo_slug}/releases/{release_id}",
            "-f",
            f"body={notes}",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=auth_env,
    )


def _upload_to_github(
    archive_path: Path,
    target: str,
    version: str,
    paths: dict,
) -> bool:
    """Upload archive to GitHub release.

    Returns True on success, False on failure.
    """
    repositories, secrets, _, _, _ = load_configuration()

    if not secrets:
        print("❌ Error: GitHub tokens not found in configuration. Cannot upload.")
        return False

    print("\n--- Uploading to GitHub Release ---")

    # Get commit hash for release notes
    target_dir = paths["target_dir"]
    commit_hash = get_commit_hash(str(target_dir)) or "UNKNOWN"
    release_notes = f"Commit: {commit_hash}\n"

    # Get repo info
    release_info = repositories.get(target)
    if not (release_info and release_info.get("url")):
        print(
            f"ℹ️ Repository URL for '{target}' not found in configuration. Skipping GitHub release."
        )
        return False

    repo_slug = _parse_github_repo(release_info["url"])
    if not repo_slug:
        print(f"❌ Error: Could not parse repository from URL: {release_info['url']}")
        return False

    owner = repo_slug.split("/")[0]
    token = secrets.get(owner)
    if not token:
        print(f"❌ Error: Token for owner '{owner}' not found in configuration.")
        return False

    auth_env = os.environ.copy()
    auth_env["GH_TOKEN"] = token
    tag_name = f"v{version}"
    archive_filename = archive_path.name

    print(f"Checking status of release '{tag_name}' in '{repo_slug}'...")

    try:
        exists, is_prerelease, assets = _check_github_release(
            tag_name, repo_slug, auth_env
        )
    except subprocess.CalledProcessError as e:
        print(f"❌ Error checking release status: {e.stderr}")
        return False

    if exists:
        if not is_prerelease:
            print(f"🚫 Release '{tag_name}' exists and is not a prerelease. Aborting.")
            return False

        # Update existing prerelease
        clobber = archive_filename in assets
        action = "overwriting" if clobber else "uploading new"
        print(
            f"🚀 Prerelease '{tag_name}' exists; {action} asset '{archive_filename}'..."
        )

        _update_github_release_notes(tag_name, repo_slug, release_notes, auth_env)

        upload_cmd = [
            "gh",
            "release",
            "upload",
            tag_name,
            str(archive_path),
            "--repo",
            repo_slug,
        ]
        if clobber:
            upload_cmd.append("--clobber")

        subprocess.run(
            upload_cmd, check=True, capture_output=True, text=True, env=auth_env
        )
        print(f"✅ Successfully uploaded asset to prerelease '{tag_name}'.")

    else:
        # Create new prerelease
        print(f"✅ Release '{tag_name}' does not exist. Creating a new one...")
        subprocess.run(
            [
                "gh",
                "release",
                "create",
                tag_name,
                str(archive_path),
                "--repo",
                repo_slug,
                "--title",
                tag_name,
                "--notes",
                release_notes,
                "--prerelease",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=auth_env,
        )
        print(
            f"✅ Successfully created new prerelease and uploaded '{archive_filename}'."
        )

    return True


# ============================================================================
# Main Publish Function
# ============================================================================


def publish(
    target: str, build_type: str, dry_run: bool = False, upload_ota: bool = False
):
    """Build, archive, and upload a release.

    Args:
        target: Target package name
        build_type: Build type (debug/release)
        dry_run: If True, skip actual publishing
        upload_ota: If True, upload to OTA server instead of GitHub
    """
    guard_require_version_bump_for_src_packages()

    paths = _get_paths(target, build_type)

    # Validate target
    details = _validate_target(paths["target_dir"])
    if not details:
        return

    print(f"✅ Found release file for '{target}'.")
    version = details.get("version", "0.0.0")
    if not _validate_publish_dependencies(details, build_type):
        return

    # Check user type
    _, _, user_type, _, _ = load_configuration()
    if user_type != "devel":
        print(
            "ℹ️  Note: This publish flow creates prerelease GitHub releases; "
            "non-'devel' users may not install prereleases."
        )

    try:
        # Build
        if not _build_package(target, build_type, paths):
            return

        # Archive
        archive_path = _create_archive(target, version, build_type, paths)

        # Dry run
        if dry_run:
            dest = "OTA server" if upload_ota else "GitHub"
            print(f"\n--- [DRY-RUN] Skipping {dest} Upload ---")
            print(f"[DRY-RUN] Would upload '{archive_path}' to {dest}")
            print(f"[DRY-RUN] Tag: v{version}")
            print("[DRY-RUN] Build and archive completed successfully.")
            return

        # Upload
        if upload_ota:
            _upload_to_ota(archive_path, target, version, build_type)
        else:
            _upload_to_github(archive_path, target, version, paths)

    except FileNotFoundError as e:
        print(
            f"❌ Command not found: '{e.filename}'. "
            "Is the required tool (cmake, ninja, zip, gh) installed and in your PATH?"
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
    help="Perform a dry run without actual publishing",
)
@click.option(
    "--upload-ota",
    is_flag=True,
    help="Upload to OTA server instead of GitHub",
)
def publish_command(target, build_type, dry_run, upload_ota):
    """
    Build, package, and upload a release to GitHub or OTA server.

    \b
    Examples:
        raisin publish raisin_network                # Publish to GitHub
        raisin publish raisin_network --type release # Publish only release build
        raisin publish raisin_network --upload-ota   # Publish to OTA server instead
        raisin publish my_package -t release
        raisin publish my_package -t both --dry-run  # Dry run without uploading
    """
    build_types = (
        ["release", "debug"] if build_type.lower() == "both" else [build_type.lower()]
    )
    click.echo(f"📦 Publishing {target} ({', '.join(build_types)} builds)...")
    for bt in build_types:
        publish(target, bt, dry_run, upload_ota)
