"""
Release command for RAISIN.

Builds, archives, and uploads releases to GitHub.
"""

import os
import re
import sys
import json
import yaml
import shutil
import platform
import subprocess
import click
from pathlib import Path

# Import globals and utilities
from commands import globals as g
from commands.utils import load_configuration
from commands.setup import (
    setup,
    get_commit_hash,
    guard_require_version_bump_for_src_packages,
)


def publish(target, build_type, skip_confirm=False):
    """
    Builds the project, creates a release archive, and uploads it to GitHub,
    prompting for overwrite if the asset already exists.
    """

    guard_require_version_bump_for_src_packages()

    # --- This initial part of the function remains the same ---
    target_dir = os.path.join(g.script_directory, "src", target)
    install_dir = f"{g.script_directory}/release/install/{target}/{g.os_type}/{g.os_version}/{g.architecture}/{build_type}"

    if not os.path.isdir(target_dir):
        print(
            f"❌ Error: Target '{target}' not found in '{os.path.join(g.script_directory, 'src')}'."
        )
        return

    release_file_path = os.path.join(target_dir, "release.yaml")

    if not os.path.isfile(release_file_path):
        print(f"❌ Error: 'release.yaml' not found in '{target_dir}'.")
        return

    print(f"✅ Found release file for '{target}'.")

    try:
        with open(release_file_path, "r") as file:
            details = yaml.safe_load(file)
            (
                repositories,
                secrets_config,
                user_type,
                _,
                _,
            ) = load_configuration()

            print(f"\n--- Setting up build for '{target}' ---")
            build_dir = Path(g.script_directory) / "release" / "build" / target
            setup(
                package_name=target, build_type=build_type, build_dir=str(build_dir)
            )  # Assuming setup is defined
            os.makedirs(build_dir, exist_ok=True)

            print("⚙️  Running CMake...")

            if platform.system().lower() == "linux":
                cmake_command = [
                    "cmake",
                    "-S",
                    g.script_directory,
                    "-G",
                    "Ninja",
                    "-B",
                    build_dir,
                    f"-DCMAKE_INSTALL_PREFIX={install_dir}",
                    f"-DCMAKE_BUILD_TYPE={build_type}",
                    "-DRAISIN_RELEASE_BUILD=ON",
                ]
                subprocess.run(cmake_command, check=True, text=True)
                print("✅ CMake configuration successful.")
                print("🛠️  Building with Ninja...")
                core_count = int(os.cpu_count() / 2) or 4
                print(f"🔩 Using {core_count} cores for the build.")
                build_command = ["ninja", "install", f"-j{core_count}"]

                subprocess.run(build_command, cwd=build_dir, check=True, text=True)
            else:
                cmake_command = [
                    "cmake",
                    "--preset",
                    f"windows-{build_type.lower()}",
                    "-S",
                    g.script_directory,
                    "-B",
                    build_dir,
                    f"-DCMAKE_TOOLCHAIN_FILE={g.script_directory}/vcpkg/scripts/buildsystems/vcpkg.cmake",
                    f"-DCMAKE_INSTALL_PREFIX={install_dir}",
                    "-DRAISIN_RELEASE_BUILD=ON",
                    *([f"-DCMAKE_MAKE_PROGRAM={g.ninja_path}"] if g.ninja_path else []),
                ]
                subprocess.run(
                    cmake_command, check=True, text=True, env=g.developer_env
                )
                print("✅ CMake configuration successful.")
                print("🛠️  Building with Ninja...")

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

            print(f"✅ Build for '{target}' complete!")

            shutil.copy(
                Path(g.script_directory) / "src" / target / "release.yaml",
                Path(install_dir) / "release.yaml",
            )
            if (
                Path(g.script_directory) / "src" / target / "install_dependencies.sh"
            ).is_file():
                shutil.copy(
                    Path(g.script_directory)
                    / "src"
                    / target
                    / "install_dependencies.sh",
                    Path(install_dir) / "install_dependencies.sh",
                )

            print("\n--- Creating Release Archive ---")
            version = details.get("version", "0.0.0")
            archive_name_base = f"{target}-{g.os_type}-{g.os_version}-{g.architecture}-{build_type}-v{version}"
            release_dir = Path(g.script_directory) / "release"
            archive_file = release_dir / archive_name_base
            print(f"📦 Compressing '{install_dir}'...")
            shutil.make_archive(
                base_name=str(archive_file), format="zip", root_dir=str(install_dir)
            )
            print(f"✅ Successfully created archive: {archive_file}.zip")

            repositories, secrets, _, _, _ = load_configuration()
            if not secrets:
                print(
                    "❌ Error: GitHub tokens not found in configuration. Cannot upload to GitHub."
                )
                return

            print("\n--- Uploading to GitHub Release ---")

            # Determine the commit hash of the package being released
            pkg_repo_path = os.path.join(g.script_directory, "src", target)
            pkg_commit_hash = get_commit_hash(pkg_repo_path) or "UNKNOWN"

            # This will replace the old generic notes
            new_release_notes = f"Commit: {pkg_commit_hash}\n"

            release_info = repositories.get(target)
            if not (release_info and release_info.get("url")):
                print(
                    f"ℹ️ Repository URL for '{target}' not found in configuration_setting.yaml. Skipping GitHub release."
                )
                return

            repo_url = release_info["url"]
            match = re.search(r"git@github\.com:(.*)\.git", repo_url)
            repo_slug = match.group(1) if match else None
            if not repo_slug:
                print(f"❌ Error: Could not parse repository from URL: {repo_url}")
                return

            owner = repo_slug.split("/")[0]
            token = secrets.get(owner)
            if not token:
                print(
                    f"❌ Error: Token for owner '{owner}' not found in configuration_setting.yaml."
                )
                return

            auth_env = os.environ.copy()
            auth_env["GH_TOKEN"] = token
            tag_name = f"v{version}"

            archive_filename = os.path.basename(archive_file) + ".zip"
            archive_file_str = str(archive_file) + ".zip"

            # 1. Check if the release and asset already exist
            release_exists = True
            asset_exists = False
            release_is_prerelease = False
            try:
                print(f"Checking status of release '{tag_name}' in '{repo_slug}'...")
                list_cmd = [
                    "gh",
                    "release",
                    "view",
                    tag_name,
                    "--repo",
                    repo_slug,
                    "--json",
                    "assets,isPrerelease",
                ]
                result = subprocess.run(
                    list_cmd, check=True, capture_output=True, text=True, env=auth_env
                )
                release_data = json.loads(result.stdout)
                release_is_prerelease = bool(release_data.get("isPrerelease"))
                existing_assets = [
                    asset["name"] for asset in release_data.get("assets", [])
                ]
                if archive_filename in existing_assets:
                    asset_exists = True

            except subprocess.CalledProcessError as e:
                if "release not found" in e.stderr:
                    release_exists = False
                else:
                    print(f"❌ Error checking release status: {e.stderr}")
                    return

            # 2. Decide whether to create, upload, or prompt for overwrite
            if not release_exists:
                print(f"✅ Release '{tag_name}' does not exist. Creating a new one...")
                gh_create_cmd = [
                    "gh",
                    "release",
                    "create",
                    tag_name,
                    archive_file_str,
                    "--repo",
                    repo_slug,
                    "--title",
                    f"{tag_name}",
                    "--notes",
                    new_release_notes,
                    "--prerelease",
                ]
                subprocess.run(
                    gh_create_cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    env=auth_env,
                )
                print(
                    f"✅ Successfully created new release and uploaded '{archive_filename}'."
                )
            elif asset_exists:
                should_overwrite = skip_confirm or release_is_prerelease
                if release_is_prerelease and not skip_confirm:
                    print(
                        "ℹ️ Release is marked as prerelease; overwriting existing asset without confirmation."
                    )

                if not should_overwrite:
                    prompt = input(
                        f"⚠️ Asset '{archive_filename}' already exists. Overwrite? (y/n): "
                    ).lower()
                    should_overwrite = prompt in ["y", "yes"]

                if should_overwrite:
                    print(f"🚀 Overwriting asset...")
                    gh_upload_cmd = [
                        "gh",
                        "release",
                        "upload",
                        tag_name,
                        archive_file_str,
                        "--repo",
                        repo_slug,
                        "--clobber",
                    ]
                    subprocess.run(
                        gh_upload_cmd,
                        check=True,
                        capture_output=True,
                        text=True,
                        env=auth_env,
                    )

                    print(f"✅ Successfully overwrote asset in release '{tag_name}'.")
                else:
                    print(f"🚫 Upload for '{archive_filename}' cancelled by user.")
            else:  # Release exists, but asset does not
                print(f"🚀 Uploading new asset to existing release '{tag_name}'...")
                gh_upload_cmd = [
                    "gh",
                    "release",
                    "upload",
                    tag_name,
                    archive_file_str,
                    "--repo",
                    repo_slug,
                ]
                subprocess.run(
                    gh_upload_cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    env=auth_env,
                )

                print(f"✅ Successfully uploaded asset to release '{tag_name}'.")

    # Keep your existing exception handling
    except FileNotFoundError as e:
        print(
            f"❌ Command not found: '{e.filename}'. Is the required tool (cmake, ninja, zip, gh) installed and in your PATH?"
        )
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"❌ A command failed with exit code {e.returncode}:\n{e.stderr}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"🔥 Error parsing YAML file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"🔥 An unexpected error occurred: {e}")
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
    type=click.Choice(["debug", "release"], case_sensitive=False),
    default="release",
    show_default=True,
    help="Build type",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Auto-confirm all prompts (e.g., overwriting release assets)",
)
def publish_command(target, build_type, yes):
    """
    Build, package, and upload a release to GitHub.

    \b
    Examples:
        raisin publish raisin_network                # Publish release build
        raisin publish raisin_network --type debug   # Publish debug build
        raisin publish my_package -t release --yes   # Auto-confirm overwrites

    \b
    Note: Previously called 'release' command.
    """
    skip_confirm = False
    if yes:
        click.echo("⚠️  Auto-confirm enabled: All prompts will be accepted.")
        skip_confirm = True

    click.echo(f"📦 Publishing {target} ({build_type} build)...")
    publish(target, build_type, skip_confirm)
