"""
Install command for RAISIN.

Downloads and installs packages from GitHub releases with dependency resolution.
"""

import re
import shutil
import click
from pathlib import Path
import requests
import zipfile
import yaml
from packaging.version import parse as parse_version
from packaging.version import InvalidVersion
from packaging.specifiers import SpecifierSet

# Import globals and utilities
from commands import globals as g
from commands.utils import load_configuration


def install_command(targets, build_type):
    """
    Install packages and their dependencies from GitHub releases.

    Args:
        targets (list): List of package specifications (e.g., ["raisin", "my-plugin>=1.2"])
        build_type (str): 'debug' or 'release'
    """
    print("🚀 Starting recursive installation process...")

    # Access globals
    script_directory = g.script_directory
    os_type = g.os_type
    os_version = g.os_version
    architecture = g.architecture

    script_dir_path = Path(script_directory)

    # Load configuration
    all_repositories, tokens, user_type, _ = load_configuration()
    if not all_repositories:
        print("❌ Error: No repositories found in configuration_setting.yaml")
        return
    if not tokens:
        print("❌ Error: No GitHub tokens found in configuration_setting.yaml")
        return

    # Process installation queue
    install_queue = list(targets)

    src_dir = script_dir_path / "src"
    if src_dir.is_dir():
        print(f"🔍 Scanning for local source packages in '{src_dir}'...")
        local_src_packages = [path.name for path in src_dir.iterdir() if path.is_dir()]
        if local_src_packages:
            print(f"  -> Found local packages to process: {local_src_packages}")
            install_queue.extend(local_src_packages)
    processed_packages = dict()
    session = requests.Session()
    is_successful = True

    while install_queue:
        target_spec = install_queue.pop(0)
        # print( f"🔄 Processing target specifier: '{target_spec}'")

        match = re.match(r"^\s*([a-zA-Z0-9_.-]+)\s*(.*)\s*$", target_spec)
        if not match:
            print(
                f"⚠️ Warning: Could not parse target specifier '{target_spec}'. Skipping."
            )
            continue

        package_name, spec_str = match.groups()
        spec_str = spec_str.strip()

        try:
            if not spec_str:
                spec = SpecifierSet(">=0.0.0")
            else:
                specifiers_list = re.findall(r"[<>=!~]+[\d.]+", spec_str)
                formatted_spec_str = ", ".join(specifiers_list)
                formatted_spec_str = formatted_spec_str.replace(">, =", ">=")
                spec = SpecifierSet(formatted_spec_str)
        except Exception as e:
            print(
                f"❌ Error: Invalid version specifier '{spec_str}' for package '{package_name}'. Skipping. Error: {e}"
            )
            is_successful = False
            continue

        def check_local_package(path, package_type):
            """Helper to check a local/precompiled package, its version, and dependencies."""
            if not path.is_dir():
                return False
            is_valid = False
            dependencies = []
            release_yaml_path = path / "release.yaml"
            if not release_yaml_path.is_file():
                if not spec_str:
                    is_valid = True
            else:
                with open(release_yaml_path, "r") as f:
                    release_info = yaml.safe_load(f) or {}
                    version_str = release_info.get("version")
                    dependencies = release_info.get("dependencies", [])
                    if not version_str:
                        if not spec_str:
                            is_valid = True
                    else:
                        try:
                            version_obj = parse_version(version_str)
                            if spec.contains(version_obj):
                                is_valid = True
                        except InvalidVersion:
                            print(
                                f"⚠️ Invalid version '{version_str}' in {package_type} release.yaml. Ignoring."
                            )
            if is_valid:
                if dependencies:
                    install_queue.extend(dependencies)
                if "version_str" in locals() and version_str:
                    print(
                        f"✅ Found suitable {package_type} package '{package_name}=={version_str}'"
                    )
                    processed_packages[package_name] = version_str
                return True
            return False

        # Priority 1: Check precompiled
        precompiled_path = (
            script_dir_path
            / "release/install"
            / package_name
            / os_type
            / os_version
            / architecture
            / build_type
        )
        if check_local_package(precompiled_path, "release/install"):
            continue

        # Priority 2: Check local source
        local_src_path = script_dir_path / "src" / package_name
        if check_local_package(local_src_path, "local source"):
            continue
        if local_src_path.is_dir():
            print(f"Skipping '{package_name}' because it exists in local source")
            continue

        # Priority 3: Find and install remote release
        repo_info = all_repositories.get(package_name)
        if not repo_info or "url" not in repo_info:
            print(f"⚠️ Warning: No repository URL found for '{package_name}'. Skipping.")
            continue

        git_url = repo_info["url"]
        match = re.search(r"git@github.com:(.*)/(.*)\.git", git_url)
        if not match:
            print(f"❌ Error: Could not parse GitHub owner/repo from URL '{git_url}'.")
            is_successful = False
            continue

        owner, repo_name = match.groups()
        token = tokens.get(owner, tokens.get("default"))
        if token:
            session.headers.update(
                {
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                }
            )
        else:  # Clear auth header if no token for this owner
            if "Authorization" in session.headers:
                del session.headers["Authorization"]

        try:
            api_url = f"https://api.github.com/repos/{owner}/{repo_name}/releases"
            response = session.get(api_url)
            response.raise_for_status()
            releases_list = response.json()

            best_release = None
            best_version = parse_version("0.0.0")

            for release in releases_list:
                tag = release.get("tag_name")
                if not tag or (release.get("prerelease") and user_type != "devel"):
                    continue
                try:
                    current_version = parse_version(tag)
                    if (
                        spec.contains(current_version)
                        and current_version >= best_version
                    ):
                        best_version = current_version
                        best_release = release
                except InvalidVersion:
                    continue

            if not best_release:
                print(
                    f"❌ Error: No release found for '{package_name}' that satisfies spec '{spec}'."
                )
                is_successful = False
                continue

            release_data = best_release
            version = release_data["tag_name"]
            if package_name in processed_packages.keys():
                installed_version = processed_packages[package_name]
                if parse_version(version) <= parse_version(installed_version):
                    print(
                        f"ℹ️  '{package_name}' version '{installed_version}' is already installed. Skipping."
                    )
                    continue
            processed_packages[package_name] = version

            asset_name = f"{package_name}-{os_type}-{os_version}-{architecture}-{build_type}-{version}.zip"
            asset_api_url = next(
                (
                    asset["url"]
                    for asset in release_data.get("assets", [])
                    if asset["name"] == asset_name
                ),
                None,
            )

            if not asset_api_url:
                print(
                    f"❌ Error: Could not find asset '{asset_name}' for release '{version}'."
                )
                is_successful = False
                continue

            install_dir = (
                script_dir_path
                / "release/install"
                / package_name
                / os_type
                / os_version
                / architecture
                / build_type
            )
            download_path = Path(script_directory) / "install" / asset_name
            download_path.parent.mkdir(parents=True, exist_ok=True)
            if install_dir.exists():
                shutil.rmtree(install_dir)
            install_dir.mkdir(parents=True, exist_ok=True)

            print("-" * 40)
            print(f"⬇️  Downloading {asset_name}...")
            download_headers = {"Accept": "application/octet-stream"}
            if token:
                download_headers["Authorization"] = f"token {token}"

            with session.get(asset_api_url, headers=download_headers, stream=True) as r:
                r.raise_for_status()
                with open(download_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)

            print(f"📂 Unzipping to {install_dir}...")
            with zipfile.ZipFile(download_path, "r") as zip_ref:
                zip_ref.extractall(install_dir)
            download_path.unlink()
            print(f"✅ Successfully installed '{package_name}=={version}'.")
            print("-" * 40)

            release_yaml_path = install_dir / "release.yaml"
            if release_yaml_path.is_file():
                with open(release_yaml_path, "r") as f:
                    release_info = yaml.safe_load(f)
                    dependencies = release_info.get("dependencies", [])
                    if dependencies:
                        install_queue.extend(dependencies)

        except Exception as e:
            print(f"❌ An error occurred while processing '{package_name}': {e}")
            is_successful = False

    if is_successful:
        print("🎉🎉🎉 Installation process finished successfully.")
    else:
        print("❌ Installation process finished with errors.")


# ============================================================================
# Click CLI Command
# ============================================================================


@click.command()
@click.argument("packages", nargs=-1, required=False)
@click.option(
    "--type",
    "-t",
    "build_type",
    type=click.Choice(["debug", "release"], case_sensitive=False),
    default="release",
    show_default=True,
    help="Build type to install",
)
def install_cli_command(packages, build_type):
    """
    Download and install packages from GitHub releases.

    \b
    Examples:
        raisin install                               # Install all packages from src/
        raisin install raisin_network                # Install release version
        raisin install raisin_network --type debug   # Install debug version
        raisin install pkg1 pkg2 pkg3                # Install multiple packages
    """
    packages = list(packages)
    if packages:
        click.echo(f"📥 Installing {len(packages)} package(s) ({build_type})...")
    else:
        click.echo(f"📥 Installing all packages from src/ ({build_type})...")
    install_command(packages, build_type)
