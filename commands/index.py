"""
Index commands for RAISIN.

Lists available packages and versions from GitHub releases or local installations.
"""

import re
import os
import yaml
import requests
import click
import concurrent.futures
from pathlib import Path
from typing import List, Tuple, Dict, Optional, Set
from packaging.version import parse as parse_version
from packaging.version import InvalidVersion
from packaging.requirements import Requirement
from packaging.version import Version
from packaging.specifiers import InvalidSpecifier

# Import globals, constants, and utilities
from commands import globals as g
from commands.constants import Colors
from commands.utils import load_configuration


def index_release_command(package_name=None):
    """
    List available packages from GitHub releases.

    If package_name is provided, lists all versions for that package.
    Otherwise, lists all available packages with their latest versions.

    Args:
        package_name (str, optional): Specific package to list versions for
    """
    if package_name:
        list_github_release_versions(package_name)
    else:
        list_all_available_packages()


def list_all_available_packages():
    """
    Fetches and lists all available packages from GitHub repositories
    with their latest versions that have valid assets for the current system.
    """
    # Access globals
    os_type = g.os_type
    os_version = g.os_version
    architecture = g.architecture

    # Get System Info for Asset Matching
    try:
        print(
            f"ℹ️  Checking for assets compatible with: {os_type}-{os_version}-{architecture}"
        )
    except FileNotFoundError:
        print("❌ Error: Could not determine OS information from /etc/os-release.")
        return

    # Load all repository configurations
    all_repositories, tokens, user_type, _, _ = load_configuration()

    if not all_repositories:
        print("🤷 No packages found in configuration_setting.yaml.")
        return

    if not tokens:
        print("❌ Error: No GitHub tokens found in configuration_setting.yaml")
        return

    session = requests.Session()

    def get_versions_for_package(package_name):
        """
        Fetches and processes release versions with valid assets for a single package.
        Colors prerelease vs release.
        """
        repo_info = all_repositories.get(package_name)
        if not repo_info or "url" not in repo_info:
            return package_name, ["(No repository URL found)"]

        git_url = repo_info["url"]
        match = re.search(r"git@github.com:(.*)/(.*)\.git", git_url)
        if not match:
            return package_name, ["(Could not parse repository URL)"]

        owner, repo_name = match.groups()
        token = tokens.get(owner, tokens.get("default"))
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"

        try:
            api_url = f"https://api.github.com/repos/{owner}/{repo_name}/releases"
            response = session.get(api_url, headers=headers, timeout=10)
            response.raise_for_status()
            releases_list = response.json()

            if not releases_list:
                return package_name, ["(No releases found)"]

            # Collect (version_obj, is_prerelease) for releases that have a matching asset
            available_versions = []
            for release in releases_list:
                tag = release.get("tag_name")
                if not tag:
                    continue
                is_prerelease = bool(release.get("prerelease"))
                try:
                    version_obj = parse_version(tag)

                    # Construct the expected asset filenames
                    expected_asset_release = f"{package_name}-{os_type}-{os_version}-{architecture}-release-{tag}.zip"
                    expected_asset_debug = f"{package_name}-{os_type}-{os_version}-{architecture}-debug-{tag}.zip"

                    # Check for a matching asset
                    for asset in release.get("assets", []):
                        if (
                            asset["name"] == expected_asset_release
                            or asset["name"] == expected_asset_debug
                        ):
                            available_versions.append((version_obj, is_prerelease))
                            break
                except InvalidVersion:
                    continue

            if not available_versions:
                return package_name, ["(No compatible assets found)"]

            # Sort newest-first by version, then colorize prerelease vs release
            sorted_versions = sorted(
                available_versions, key=lambda x: x[0], reverse=True
            )

            colored = []
            for version_obj, is_prerelease in sorted_versions[:3]:
                text = str(version_obj)  # normalized version string
                if is_prerelease:
                    colored.append(f"{Colors.YELLOW}{text}{Colors.RESET}")
                else:
                    colored.append(f"{Colors.GREEN}{text}{Colors.RESET}")

            return package_name, colored

        except requests.exceptions.RequestException:
            return package_name, ["(API Error)"]

    # Fetch versions concurrently for all packages
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_package = {
            executor.submit(get_versions_for_package, name): name
            for name in all_repositories.keys()
        }
        for future in concurrent.futures.as_completed(future_to_package):
            name, version_list = future.result()
            results[name] = version_list

    # Print the formatted results
    print("\nAvailable packages and latest versions:")
    for package_name in sorted(results.keys()):
        versions_str = ", ".join(results[package_name])
        print(f"  - {package_name}: {versions_str}")


def list_github_release_versions(package_name):
    """
    Fetches and lists all available release versions of a package from its GitHub
    repository that have a valid asset for the current system.

    Args:
        package_name (str): Name of the package to list versions for
    """
    print(f"🔍 Finding available versions with assets for '{package_name}'...")

    # Access globals
    os_type = g.os_type
    os_version = g.os_version
    architecture = g.architecture
    script_directory = g.script_directory

    script_dir_path = Path(script_directory)

    # Get System Info for Asset Matching
    try:
        print(
            f"ℹ️  Checking for assets compatible with: {os_type}-{os_version}-{architecture}"
        )
    except FileNotFoundError:
        print("❌ Error: Could not determine OS information from /etc/os-release.")
        return

    # Load Repository and Secrets Configuration
    all_repositories, tokens, user_type, _, _ = load_configuration()

    if not all_repositories:
        print("❌ Error: No repositories found in configuration_setting.yaml")
        return
    if not tokens:
        print("❌ Error: No GitHub tokens found in configuration_setting.yaml")
        return

    # Find the repository URL for the package
    repo_info = all_repositories.get(package_name)
    if not repo_info or "url" not in repo_info:
        print(
            f"❌ Error: No repository URL found for '{package_name}' in configuration_setting.yaml."
        )
        return

    # Parse Owner/Repo from URL
    git_url = repo_info["url"]
    match = re.search(r"git@github.com:(.*)/(.*)\.git", git_url)
    if not match:
        print(f"❌ Error: Could not parse GitHub owner/repo from URL '{git_url}'.")
        return

    owner, repo_name = match.groups()

    # Query the GitHub API
    session = requests.Session()
    token = tokens.get(owner, tokens.get("default"))
    if token:
        session.headers.update(
            {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            }
        )

    try:
        api_url = f"https://api.github.com/repos/{owner}/{repo_name}/releases"
        response = session.get(api_url)
        response.raise_for_status()
        releases_list = response.json()

        if not releases_list:
            print(f"🤷 No releases found for repository '{owner}/{repo_name}'.")
            return

        # Parse, Match Assets, Sort, and Display Versions
        available_versions = []
        for release in releases_list:
            tag = release.get("tag_name")
            if not tag or release.get("prerelease"):
                continue

            try:
                version_obj = parse_version(tag)
                # Construct the expected asset filenames for release and debug builds
                expected_asset_release = f"{package_name}-{os_type}-{os_version}-{architecture}-release-{tag}.zip"
                expected_asset_debug = f"{package_name}-{os_type}-{os_version}-{architecture}-debug-{tag}.zip"

                # Check if any asset in this release matches our expected filename
                for asset in release.get("assets", []):
                    if (
                        asset["name"] == expected_asset_release
                        or asset["name"] == expected_asset_debug
                    ):
                        available_versions.append(version_obj)
                        break  # Found a valid asset, no need to check others in this release
            except InvalidVersion:
                continue

        if not available_versions:
            print(f"🤷 No releases with compatible assets found for '{package_name}'.")
            return

        # Sort from newest to oldest
        sorted_versions = sorted(available_versions, reverse=True)

        print(f"Available versions for {package_name} ({owner}/{repo_name}):")
        for v in sorted_versions:
            print(f"  {v}")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(
                f"❌ Error: Repository '{owner}/{repo_name}' not found on GitHub or you lack permissions."
            )
        else:
            print(f"❌ HTTP Error fetching release data: {e}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error: {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")


def index_local_command():
    """
    Lists local packages and validates their dependencies.
    Scans both src/ and release/install/ directories for packages.
    """
    script_directory = g.script_directory
    targets_to_process = find_target_yamls(
        Path(script_directory) / "src", Path(script_directory) / "release" / "install"
    )

    if not targets_to_process:
        print("Found no packages with release.yaml files in specified locations.")
        return

    # PASS 1: Run parallel parsing
    # all_parse_results format: [(name, ver, raw_deps_list, origin), ...]
    all_parse_results = run_parallel_parse(targets_to_process)

    # Build the Package Database for validation
    # This map contains ONLY valid packages that can be dependencies.
    package_db: Dict[str, str] = {}
    for name, ver, deps_list, origin in all_parse_results:
        if ver not in ("ERROR", "N/A"):
            package_db[name] = ver

    # PASS 2: Run parallel validation using the database
    # final_print_data format: [(name, ver, colored_deps_str, origin), ...]
    final_print_data = run_parallel_validation(all_parse_results, package_db)

    # Sort the final list alphabetically
    final_print_data.sort(key=lambda x: x[0])

    # Print the aligned, colored results
    print_aligned_results(final_print_data)


# ============================================================================
# Helper Functions for index local
# ============================================================================


def find_target_yamls(
    priority_dir: Path, fallback_dir: Path
) -> List[Tuple[str, Path, str]]:
    """
    Scans directories for 'release.yaml' files, tagging their origin.

    Args:
        priority_dir: Priority directory to scan first (e.g., src/)
        fallback_dir: Fallback directory to scan (e.g., release/install/)

    Returns:
        List of tuples: [(package_name, yaml_path, origin_tag), ...]
    """
    targets: List[Tuple[str, Path, str]] = []
    found_packages: Set[str] = set()

    # 1. Scan the PRIORITY directory first (src)
    if priority_dir.is_dir():
        for item in priority_dir.iterdir():
            if item.is_dir():
                yaml_file = item / "release.yaml"
                if yaml_file.is_file():
                    pkg_name = item.name
                    targets.append((pkg_name, yaml_file, "source"))
                    found_packages.add(pkg_name)
    else:
        print(f"Warning: Priority directory not found, skipping: {priority_dir}")

    # 2. Scan the FALLBACK directory (release/install)
    if fallback_dir.is_dir():
        for item in fallback_dir.iterdir():
            if item.is_dir():
                pkg_name = item.name
                if pkg_name not in found_packages:
                    os_type = g.os_type
                    os_version = g.os_version
                    architecture = g.architecture

                    yaml_file_release = (
                        item
                        / os_type
                        / os_version
                        / architecture
                        / "release/release.yaml"
                    )
                    yaml_file_debug = (
                        item
                        / os_type
                        / os_version
                        / architecture
                        / "debug/release.yaml"
                    )
                    if yaml_file_release.is_file():
                        targets.append((pkg_name, yaml_file_release, "release"))
                    elif yaml_file_debug.is_file():
                        targets.append((pkg_name, yaml_file_debug, "release"))
    else:
        print(f"Warning: Fallback directory not found, skipping: {fallback_dir}")

    return targets


def parse_package_yaml(
    pkg_name: str, yaml_path: Path
) -> Tuple[str, str, Optional[List[str]]]:
    """
    Worker function for Pass 1 (Parse).
    Parses a single YAML file and returns the RAW dependency list.

    Args:
        pkg_name: Name of the package
        yaml_path: Path to the release.yaml file

    Returns:
        A tuple: (package_name, version_string, raw_deps_list_or_None)
    """
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            return (pkg_name, "ERROR", ["Invalid or empty YAML"])

        version = str(data.get("version", "N/A"))

        # Get the raw list of dependencies (or None)
        deps_list: Optional[List[str]] = data.get("dependencies")

        return (pkg_name, version, deps_list)

    except yaml.YAMLError as e:
        return (pkg_name, "ERROR", [f"YAML Parse Error: {e}"])
    except Exception as e:
        return (pkg_name, "ERROR", [f"File Read Error: {e}"])


def run_parallel_parse(
    targets: List[Tuple[str, Path, str]],
) -> List[Tuple[str, str, Optional[List[str]], str]]:
    """
    Manages the first thread pool (Pass 1) to parse all files.

    Args:
        targets: List of tuples (pkg_name, yaml_path, origin_tag)

    Returns:
        List of tuples: [(pkg_name, ver_str, raw_deps_list, origin_tag), ...]
    """
    all_parse_results = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures_map = {
            executor.submit(parse_package_yaml, pkg_name, yaml_path): (
                pkg_name,
                origin_tag,
            )
            for pkg_name, yaml_path, origin_tag in targets
        }

        for future in concurrent.futures.as_completed(futures_map):
            pkg_name_for_error, origin = futures_map[future]
            try:
                # parser_result is (pkg_name, ver, deps_list)
                parser_result = future.result()
                all_parse_results.append(parser_result + (origin,))
            except Exception as e:
                print(f"Critical error processing package {pkg_name_for_error}: {e}")
                all_parse_results.append(
                    (pkg_name_for_error, "CRITICAL ERROR", [str(e)], origin)
                )

    return all_parse_results


def process_and_color_deps(
    pkg_name: str,
    version: str,
    deps_list: Optional[List[str]],
    origin: str,
    package_db: Dict[str, str],
) -> Tuple[str, str, str, str]:
    """
    Worker function for Pass 2 (Validate).
    Takes one package's raw deps and validates them against the complete DB.

    Args:
        pkg_name: Package name
        version: Version string
        deps_list: List of dependency specifications
        origin: Origin tag (source or release)
        package_db: Database of available packages {name: version}

    Returns:
        Final tuple for printing: (pkg_name, version, colored_deps_string, origin)
    """

    # If this package itself failed parsing (Pass 1), its version is "ERROR"
    # and its "deps_list" is actually the error message. Color it all red.
    if version == "ERROR":
        deps_str = (
            f"{Colors.RED}{', '.join(deps_list or ['Unknown Error'])}{Colors.RESET}"
        )
        return (pkg_name, version, deps_str, origin)

    # If parsing was successful but there are no dependencies, return "None"
    if not deps_list:
        return (pkg_name, version, "None", origin)

    # Begin validating the list of dependencies one by one
    colored_deps = []
    for dep_spec_string in deps_list:
        try:
            # Use 'packaging' library to parse the requirement string
            # e.g., "pkg_b>=1.0.0,<2.0.0" or just "pkg_c"
            req = Requirement(dep_spec_string)

        except (InvalidSpecifier, Exception):
            # Handle malformed requirement strings like "pkg_b>>>1"
            colored_deps.append(
                f"{Colors.RED}{dep_spec_string} (Invalid Spec){Colors.RESET}"
            )
            continue

        # 1. Check if the dependency EXISTS in our database
        if req.name not in package_db:
            colored_deps.append(
                f"{Colors.RED}{dep_spec_string} (Missing){Colors.RESET}"
            )
            continue

        # 2. If it exists, check if the found version MATCHES the specifier
        try:
            actual_version_str = package_db[req.name]
            actual_version = Version(actual_version_str)

            # This is the core check using the 'packaging' library:
            # req.specifier is a SpecifierSet object (e.g., ">=1.0.0,<2.0.0")
            # The 'in' operator checks if the Version object satisfies the constraints.
            # If the specifier is empty (e.g., just "pkg_c"), it matches any version.
            if actual_version in req.specifier:
                colored_deps.append(f"{Colors.GREEN}{dep_spec_string}{Colors.RESET}")
            else:
                # Found, but version is wrong (e.g., we require >=1.0 but found 0.9)
                colored_deps.append(
                    f"{Colors.RED}{dep_spec_string} (Wrong Version){Colors.RESET}"
                )

        except InvalidVersion:
            # The dependency we found has an invalid version (e.g., "N/A" or "ERROR")
            # It cannot satisfy any version requirement.
            colored_deps.append(
                f"{Colors.RED}{dep_spec_string} (Dep has Invalid Ver: {actual_version_str}){Colors.RESET}"
            )
        except Exception as e:
            # Catch-all for other unexpected validation errors
            colored_deps.append(
                f"{Colors.RED}{dep_spec_string} (Check Error: {e}){Colors.RESET}"
            )

    # Join all the individually colored strings with a comma
    final_deps_str = ", ".join(colored_deps)
    return (pkg_name, version, final_deps_str, origin)


def run_parallel_validation(
    all_pkg_data: List[Tuple[str, str, Optional[List[str]], str]],
    package_db: Dict[str, str],
) -> List[Tuple[str, str, str, str]]:
    """
    Manages the second thread pool (Pass 2) to validate all dependencies.

    Args:
        all_pkg_data: List of parsed package data
        package_db: Database of available packages {name: version}

    Returns:
        List of validated and colored results for printing
    """
    final_print_data = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures_map = {
            executor.submit(
                process_and_color_deps, name, ver, deps, origin, package_db
            ): name
            for name, ver, deps, origin in all_pkg_data
        }

        for future in concurrent.futures.as_completed(futures_map):
            try:
                # Result is the final 4-tuple for printing
                result = future.result()
                final_print_data.append(result)
            except Exception as e:
                pkg_name = futures_map[future]
                print(f"Critical error during validation for {pkg_name}: {e}")

    return final_print_data


def print_aligned_results(results: List[Tuple[str, str, str, str]]):
    """
    Takes the final (colored) results and prints them in an aligned format.
    This logic handles the color codes in the package prefix correctly.

    Args:
        results: List of tuples (name, version, colored_deps_str, origin)
    """
    if not results:
        print("No package data to display.")
        return

    # --- Alignment Calculation (Pre-pass) ---
    processed_data = []
    max_name_len = 0
    max_ver_len = 0

    for name, ver, colored_deps_str, origin in results:
        raw_full_name = f"({origin}) {name}"
        processed_data.append((raw_full_name, ver, colored_deps_str, origin))

        if len(raw_full_name) > max_name_len:
            max_name_len = len(raw_full_name)
        if len(ver) > max_ver_len:
            max_ver_len = len(ver)

    # --- Print Header and Results ---
    print("\n--- Package Version Report ---")
    for raw_name, ver, colored_deps_str, origin in processed_data:

        padded_raw_name = f"{raw_name:<{max_name_len}}"

        if origin == "source":
            color = Colors.GREEN
            tag = "(source)"
        else:  # origin == "release"
            color = Colors.BLUE
            tag = "(release)"

        # Replace the raw tag with the colored one to preserve alignment
        colored_name = padded_raw_name.replace(tag, f"{color}{tag}{Colors.RESET}")

        padded_ver = f"{ver:<{max_ver_len}}"

        # Print the final line. The dependency string is the last column,
        # so its variable visual length (due to color codes) is fine.
        print(
            f"{colored_name} , version: {padded_ver} , dependencies: {colored_deps_str}"
        )


# ============================================================================
# Click CLI Commands
# ============================================================================


@click.group()
def index_group():
    """
    List available packages (local or remote).

    \b
    Examples:
        raisin index local                   # List local packages
        raisin index release                 # List all remote packages
        raisin index release raisin_network  # List versions of a package
    """
    pass


@index_group.command("release")
@click.argument("package", required=False)
def index_release_cli(package):
    """
    List packages available on GitHub releases.

    \b
    Examples:
        raisin index release                 # List all packages
        raisin index release raisin_network  # Show versions of package
    """
    if package:
        index_release_command(package)
    else:
        index_release_command()


@index_group.command("local")
def index_local_cli():
    """
    List packages built locally with dependency validation.

    \b
    Examples:
        raisin index local                   # Show all local packages
    """
    index_local_command()
