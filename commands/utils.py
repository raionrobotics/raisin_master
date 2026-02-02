"""
Utility functions for RAISIN.

Shared utilities used across multiple command modules.
"""

import os
import re
import sys
import yaml
import shutil
import platform
from pathlib import Path
from typing import Dict, Tuple, Optional, Union

from packaging.specifiers import SpecifierSet, InvalidSpecifier

# Import globals
from commands import globals as g


def parse_version_specifier(spec_str: str) -> Optional[SpecifierSet]:
    """Parse a version specifier string into a SpecifierSet.

    Handles various formats:
        - Empty string or None → >=0.0.0 (any version)
        - ">=1.0.0" → standard specifier
        - ">=1.0.0,<2.0.0" → compound specifier
        - "1.0.0" → treated as ==1.0.0

    Args:
        spec_str: Version specifier string (e.g., ">=1.0", "==1.1.0", "")

    Returns:
        SpecifierSet on success, None on parse failure.
    """
    try:
        spec_str = (spec_str or "").strip()
        if not spec_str:
            return SpecifierSet(">=0.0.0")

        # Extract version specifiers (handles ">=1.0, <2.0" format)
        specifiers = re.findall(r"[<>=!~]+[\d.]+", spec_str)
        if specifiers:
            formatted = ", ".join(specifiers)
            # Fix malformed "> =" to ">="
            formatted = formatted.replace(">, =", ">=").replace("< =", "<=")
            return SpecifierSet(formatted)

        # If no operators found, treat as exact version match
        if re.match(r"^[\d.]+$", spec_str):
            return SpecifierSet(f"=={spec_str}")

        return None
    except InvalidSpecifier:
        return None


def load_configuration():
    """
    Load configuration from configuration_setting.yaml and repositories.yaml.

    Returns:
        tuple: (all_repositories, tokens, user_type, packages_to_ignore, repos_to_ignore)
    """
    script_dir_path = Path(g.script_directory)
    config_path = script_dir_path / "configuration_setting.yaml"

    # Load repositories from repositories.yaml
    all_repositories = {}
    repo_path = script_dir_path / "repositories.yaml"
    if repo_path.is_file():
        with open(repo_path, "r") as f:
            repo_data = yaml.safe_load(f)
            if repo_data:
                all_repositories = repo_data

    tokens = {}
    user_type = None
    packages_to_ignore = []
    repos_to_ignore = []

    if config_path.is_file():
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
            tokens = config.get("gh_tokens", {})
            user_type = config.get("user_type")
            packages_to_ignore = config.get("packages_to_ignore", [])
            repos_to_ignore = config.get("repos_to_ignore", [])
    else:
        secrets_path = script_dir_path / "secrets.yaml"
        if secrets_path.is_file():
            with open(secrets_path, "r") as f:
                secrets = yaml.safe_load(f)
                tokens = secrets.get("gh_tokens", {})
                user_type = secrets.get("user_type")

    # Validate user_type
    if user_type is None:
        print("❌ Error: 'user_type' is not specified in configuration_setting.yaml")
        print("Please set 'user_type' to either 'user' or 'devel'")
        sys.exit(1)

    if user_type not in ["user", "devel"]:
        print(f"❌ Error: Invalid 'user_type' value: '{user_type}'")
        print(
            "'user_type' must be either 'user' or 'devel' in configuration_setting.yaml"
        )
        sys.exit(1)

    return (
        all_repositories,
        tokens,
        user_type,
        packages_to_ignore,
        repos_to_ignore,
    )


def delete_directory(directory):
    """
    Delete a directory and all its contents if it exists.

    Args:
        directory: Path to the directory to delete
    """
    if os.path.exists(directory):
        shutil.rmtree(directory)


def get_repo_name_from_path(path: Union[str, Path]) -> Optional[str]:
    """
    Determine the top-level repository name (direct child of src/) for a path.

    Args:
        path: File system path to evaluate.

    Returns:
        Optional[str]: Repository name if the path is under src/, otherwise None.
    """
    if not path:
        return None

    try:
        src_root = (Path(g.script_directory) / "src").resolve(strict=False)
        rel_path = Path(path).resolve(strict=False).relative_to(src_root)
    except ValueError:
        return None

    parts = rel_path.parts
    return parts[0] if parts else None


def is_root():
    """
    Check if the current user is root.

    Returns:
        bool: True if running as root, False otherwise
    """
    return os.geteuid() == 0


def _read_os_release() -> Dict[str, str]:
    """
    Best-effort reader for Linux /etc/os-release. Uses platform.freedesktop_os_release()
    when available; falls back to parsing the file manually. Returns {} on failure.

    Returns:
        Dict[str, str]: Dictionary of OS release information
    """
    # Python 3.10+ provides this:
    if hasattr(platform, "freedesktop_os_release"):
        try:
            return platform.freedesktop_os_release()
        except Exception:
            pass

    # Manual fallback for older Pythons
    data: Dict[str, str] = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip().strip('"')
                data[k] = v
    except Exception:
        pass
    return data


def _normalize_arch(arch: str) -> str:
    """
    Normalize common architecture names across platforms.

    Args:
        arch: Raw architecture string from platform.machine()

    Returns:
        str: Normalized architecture name
    """
    m = (arch or "").lower()
    mapping = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86_64": "x86_64",
        "i386": "x86",
        "i686": "x86",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "armv7l",
        "armv6l": "armv6l",
        "ppc64le": "ppc64le",
        "ppc64": "ppc64",
        "s390x": "s390x",
    }
    return mapping.get(m, arch)


def get_os_info() -> Tuple[str, str, str, str, str, dict]:
    """
    Returns (os_type, architecture, os_version, vs_path, ninja_path, developer_env)
    across Linux/macOS/Windows.

    - os_type:
        Linux -> distro ID if available (e.g., 'ubuntu', 'fedora'), otherwise 'linux'
        macOS -> 'macos'
        Windows -> 'windows'
        Other/Unix -> platform.system().lower()
    - architecture: normalized machine type (e.g., 'x86_64', 'arm64')
    - os_version:
        Linux -> VERSION_ID from os-release if available, else kernel release
        macOS -> product version (e.g., '14.5'), else kernel release
        Windows -> major.minor.build from sys.getwindowsversion(), else win32_ver()/release()
    - vs_path: Visual Studio path (Windows only)
    - ninja_path: Ninja build tool path (Windows only)
    - developer_env: Developer environment variables (Windows only)

    Returns:
        Tuple[str, str, str, str, str, dict]: OS information tuple
    """
    # Import here to avoid circular dependency
    from commands.build_tools import find_build_tools

    system = platform.system()
    arch = _normalize_arch(platform.machine())
    vs_path2 = ""
    ninja_path2 = ""
    developer_env2 = dict()

    if system == "Linux":
        osr = _read_os_release()
        os_type2 = (osr.get("ID") or "linux").lower()
        os_version2 = osr.get("VERSION_ID") or platform.release()

    elif system == "Darwin":
        os_type2 = "macos"
        mac_release, _, _ = platform.mac_ver()
        os_version2 = mac_release or platform.release()

    elif system == "Windows":
        vs_path2, ninja_path2, developer_env2 = find_build_tools("amd64")
        os_type2 = "windows"
        try:
            win = (
                sys.getwindowsversion()
            )  # (major, minor, build, platform, service_pack)
            # os_version2 = f"{win.major}.{win.minor}.{win.build}"
            os_version2 = "10or11"
        except Exception:
            release, version, _, _ = platform.win32_ver()
            os_version2 = version or release or platform.release()

    else:  # e.g., FreeBSD, OpenBSD, SunOS, etc.
        os_type2 = system.lower() if system else "unknown"
        os_version2 = platform.release()

    return os_type2, arch, os_version2, vs_path2, ninja_path2, developer_env2


def init_environment(script_file_path, yes_flag):
    """
    Initialize the environment and global state.

    Args:
        script_file_path: Path to the main script file
        yes_flag: Auto-confirm all prompts if True

    This function initializes all global variables and sets up the environment.
    """
    script_directory = Path(
        os.path.dirname(os.path.realpath(script_file_path))
    ).as_posix()
    (
        os_type,
        architecture,
        os_version,
        visual_studio_path,
        ninja_path,
        developer_env,
    ) = get_os_info()

    # Initialize commands.globals for modular commands
    g.init_globals(
        script_directory=script_directory,
        os_type=os_type,
        architecture=architecture,
        os_version=os_version,
        ninja_path=ninja_path,
        visual_studio_path=visual_studio_path,
        developer_env=developer_env,
        build_pattern=[],
        vcpkg_dependencies=set(),
        always_yes=yes_flag,
    )

    delete_directory(os.path.join(script_directory, "temp"))
