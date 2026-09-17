"""
Global configuration and state for RAISIN.

This module holds global variables that are initialized once
and shared across all command modules.
"""

from pathlib import Path

# Build pattern filters
build_pattern = []

# System information (initialized in main)
os_type = ""
architecture = ""
os_version = ""
script_directory = ""

# Root for generated message/service headers. Target-scoped: a cross build
# points this at its own build directory so it never shares or clobbers the
# host's generated/ tree.
generated_dir = ""

# Windows-specific
ninja_path = ""
visual_studio_path = ""
developer_env = dict()
vcpkg_dependencies = set()


def init_globals(**kwargs):
    """
    Initialize global variables from main script.

    Args:
        os_type: Operating system type
        architecture: System architecture
        os_version: OS version
        script_directory: Root directory of the script
        ninja_path: Path to ninja (Windows)
        visual_studio_path: Path to Visual Studio (Windows)
        developer_env: Developer environment variables (Windows)
    """
    global os_type, architecture, os_version, script_directory, generated_dir
    global ninja_path, visual_studio_path, developer_env

    os_type = kwargs.get("os_type", "")
    architecture = kwargs.get("architecture", "")
    os_version = kwargs.get("os_version", "")
    script_directory = kwargs.get("script_directory", "")
    generated_dir = kwargs.get(
        "generated_dir", str(Path(script_directory) / "generated") if script_directory else ""
    )
    ninja_path = kwargs.get("ninja_path", "")
    visual_studio_path = kwargs.get("visual_studio_path", "")
    developer_env = kwargs.get("developer_env", {})
