"""
Global configuration and state for RAISIN.

This module holds global variables that are initialized once
and shared across all command modules.
"""

# Build pattern filters
build_pattern = []

# System information (initialized in main)
os_type = ""
architecture = ""
os_version = ""
script_directory = ""

# Windows-specific
ninja_path = ""
visual_studio_path = ""
developer_env = dict()
vcpkg_dependencies = set()

# CLI flags
always_yes = False


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
        always_yes: always yes to all prompts
    """
    global os_type, architecture, os_version, script_directory
    global ninja_path, visual_studio_path, developer_env, always_yes

    os_type = kwargs.get("os_type", "")
    architecture = kwargs.get("architecture", "")
    os_version = kwargs.get("os_version", "")
    script_directory = kwargs.get("script_directory", "")
    ninja_path = kwargs.get("ninja_path", "")
    visual_studio_path = kwargs.get("visual_studio_path", "")
    developer_env = kwargs.get("developer_env", {})
    always_yes = kwargs.get("always_yes", False)
