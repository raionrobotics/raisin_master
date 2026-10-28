"""FMS runtime build selection and archive metadata."""

import json
import re
from pathlib import Path


FMS_RUNTIME_PACKAGE = "raisin_behavior_tree_plugin"
FMS_RUNTIME_OPTION = "RAISIN_BUILD_FMS_RUNTIME"


def fms_runtime_cmake_args(script_directory: str, enabled: bool) -> list[str]:
    """Set the feature explicitly when declared; fail closed on unsupported opt-in."""
    cmake_file = (
        Path(script_directory)
        / "src"
        / "raisin_plugin"
        / FMS_RUNTIME_PACKAGE
        / "CMakeLists.txt"
    )
    try:
        source = cmake_file.read_text(encoding="utf-8")
    except OSError as exc:
        if not enabled:
            return []
        raise ValueError(
            "FMS runtime requested, but the raisin_plugin source is unavailable"
        ) from exc

    # CMake cache variable names are case-sensitive; a differently-cased
    # declaration would not be controlled by the exact -D option below.
    option_pattern = rf"(?m)^[ \t]*option\s*\(\s*{re.escape(FMS_RUNTIME_OPTION)}\b"
    if not re.search(option_pattern, source):
        if not enabled:
            return []
        raise ValueError(
            "FMS runtime requested, but the selected raisin_plugin source does not "
            f"declare {FMS_RUNTIME_OPTION}"
        )

    return [f"-D{FMS_RUNTIME_OPTION}={'ON' if enabled else 'OFF'}"]


def write_fms_build_profile(install_directory: str, enabled: bool) -> Path:
    """Write the selected FMS feature into the package's immutable archive tree."""
    profile_path = (
        Path(install_directory) / "share" / "raisin" / "build-profile.json"
    )
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "package": FMS_RUNTIME_PACKAGE,
                "features": {"fms_runtime": enabled},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return profile_path
