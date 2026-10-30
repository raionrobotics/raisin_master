"""FMS runtime build selection and archive metadata."""

import json
import re
from pathlib import Path
from typing import Optional, Union


FMS_RUNTIME_PACKAGE = "raisin_behavior_tree_plugin"
FMS_RUNTIME_OPTION = "RAISIN_BUILD_FMS_RUNTIME"


def _skip_cmake_comment(source: str, position: int) -> int:
    """Return the first position after a CMake comment beginning at ``#``."""
    bracket = re.match(r"\[(=*)\[", source[position + 1 :])
    if bracket:
        closing = "]" + bracket.group(1) + "]"
        end = source.find(closing, position + 1 + bracket.end())
        return len(source) if end < 0 else end + len(closing)
    end = source.find("\n", position + 1)
    return len(source) if end < 0 else end + 1


def _skip_cmake_quoted(source: str, position: int) -> int:
    """Return the first position after a CMake quoted argument."""
    position += 1
    while position < len(source):
        if source[position] == "\\":
            position += 2
        elif source[position] == '"':
            return position + 1
        else:
            position += 1
    return len(source)


def _bracket_argument_end(source: str, position: int) -> Optional[int]:
    """Return the position after a CMake bracket argument, if one starts here."""
    bracket = re.match(r"\[(=*)\[", source[position:])
    if not bracket:
        return None
    closing = "]" + bracket.group(1) + "]"
    end = source.find(closing, position + bracket.end())
    return len(source) if end < 0 else end + len(closing)


def _skip_cmake_command(source: str, open_paren: int) -> int:
    """Skip a complete command, ignoring parentheses in comments and literals."""
    depth = 1
    position = open_paren + 1
    while position < len(source):
        char = source[position]
        if char == "#":
            position = _skip_cmake_comment(source, position)
        elif char == '"':
            position = _skip_cmake_quoted(source, position)
        elif char == "[":
            end = _bracket_argument_end(source, position)
            position = end if end is not None else position + 1
        elif char == "(":
            depth += 1
            position += 1
        elif char == ")":
            depth -= 1
            position += 1
            if depth == 0:
                return position
        else:
            position += 1
    return len(source)


def _skip_cmake_space_and_comments(source: str, position: int) -> int:
    while position < len(source):
        if source[position].isspace() or source[position] == ";":
            position += 1
        elif source[position] == "#":
            position = _skip_cmake_comment(source, position)
        else:
            break
    return position


def _first_cmake_argument(source: str, position: int) -> Optional[str]:
    position = _skip_cmake_space_and_comments(source, position)
    if position >= len(source) or source[position] == ")":
        return None
    if source[position] == '"':
        end = _skip_cmake_quoted(source, position)
        if end == len(source) and not source.endswith('"'):
            return None
        return source[position + 1 : end - 1]
    if source[position] == "[":
        end = _bracket_argument_end(source, position)
        if end is None:
            return None
        opening = re.match(r"\[(=*)\[", source[position:])
        assert opening is not None
        closing = "]" + opening.group(1) + "]"
        return source[position + opening.end() : end - len(closing)]
    match = re.match(r"[^\s()#;]+", source[position:])
    return match.group(0) if match else None


def _declares_cmake_option(source: str, variable: str) -> bool:
    """Find an actual top-level CMake option() command, not text in literals/comments."""
    position = 0
    while position < len(source):
        position = _skip_cmake_space_and_comments(source, position)
        if position >= len(source):
            break
        command = re.match(r"[A-Za-z_][A-Za-z0-9_]*", source[position:])
        if not command:
            position += 1
            continue
        after_name = _skip_cmake_space_and_comments(
            source, position + command.end()
        )
        if after_name >= len(source) or source[after_name] != "(":
            position += command.end()
            continue
        if (
            command.group(0).lower() == "option"
            and _first_cmake_argument(source, after_name + 1) == variable
        ):
            return True
        position = _skip_cmake_command(source, after_name)
    return False


def fms_runtime_cmake_args(
    script_directory: str,
    enabled: bool,
    package_source_dir: Optional[Union[str, Path]] = None,
) -> list[str]:
    """Set the feature explicitly when declared; fail closed on unsupported opt-in."""
    if package_source_dir is None:
        cmake_file = (
            Path(script_directory)
            / "src"
            / "raisin_plugin"
            / FMS_RUNTIME_PACKAGE
            / "CMakeLists.txt"
        )
    else:
        cmake_file = Path(package_source_dir) / "CMakeLists.txt"
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
    if not _declares_cmake_option(source, FMS_RUNTIME_OPTION):
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
