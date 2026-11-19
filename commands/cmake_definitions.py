"""Validate generic cache definitions before invoking CMake with an argv list."""
import re
from typing import Sequence

# These select the build layout/toolchain managed by the CLI, rather than a
# package feature. In particular, publish must install into its archive tree.
_MANAGED_KEYS = frozenset({
    "CMAKE_BUILD_TYPE", "CMAKE_INSTALL_PREFIX", "CMAKE_TOOLCHAIN_FILE",
    "CMAKE_GENERATOR", "CMAKE_GENERATOR_PLATFORM", "CMAKE_GENERATOR_TOOLSET",
    "CMAKE_MAKE_PROGRAM",
})


def cmake_definition_args(definitions: Sequence[str] = ()) -> list[str]:
    """Return one -D argv element per KEY=VALUE; package semantics stay in CMake."""
    args = []
    seen = set()
    for definition in definitions:
        key, separator, _ = definition.partition("=")
        if (not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                or any(ord(char) < 32 or ord(char) == 127 for char in definition)):
            raise ValueError("--cmake-define requires KEY=VALUE without control characters")
        if key in _MANAGED_KEYS:
            raise ValueError(f"{key} is managed by the CLI and cannot be overridden")
        if key in seen:
            raise ValueError(f"Duplicate --cmake-define key: {key}")
        seen.add(key)
        args.append("-D" + definition)
    return args
