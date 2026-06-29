"""
Shared build-directory resolution for RAISIN commands.

Both `raisin test` and `raisin cppcheck` need to locate the CMake build
directory for a given build type. Keeping these helpers here (rather than in
either command module) avoids a circular import between commands.test and
commands.cppcheck.
"""

from pathlib import Path
from typing import Optional

import click

from commands import globals as g


def _get_build_dir_from_config(build_type: str) -> Path:
    config_path = Path(g.script_directory) / "configuration_setting.yaml"
    if not config_path.is_file():
        return Path(g.script_directory) / f"cmake-build-{build_type}"

    try:
        import yaml
    except ImportError as e:
        raise click.ClickException(
            "Missing dependency 'pyyaml'; required to read configuration_setting.yaml"
        ) from e

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except Exception as e:
        raise click.ClickException(f"Failed to read {config_path}: {e}") from e

    key = "release_build_dir" if build_type == "release" else "debug_build_dir"
    raw = config.get(key)
    if not raw:
        return Path(g.script_directory) / f"cmake-build-{build_type}"

    build_dir = Path(str(raw))
    if not build_dir.is_absolute():
        build_dir = (Path(g.script_directory) / build_dir).resolve()
    return build_dir


def resolve_build_dir(build_type: Optional[str]) -> Path:
    preferred = (build_type or "release").lower().strip() or "release"
    build_dir = _get_build_dir_from_config(preferred)

    if not build_dir.is_dir() and not build_type and preferred == "release":
        debug_dir = _get_build_dir_from_config("debug")
        if debug_dir.is_dir():
            click.echo(
                f"⚠️  {build_dir} not found; falling back to {debug_dir}",
                err=True,
            )
            build_dir = debug_dir
    return build_dir
