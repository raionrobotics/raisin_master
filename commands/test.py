"""
Test command for RAISIN.

Runs all unit test executables built by CMake that end with `_unittest`.
"""

import os
import platform
import subprocess
from pathlib import Path

import click
from typing import Optional

from commands import globals as g


def _is_unittest_executable(path: Path) -> bool:
    if not path.is_file():
        return False
    if not path.stem.endswith("_unittest"):
        return False
    if platform.system().lower() == "windows":
        return path.suffix.lower() in {".exe", ".bat", ".cmd"}
    return os.access(path, os.X_OK)

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


def run_unittests(build_type: Optional[str]) -> None:
    requested = (build_type or "").lower().strip()
    if requested and requested not in {"debug", "release"}:
        raise click.ClickException("build_type must be 'debug' or 'release'")

    preferred = requested or "release"
    build_dir = _get_build_dir_from_config(preferred)

    if not build_dir.is_dir() and not requested and preferred == "release":
        debug_dir = _get_build_dir_from_config("debug")
        if debug_dir.is_dir():
            click.echo(
                f"⚠️  {build_dir} not found; falling back to {debug_dir}",
                err=True,
            )
            build_dir = debug_dir

    if not build_dir.is_dir():
        build_type_for_message = requested or preferred
        raise click.ClickException(
            f"Build directory not found: {build_dir}\n"
            f"Run: python3 raisin.py build --type {build_type_for_message}"
        )

    executables = sorted(
        [p for p in build_dir.rglob("*_unittest*") if _is_unittest_executable(p)],
        key=lambda p: str(p),
    )

    if not executables:
        raise click.ClickException(
            f"No unit test executables found under: {build_dir}\n"
            "Expected files whose name ends with '_unittest'."
        )

    click.echo(f"🧪 Running {len(executables)} unit test(s) in {build_dir}")

    failures = 0
    for exe in executables:
        click.echo(f"\n▶ {exe}")
        try:
            subprocess.run([str(exe)], cwd=build_dir, check=True)
        except subprocess.CalledProcessError as e:
            failures += 1
            click.echo(f"❌ Failed with exit code {e.returncode}: {exe}", err=True)

    if failures:
        raise click.ClickException(f"{failures} test(s) failed.")

    click.echo("\n✅ All unit tests passed.")


@click.command(name="test")
@click.argument(
    "build_type",
    required=False,
    type=click.Choice(["debug", "release"], case_sensitive=False),
)
def test_command(build_type: Optional[str]) -> None:
    """
    Run all unit tests from the CMake build folder.

    \b
    Examples:
        python3 raisin.py test            # runs release tests (default)
        python3 raisin.py test debug      # runs debug tests
        python3 raisin.py test release    # runs release tests
    """
    try:
        run_unittests(build_type)
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e)) from e
