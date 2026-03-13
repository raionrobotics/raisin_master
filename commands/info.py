"""
Info command for RAISIN.

Prints build environment diagnostics for debugging cross-architecture builds.
"""

import os
import platform

import click

from commands import globals as g
from commands.utils import (
    is_qemu_emulated,
    get_build_jobs,
    get_default_portable_march,
    SUPPORTED_ARCHITECTURES,
)


def _detect_compiler_version(compiler: str) -> str:
    """Get the version string for a compiler, or 'not found'."""
    import subprocess

    try:
        result = subprocess.run(
            [compiler, "--version"], capture_output=True, text=True, timeout=5
        )
        # First line typically contains the version info
        return result.stdout.splitlines()[0] if result.stdout else "not found"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "not found"


@click.command()
def info_command():
    """
    Print build environment diagnostics.

    \\b
    Shows architecture, QEMU status, compiler info, -march flags,
    and parallelism settings. Useful for debugging cross-arch builds.

    \\b
    Examples:
        raisin info
    """
    machine = platform.machine()
    qemu = is_qemu_emulated()
    march_override = os.environ.get("RAISIN_MARCH")
    jobs_override = os.environ.get("RAISIN_MAX_JOBS")
    retry_override = os.environ.get("RAISIN_QEMU_RETRY")

    fields = [
        ("architecture", machine),
        ("os", f"{g.os_type} {g.os_version}"),
        ("qemu_emulated", str(qemu).lower()),
        ("qemu_retry", retry_override or "(auto)"),
        (
            "build_jobs",
            f"{get_build_jobs()}{f' (RAISIN_MAX_JOBS={jobs_override})' if jobs_override else ''}",
        ),
        ("portable_march", get_default_portable_march()),
        ("march_override", march_override or "(none)"),
        ("gcc", _detect_compiler_version("gcc")),
        ("g++", _detect_compiler_version("g++")),
    ]

    width = max(len(k) for k, _ in fields)
    for key, value in fields:
        print(f"{key + ':':<{width + 2}}{value}")

    if machine not in SUPPORTED_ARCHITECTURES:
        print(f"\n⚠️  WARNING: '{machine}' is not a supported architecture.")
        print(f"   Supported: {', '.join(sorted(set(SUPPORTED_ARCHITECTURES)))}")
        print(
            f"   'raisin build' and 'raisin setup' will refuse to run on this platform."
        )
