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
    # TODO: Implement the diagnostic output here.
    #
    # Available data:
    #   platform.machine()           -> e.g. "x86_64", "aarch64"
    #   g.os_type                    -> e.g. "ubuntu"
    #   g.os_version                 -> e.g. "24.04"
    #   g.architecture               -> normalized arch from utils
    #   is_qemu_emulated()           -> True if under QEMU user-mode emulation
    #   get_build_jobs()             -> resolved parallel job count
    #   get_default_portable_march() -> e.g. "x86-64-v3" or "armv8.2-a+..."
    #   SUPPORTED_ARCHITECTURES      -> tuple of supported arch strings
    #   RAISIN_MAX_JOBS env var      -> user override for job count
    #   RAISIN_MARCH env var         -> user override for march
    #   RAISIN_QEMU_RETRY env var    -> manual QEMU retry override
    #   _detect_compiler_version()   -> gcc/g++ version strings
    #
    # Consider: what format is most scannable when pasted into a bug report?
    # Consider: should unsupported arch show a warning here (non-fatal) vs
    #           the hard exit in build/setup?
    pass
