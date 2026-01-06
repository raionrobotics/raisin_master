#!/usr/bin/env python3
"""
RAISIN Build & Management Tool

Main entry point that registers all commands from the commands package.
"""

import sys
import click
from commands.utils import init_environment
from commands.help import print_help, help_command
from commands.setup import setup_command
from commands.build import build_cli_command
from commands.publish import publish_command
from commands.install import install_cli_command
from commands.index import index_group
from commands.git_commands import git_group
from commands.test import test_command

try:
    from packaging.requirements import Requirement
    from packaging.version import Version, InvalidVersion
    from packaging.specifiers import InvalidSpecifier
except ImportError:
    print("Error: 'packaging' library not found.")
    print("Please install it running: pip install packaging")
    exit(1)


# Main CLI group
@click.group(
    invoke_without_command=True,
    context_settings=dict(help_option_names=["-h", "--help"]),
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Auto-confirm all prompts (e.g., overwriting release assets)",
)
@click.pass_context
def cli(ctx, yes):
    """
    🍇 RAISIN Build & Management Tool

    A researcher-friendly tool for building, managing, and distributing robotics software packages.
    """
    ctx.ensure_object(dict)
    print(f"🐍 Python: {sys.executable}")
    init_environment(__file__, yes_flag=yes)

    # If no command provided, show help
    if ctx.invoked_subcommand is None:
        print_help()
        ctx.exit(0)


# Register all commands
cli.add_command(setup_command, name="setup")
cli.add_command(build_cli_command, name="build")
cli.add_command(publish_command, name="publish")
cli.add_command(install_cli_command, name="install")
cli.add_command(index_group, name="index")
cli.add_command(git_group, name="git")
cli.add_command(test_command, name="test")
cli.add_command(help_command, name="help")


if __name__ == "__main__":
    cli()
