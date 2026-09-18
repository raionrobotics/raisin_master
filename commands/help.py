import os
import sys
import click


def print_help():
    """Displays the comprehensive help message for the script."""
    script_name = os.path.basename(sys.argv[0])
    print(f"RAISIN Build & Management Tool 🍇")
    print("=" * 70)
    print(f"Usage: python {script_name} <command> [options]\n")

    print("## Global Options")
    print("-" * 70)
    print(
        f"  {'--yes':<20} Answers 'yes' to all prompts, like overwriting release assets."
    )

    print("\n## Build & Release Commands")
    print("-" * 70)
    print(
        f"  {'setup [target ...]':<20} 🛠️  Generates message headers and configures the main CMakeLists.txt."
    )
    print(
        f"  {'':<22} If [target...] is provided, configures only those targets and their"
    )
    print(f"  {'':<22} dependencies. Otherwise, configures all projects in 'src/'.")
    print("-" * 35)
    print(
        f"  {'build --type <debug|release> [--install]':<20} ⚙️  Runs the 'setup' step, then compiles the entire project using Ninja."
    )
    print(
        f"  {'':<22} The build type ('debug' or 'release') must be specified using --type."
    )
    print(
        f"  {'':<22} Add --install flag to also install artifacts into the 'install/' directory."
    )
    print("-" * 35)
    print(
        f"  {'publish <target> [--type debug|release]':<20} 📦 Builds, archives, and uploads a distributable package for the target."
    )
    print(f"  {'':<22} Archives are uploaded to the OTA server.")
    print(f"  {'':<22} Build type defaults to 'release' if not specified.")

    print("-" * 35)
    print(
        f"  {'build_sdk android [--abi <abi>] [--api <n>]':<20} 🤖 Cross-compiles the communication-only core with the Android NDK"
    )
    print(
        f"  {'':<22} and packages a relocatable CMake SDK plus a local archive."
    )
    print(
        f"  {'':<22} Host outputs are untouched. 'build_sdk android --list-profiles' lists the target profiles."
    )

    print("\n## Package Management Commands")
    print("-" * 70)
    print(
        f"  {'install [pkg>=1.0 ...] [--type debug|release]':<20} 🚀 Downloads and installs pre-compiled packages and dependencies."
    )
    print(
        f"  {'':<22} If no packages are listed, it processes/installs all local 'src/' packages."
    )
    print(f"  {'':<22} Supports version constraints (e.g., 'raisin_core>=1.2.3').")
    print(f"  {'':<22} Build type defaults to 'release' if not specified.")
    print("-" * 35)
    print(
        f"  {'index local':<20} ℹ️  Scans local 'src/' and 'release/install/' packages and validates"
    )
    print(
        f"  {'':<22} their dependency graph, printing a colored report of the status."
    )

    print("\n## Git Integration Commands")
    print("-" * 70)
    print(
        f"  {'git status':<20} 🔄 Fetches and shows the detailed sync status for all local repositories."
    )
    print("-" * 35)
    print(
        f"  {'git pull [remote]':<20} ⬇️  Pulls changes for all local repositories from the specified remote"
    )
    print(f"  {'':<22} (defaults to 'origin').")
    print("-" * 35)
    print(
        f"  {'git setup <remote:user ...>':<20} 🔱 Clears all existing remotes and sets up new ones for all repos in 'src/'."
    )
    print(f"  {'':<22} Example: 'git setup origin:raisim raion:raionrobotics'")

    print("\n## Help")
    print("-" * 70)
    print(f"  {'help, -h, --help':<20} ❓ Displays this help message.")
    print("=" * 70)


# ============================================================================
# Click CLI Command
# ============================================================================


@click.command()
def help_command():
    """Show help message."""
    print_help()
