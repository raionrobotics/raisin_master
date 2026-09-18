"""
Install command for RAISIN.

Downloads and installs packages from the OTA server.

Install modes:
- Default: Download from latest archive based on build type
- --archive-version: Download from a specific archive version
- --at: Download packages at a specific timestamp (time-travel)
"""

import re
from functools import wraps
import click
from pathlib import Path
from typing import Optional
import yaml
from packaging.version import parse as parse_version
from packaging.version import InvalidVersion
from packaging.specifiers import SpecifierSet

# Import globals and utilities
from commands import globals as g
from commands.utils import load_configuration, parse_version_specifier

from raisin_ota import (
    InstallStateBusy,
    InstallStateLockUnavailable,
    InstallTreeUnusable,
    install_state_lock,
)
from raisin_ota.client import (
    download_package_at_timestamp,
    download_all_from_archive,
    OtaDesiredStateUnusable,
    OtaInstallHalted,
    archive_is_pinned,
    flush_pending_snapshot_reports,
    clear_install_session,
    report_install_outcome,
    flush_install_events,
)


def _default_tag_for_user_type(user_type: Optional[str]) -> str:
    """Map configuration_setting.yaml `user_type` to the default archive tag.

    - "devel" (and anything that starts with "dev") → "latest"
      — developers want the freshest build.
    - everything else (including "user") → "stable"
      — production-style installs default to the promoted/blessed archive.
    """
    if user_type and user_type.strip().lower().startswith("dev"):
        return "latest"
    return "stable"


def install_command(
    targets,
    build_type,
    archive_version: Optional[str] = None,
    archive_name: Optional[str] = None,
    at_timestamp: Optional[str] = None,
    tag: Optional[str] = None,
) -> bool:
    """Install packages, reporting a broken install tree rather than raising.

    Both the archive route and the per-package route prepare the versioned
    tree, so both can find it unusable — on a robot whose `release/install` is
    a mount point, for instance. That is a layout problem, not a reason to
    install the same packages from somewhere else into the same place, so it
    ends the run here instead of falling through.
    """
    try:
        return _install(
            targets,
            build_type,
            archive_version,
            archive_name,
            at_timestamp,
            tag,
        )
    except InstallTreeUnusable as unusable:
        print("")
        print("=" * 72)
        print("❌ The install tree cannot be prepared — nothing was installed.")
        print(f"   {unusable}")
        print("   No fallback is performed; the layout has to change first.")
        print("=" * 72)
        return False


def _install(
    targets,
    build_type,
    archive_version: Optional[str] = None,
    archive_name: Optional[str] = None,
    at_timestamp: Optional[str] = None,
    tag: Optional[str] = None,
) -> bool:
    """
    Install packages and their dependencies.

    Args:
        targets (list): List of package specifications (e.g., ["raisin", "my-plugin>=1.2"])
        build_type (str): 'debug' or 'release'
        archive_version (str): Optional specific archive version (e.g., 'v2024.01')
        archive_name (str): Optional archive base name override (e.g., 'raisin-robot')
        at_timestamp (str): Optional timestamp for time-travel install (e.g., '2024-01-15')
        tag (str): Archive tag to resolve. When None (default), the tag is
            derived from configuration_setting.yaml: `user_type: devel` →
            "latest", anything else → "stable". Pass an explicit tag string
            (e.g. "beta") to override, or "none"/None at this layer to fall
            back to legacy latest-by-time selection. Ignored when
            `archive_version` is provided.

    Returns:
        bool: True if every requested package installed cleanly, False if
        anything failed or had to be skipped. The CLI wrapper propagates
        this to a non-zero exit code so failures surface in CI.
    """
    print("🚀 Starting installation process...")

    # Access globals
    script_directory = g.script_directory
    os_type = g.os_type
    os_version = g.os_version
    architecture = g.architecture

    script_dir_path = Path(script_directory)

    # Load configuration
    _, _, user_type, _, repos_to_ignore = load_configuration()

    # If the caller didn't pin a tag, derive it from the user_type.
    # "devel" → bleeding-edge ("latest"), anything else → "stable".
    if tag is None:
        tag = _default_tag_for_user_type(user_type)
        print(
            f"ℹ️  No --tag provided; using '{tag}' "
            f"(derived from configuration_setting.yaml user_type='{user_type}')."
        )

    # Process installation queue
    install_queue = list(targets)

    src_dir = script_dir_path / "src"
    repo_ignore_set = set(repos_to_ignore or [])
    if src_dir.is_dir():
        print(f"🔍 Scanning for local source packages in '{src_dir}'...")
        local_src_packages = [
            path.name
            for path in src_dir.iterdir()
            if path.is_dir() and path.name not in repo_ignore_set
        ]
        if local_src_packages:
            print(f"  -> Found local packages to process: {local_src_packages}")
            install_queue.extend(local_src_packages)
    processed_packages = dict()
    is_successful = True

    # When an archive is pinned — on the command line, or per-node through
    # RAISIN_ARCHIVE_NAME — we refuse to fall back silently to another archive,
    # another tag. A miss must be a hard, loud failure: the
    # alternative is what caused `--archive-name dso --archive-version 1.0.3`
    # to quietly resolve to `raisin-dev 1.0.3` and install the wrong controllers.
    explicit_archive_pin = archive_is_pinned(archive_name, archive_version)

    if not install_queue:
        # Normalize 'none' (case-insensitive) to None for legacy fallback.
        resolved_tag = None if (tag is None or str(tag).lower() == "none") else tag
        if archive_name and archive_version:
            print(
                "ℹ️  No packages specified. Installing all packages from "
                f"archive '{archive_name}' version '{archive_version}'."
            )
        elif archive_name:
            print(
                "ℹ️  No packages specified. Installing all packages from "
                f"archive '{archive_name}'."
            )
        elif archive_version:
            print(
                "ℹ️  No packages specified. Installing all packages from "
                f"archive version {archive_version}."
            )
        elif resolved_tag:
            print(
                "ℹ️  No packages specified. Installing all packages from "
                f"archive tagged '{resolved_tag}'."
            )
        else:
            print(
                "ℹ️  No packages specified. Installing all packages from "
                "the latest archive."
            )

        try:
            ota_results = download_all_from_archive(
                build_type,
                script_dir_path / "release" / "install",
                archive_version=archive_version,
                archive_name=archive_name,
                tag=resolved_tag,
            )
        except OtaInstallHalted as halted:
            # A halt is an instruction to stop. Falling back would install the
            # same software from somewhere else and call it obedience.
            print("")
            print("=" * 72)
            print("⛔ Installs are halted for this node — nothing was installed.")
            print(f"   {halted}")
            print("   No fallback is performed while a halt is in effect.")
            print("=" * 72)
            return False
        except OtaDesiredStateUnusable as unusable:
            # Caught for the same reason and reported the same way. Left
            # uncaught it left `install_cli_command` before the attempt was
            # closed, so the one failure the fleet most needs told — this
            # machine cannot run what it was assigned — was the one it never
            # heard, and an operator got a traceback in place of the reason.
            print("")
            print("=" * 72)
            print("⛔ This node cannot install what it was assigned.")
            print(f"   {unusable}")
            print("   Nothing else is installed in its place.")
            print("=" * 72)
            return False

        if ota_results:
            print("🎉🎉🎉 Installation process finished successfully.")
            return True

        if explicit_archive_pin:
            # The user pinned an exact archive (name/version) and OTA could
            # not satisfy that request. Don't quietly install something else.
            print("")
            print("=" * 72)
            print("❌ Requested archive not found on OTA — refusing to fall back.")
            print(
                "   archive_name    : "
                f"{archive_name if archive_name else '(default)'}"
            )
            print(
                "   archive_version : "
                f"{archive_version if archive_version else '(latest)'}"
            )
            print(
                "   platform        : "
                f"{os_type}-{os_version}-{architecture} ({build_type})"
            )
            print(
            )
            print("=" * 72)
            return False

        # OTA returned nothing (tag missing, server unreachable, etc.). There is
        # nowhere else to look: say so rather than reporting an empty success.
        print("")
        print("=" * 72)
        print("❌ No archive available on OTA — nothing was installed.")
        print(f"   platform        : {os_type}-{os_version}-{architecture} ({build_type})")
        print("   Check the OTA endpoint and that an archive is published for")
        print("   this platform and tag.")
        print("=" * 72)
        return False

    while install_queue:
        target_spec = install_queue.pop(0)
        print(f"🔄 Processing target specifier: '{target_spec}'")

        match = re.match(r"^\s*([a-zA-Z0-9_.-]+)\s*(.*)\s*$", target_spec)
        if not match:
            print(
                f"⚠️ Warning: Could not parse target specifier '{target_spec}'. Skipping."
            )
            continue

        package_name, spec_str = match.groups()
        spec_str = spec_str.strip()

        spec = parse_version_specifier(spec_str)
        if spec is None:
            print(
                f"❌ Error: Invalid version specifier '{spec_str}' for package '{package_name}'. Skipping."
            )
            is_successful = False
            continue

        def check_local_package(path, package_type):
            """Helper to check a local/precompiled package, its version, and dependencies."""
            if not path.is_dir():
                return False
            is_valid = False
            dependencies = []
            release_yaml_path = path / "release.yaml"
            version_str = None
            if not release_yaml_path.is_file():
                if not spec_str:
                    is_valid = True
            else:
                with open(release_yaml_path, "r") as f:
                    release_info = yaml.safe_load(f) or {}
                    version_str = release_info.get("version")
                    dependencies = release_info.get("dependencies", [])
                    if not version_str:
                        if not spec_str:
                            is_valid = True
                    else:
                        try:
                            version_obj = parse_version(version_str)
                            if spec.contains(version_obj):
                                is_valid = True
                        except InvalidVersion:
                            print(
                                f"⚠️ Invalid version '{version_str}' in {package_type} release.yaml. Ignoring."
                            )
            if is_valid:
                if dependencies:
                    install_queue.extend(dependencies)
                if version_str:
                    print(
                        f"✅ Found suitable {package_type} package '{package_name}=={version_str}'"
                    )
                    processed_packages[package_name] = version_str
                return True
            return False

        # Priority 1: Check precompiled
        precompiled_path = (
            script_dir_path
            / "release/install"
            / package_name
            / os_type
            / os_version
            / architecture
            / build_type
        )
        if check_local_package(precompiled_path, "release/install"):
            continue

        # Priority 2: Check local source
        local_src_path = script_dir_path / "src" / package_name
        if check_local_package(local_src_path, "local source"):
            continue
        if local_src_path.is_dir():
            print(f"Skipping '{package_name}' because it exists in local source")
            continue

        # Priority 3: OTA Server
        try:
            ota_result = None
            if at_timestamp:
                # Timestamp-based download (time-travel)

                ota_result = download_package_at_timestamp(
                    package_name,
                    at_timestamp,
                    build_type,
                    script_dir_path / "release" / "install",
                )
            else:
                # Archive-based download (default or specific version)
                from raisin_ota.client import download_package as ota_download

                # Normalize 'none' (case-insensitive) to None so the OTA
                # client falls back to legacy latest-by-time selection.
                resolved_tag = (
                    None if (tag is None or str(tag).lower() == "none") else tag
                )
                ota_result = ota_download(
                    package_name,
                    spec_str,
                    build_type,
                    script_dir_path / "release" / "install",
                    archive_version=archive_version,
                    archive_name=archive_name,
                    tag=resolved_tag,
                )
            if ota_result:
                processed_packages[package_name] = ota_result["version"]
                install_queue.extend(ota_result.get("dependencies", []))
                continue
            # OTA is the only source now, so "not there" ends this package
            # rather than moving on to somewhere else to look.
            if explicit_archive_pin:
                print(
                    f"❌ Package '{package_name}' not found in pinned "
                    f"archive '{archive_name or '(default)'}'"
                    f"{f' v{archive_version}' if archive_version else ''}."
                )
            else:
                print(
                    f"❌ Package '{package_name}'"
                    f"{f' {spec_str}' if spec_str else ''} is not on the OTA "
                    "server, and it is neither a local source package nor "
                    "already installed."
                )
            is_successful = False
            continue
        except InstallTreeUnusable:
            # Not a per-package problem, and retrying the next package
            # against the same broken tree would only repeat it.
            raise
        except Exception as e:
            print(f"❌ OTA download failed for '{package_name}': {e}")
            is_successful = False
            continue

    if is_successful:
        print("🎉🎉🎉 Installation process finished successfully.")
    else:
        print("❌ Installation process finished with errors.")
    return is_successful


# ============================================================================
# Click CLI Command
# ============================================================================


def _with_install_state_lock(function):
    """Fail fast before this CLI invocation changes any shared install state."""

    @wraps(function)
    def locked(*args, **kwargs):
        try:
            with install_state_lock(g.script_directory, "raisin install"):
                return function(*args, **kwargs)
        except (InstallStateBusy, InstallStateLockUnavailable) as busy:
            # A Click error is concise, names the holder, and exits non-zero
            # without a traceback. Nothing in the command body has run yet.
            raise click.ClickException(str(busy)) from None

    return locked


@click.command()
@click.argument("packages", nargs=-1, required=False)
@click.option(
    "--type",
    "-t",
    "build_type",
    type=click.Choice(["debug", "release"], case_sensitive=False),
    default="release",
    show_default=True,
    help="Build type to install",
)
@click.option(
    "--archive-version",
    "-v",
    "archive_version",
    default=None,
    help="Install from a specific archive version (e.g., 'v2024.01')",
)
@click.option(
    "--archive-name",
    "archive_name",
    default=None,
    help="Override the OTA archive name (e.g., 'raisin-robot' or 'raisin-robot-debug'). For debug builds, '-debug' is added only if not already present.",
)
@click.option(
    "--at",
    "at_timestamp",
    default=None,
    help="Install packages at a specific timestamp (e.g., '2024-01-15' or '2024-01-15T10:00:00Z')",
)
@click.option(
    "--tag",
    "tag",
    default=None,
    help=(
        "Install from the archive marked with this tag. When omitted, the tag "
        "defaults based on configuration_setting.yaml user_type: 'devel' → "
        "'latest', anything else → 'stable'. Fallback chain when the requested "
        "tag is missing on OTA: tag → 'stable' (each step prints a clear "
        "warning). Pass 'none' to skip the tag and use legacy "
        "latest-by-time selection on OTA."
    ),
)
@_with_install_state_lock
def install_cli_command(
    packages,
    build_type,
    archive_version,
    archive_name,
    at_timestamp,
    tag,
):
    """
    Download and install packages from the OTA server.

    \b
    Examples:
        raisin install                               # Install from latest archive
        raisin install raisin_network                # Install specific package
        raisin install raisin_network==1.1.0         # Install specific version
        raisin install --type debug                  # Install debug builds
        raisin install --archive-version v2024.01   # Install from specific archive
        raisin install --archive-name team-robot    # Install from a custom archive name
        raisin install --at 2024-01-15               # Install packages at timestamp
    """
    packages = list(packages)

    build_types = [build_type]

    # Run every build_type even if an earlier one fails so the user sees the
    # full picture, then exit non-zero if any of them reported failure. That's
    # important for CI: a silent zero-exit on a broken install used to mask
    # cases like the dso/raisin-dev cross-archive bug.
    overall_success = True
    for bt in build_types:
        if at_timestamp:
            click.echo(f"📥 Installing packages at {at_timestamp} ({bt})...")
        elif archive_name and archive_version:
            click.echo(
                f"📥 Installing from archive {archive_name} ({archive_version}, {bt})..."
            )
        elif archive_name:
            click.echo(f"📥 Installing from archive {archive_name} ({bt})...")
        elif archive_version:
            click.echo(f"📥 Installing from archive {archive_version} ({bt})...")
        elif packages:
            click.echo(f"📥 Installing {len(packages)} package(s) ({bt})...")
        else:
            click.echo(f"📥 Installing all packages from latest archive ({bt})...")
        succeeded = install_command(
            packages,
            bt,
            archive_version,
            archive_name,
            at_timestamp,
            tag=tag,
        )
        if not succeeded:
            overall_success = False

    flush_pending_snapshot_reports()

    # Close the attempt with one terminal event. A failure noted downstream
    # outranks overall_success, because install_command returns True when any
    # package landed — a partial archive install is not a completed one.
    report_install_outcome(overall_success)

    # Flush either way — a failed attempt is exactly what needs reporting.
    flush_install_events()

    # Keep the session on failure so a retry resumes it; retire it on success.
    if not overall_success:
        raise click.exceptions.Exit(code=1)

    clear_install_session()
