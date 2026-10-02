"""
Install command for RAISIN.

Downloads and installs packages from the OTA server.

Install modes:
- Default: Prefer active local sources, reuse compatible binaries, fetch missing packages
- No targets: Resolve source dependencies
- --all: Install every package in the selected OTA archive and its dependencies
- --upgrade: Query latest OTA packages, keeping active sources and newer installed binaries
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
    get_archive_name,
    PackageInstallTransaction,
    note_install_failure,
    classify_download_error,
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
    include_local: bool = False,
    strict_local_version: bool = False,
    upgrade: bool = False,
    all_packages: bool = False,
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
            include_local,
            strict_local_version,
            upgrade,
            all_packages,
        )
    except InstallTreeUnusable as unusable:
        print("")
        print("=" * 72)
        print("❌ The install tree cannot be prepared — nothing was installed.")
        print(f"   {unusable}")
        print("   No fallback is performed; the layout has to change first.")
        print("=" * 72)
        return False
    except OSError as error:
        note_install_failure("unpack", classify_download_error(error), str(error))
        print(f"❌ Could not prepare or commit packages: {error}.")
        print("   The new package tree was not activated.")
        return False


def _install(
    targets,
    build_type,
    archive_version: Optional[str] = None,
    archive_name: Optional[str] = None,
    at_timestamp: Optional[str] = None,
    tag: Optional[str] = None,
    include_local: bool = False,
    strict_local_version: bool = False,
    upgrade: bool = False,
    all_packages: bool = False,
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
        include_local (bool): Also resolve dependencies of local src/ packages.
        strict_local_version (bool): Fail instead of warning when an active
            source version does not satisfy its requested conditions. Sources
            remain selected in either mode, matching setup/build.
        upgrade (bool): Query latest OTA packages unless a tag was selected;
            never silently downgrade an installed binary.
        all_packages (bool): Use every package in the selected OTA archive as
            a dependency root. Active sources are still preferred.

    Explicit targets resolve their own dependency closure. include_local adds
    source repositories as roots; without targets these roots are automatic.
    --all explicitly adds every package in the selected OTA archive. Active
    sources always take precedence, matching setup/build. Compatible installed
    binaries are reused unless an OTA selection is explicit. Downloaded package
    dependencies are read from ZIP release.yaml files in one staged tree.

    Returns:
        bool: True if every requested package installed cleanly, False if
        anything failed or had to be skipped. The CLI wrapper propagates
        this to a non-zero exit code so failures surface in CI.
    """
    print("🚀 Starting installation process...")

    if all_packages and targets:
        print("❌ --all cannot be combined with explicit package targets.")
        return False
    if all_packages and at_timestamp:
        print(
            "❌ --all cannot be combined with --at; use package targets for timestamp installs."
        )
        return False
    if upgrade and (archive_version is not None or at_timestamp is not None):
        print(
            "❌ --upgrade cannot be combined with --archive-version or --at; "
            "use an explicit install to restore a pinned version."
        )
        return False

    # Access globals
    script_directory = g.script_directory
    os_type = g.os_type
    os_version = g.os_version
    architecture = g.architecture

    script_dir_path = Path(script_directory)

    # Load configuration
    _, user_type, _, repos_to_ignore = load_configuration()

    explicit_selection = any(
        value is not None
        for value in (tag, archive_name, archive_version, at_timestamp)
    )

    # If the caller didn't pin a tag, derive it from the user_type.
    # "devel" → bleeding-edge ("latest"), anything else → "stable".
    if tag is None:
        tag = "latest" if upgrade else _default_tag_for_user_type(user_type)
        tag_reason = (
            "--upgrade"
            if upgrade
            else f"configuration_setting.yaml user_type='{user_type}'"
        )
        print(f"ℹ️  No --tag provided; using '{tag}' " f"(derived from {tag_reason}).")

    # Process installation queue
    install_queue = list(targets)
    requested_packages = set()
    for target_spec in install_queue:
        if isinstance(target_spec, str):
            match = re.match(r"^\s*([a-zA-Z0-9_.-]+)", target_spec)
            if match:
                requested_packages.add(match.group(1))

    src_dir = script_dir_path / "src"
    repo_ignore_set = set(repos_to_ignore or [])
    source_packages = (
        {
            path.name
            for path in src_dir.iterdir()
            if path.is_dir() and path.name not in repo_ignore_set
        }
        if src_dir.is_dir()
        else set()
    )
    if (include_local or (not targets and not all_packages)) and src_dir.is_dir():
        print(f"🔍 Scanning for local source packages in '{src_dir}'...")
        local_src_packages = [
            path.name
            for path in sorted(src_dir.iterdir())
            if path.is_dir()
            and path.name not in repo_ignore_set
            and path.name not in requested_packages
        ]
        if local_src_packages:
            print(f"  -> Found local packages to process: {local_src_packages}")
            install_queue.extend(local_src_packages)
    if include_local and not all_packages and not install_queue:
        print(
            f"❌ No packages requested and no local source packages found in '{src_dir}'."
        )
        return False

    # When an archive is pinned — on the command line, or per-node through
    # RAISIN_ARCHIVE_NAME — we refuse to fall back silently to another archive
    # or another tag. A miss must be a hard, loud failure: the alternative is
    # what caused `--archive-name dso --archive-version 1.0.3` to quietly
    # resolve to `raisin-dev 1.0.3` and install the wrong controllers.
    explicit_archive_pin = archive_is_pinned(archive_name, archive_version)
    refresh_from_ota = upgrade or explicit_selection or explicit_archive_pin

    if not all_packages and not install_queue:
        if at_timestamp:
            print("❌ --at requires package targets or local source packages.")
            return False
        print(
            "❌ No package targets or local source packages found. "
            "Use 'raisin install --all' to install the OTA archive."
        )
        return False

    with PackageInstallTransaction(
        script_dir_path / "release" / "install", upgrade=upgrade
    ) as transaction:
        initial_results = {}
        if all_packages:
            resolved_tag = None if str(tag).lower() == "none" else tag
            try:
                initial_results = download_all_from_archive(
                    build_type,
                    transaction.install_base_path,
                    archive_version=archive_version,
                    archive_name=archive_name,
                    tag=resolved_tag,
                    transaction=transaction,
                    source_packages=source_packages,
                )
            except OtaInstallHalted as halted:
                print(
                    f"⛔ Installs are halted for this node — nothing was installed. {halted}"
                )
                return False
            except OtaDesiredStateUnusable as unusable:
                print(f"⛔ This node cannot install what it was assigned. {unusable}")
                return False
            if not transaction.archive_prepared and not initial_results:
                if explicit_archive_pin:
                    print(
                        f"❌ Requested archive not found or incomplete on OTA: "
                        f"'{archive_name or '(default)'}' version '{archive_version or '(selected tag)'}'."
                    )
                else:
                    print(
                        "❌ No complete archive available on OTA — nothing was installed."
                    )
                return False
            roots = transaction.archive_roots or set(initial_results)
            install_queue.extend(
                name for name in sorted(roots) if name not in install_queue
            )
        local_version_overrides = {}
        is_successful = _resolve_packages(
            install_queue,
            build_type,
            archive_version,
            archive_name,
            at_timestamp,
            tag,
            repo_ignore_set,
            refresh_from_ota,
            explicit_archive_pin,
            transaction,
            strict_local_version,
            local_version_overrides,
            initial_results,
        )
        if is_successful:
            is_successful = _validate_retained_consumers(
                transaction, build_type, repo_ignore_set
            )
        if is_successful:
            is_successful = transaction.commit()
        if is_successful:
            print("🎉🎉🎉 Installation process finished successfully.")
        else:
            print(
                "❌ Installation process finished with errors; the previous package tree is preserved."
            )
        if local_version_overrides:
            print("⚠️ Local source version warnings (sources retained for build):")
            for name, override in sorted(local_version_overrides.items()):
                print(
                    f"   {name} at {override['path']}: version '{override['version']}', "
                    f"required '{override['required']}'."
                )
            print(
                "   These source versions have not been verified against the requested conditions."
            )
        return is_successful


def _validate_retained_consumers(transaction, build_type, repo_ignore_set):
    """A partial install must also satisfy packages retained in the active tree.

    Only dependencies on changed binaries are checked. Source consumers must
    have been selected while resolving this install's roots and dependencies.
    Providers follow the same source-first rule as setup/build.
    """
    changed = transaction.packages.get(build_type, set())
    if not changed:
        return True
    source_dir = Path(g.script_directory) / "src"
    base = transaction.package_base
    providers = {
        path.name: path / g.os_type / g.os_version / g.architecture / build_type
        for path in base.iterdir()
        if path.is_dir()
    }
    sources = (
        {
            path.name: path
            for path in source_dir.iterdir()
            if path.is_dir() and path.name not in repo_ignore_set
        }
        if source_dir.is_dir()
        else {}
    )
    providers.update(sources)
    manifests = {}
    for name, directory in providers.items():
        if name in sources and name not in transaction.resolved_sources:
            continue
        try:
            info = yaml.safe_load(
                (directory / "release.yaml").read_text(encoding="utf-8")
            )
        except (OSError, yaml.YAMLError) as error:
            print(
                f"⚠️ Cannot validate retained package '{name}' at {directory}: {error}."
            )
            continue
        if isinstance(info, dict):
            manifests[name] = info
    success = True
    for consumer, info in manifests.items():
        dependencies = info.get("dependencies", [])
        if not isinstance(dependencies, list):
            continue
        for dependency in dependencies:
            match = (
                re.fullmatch(r"\s*([a-zA-Z0-9_.-]+)\s*(.*?)\s*", dependency)
                if isinstance(dependency, str)
                else None
            )
            if not match or match.group(1) not in changed:
                continue
            name, spec_text = match.groups()
            spec = parse_version_specifier(spec_text)
            version = manifests.get(name, {}).get("version")
            try:
                compatible = (
                    spec is not None
                    and version is not None
                    and spec.contains(parse_version(str(version)))
                )
            except InvalidVersion:
                compatible = False
            if not compatible:
                print(
                    f"❌ Retained package '{consumer}' requires '{dependency}', but "
                    f"the selected provider at {providers.get(name)} has version '{version or 'unknown'}'."
                )
                success = False
    return success


def _resolve_packages(
    install_queue,
    build_type,
    archive_version,
    archive_name,
    at_timestamp,
    tag,
    repo_ignore_set,
    refresh_from_ota,
    explicit_archive_pin,
    transaction,
    strict_local_version,
    local_version_overrides,
    initial_results,
):
    script_dir_path = Path(g.script_directory)
    os_type, os_version, architecture = g.os_type, g.os_version, g.architecture
    is_successful = True
    processed_specs = set()
    downloaded_packages = dict(initial_results)
    expanded_dependencies = set()
    package_requirements = {}

    while install_queue:
        target_spec = install_queue.pop(0)
        print(f"🔄 Processing target specifier: '{target_spec}'")

        match = (
            re.match(r"^\s*([a-zA-Z0-9_.-]+)\s*(.*)\s*$", target_spec)
            if isinstance(target_spec, str)
            else None
        )
        if not match:
            print(
                f"⚠️ Warning: Could not parse target specifier '{target_spec}'. Skipping."
            )
            is_successful = False
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

        # Every consumer's requirement remains in force if another dependency
        # later asks for a different version of the same package.
        if spec_str:
            previous = package_requirements.get(package_name, SpecifierSet())
            spec = SpecifierSet(",".join(filter(None, (str(previous), str(spec)))))
            package_requirements[package_name] = spec
            spec_str = str(spec)
        elif package_name in package_requirements:
            spec = package_requirements[package_name]
            spec_str = str(spec)

        # An unconstrained source root may have no version. Do not let that
        # visit suppress a later explicit >=0.0.0 requirement in strict mode.
        request = (package_name, str(spec), bool(spec_str))
        if request in processed_specs:
            print(
                f"ℹ️ Already processed '{target_spec}' in this install; skipping duplicate."
            )
            continue
        processed_specs.add(request)

        downloaded = downloaded_packages.get(package_name)
        if downloaded and spec.contains(parse_version(str(downloaded["version"]))):
            print(
                f"✅ Reusing '{package_name}=={downloaded['version']}' resolved in this "
                f"install; satisfies '{spec}'. OTA lookup skipped."
            )
            if package_name not in expanded_dependencies:
                install_queue.extend(downloaded.get("dependencies", []))
                expanded_dependencies.add(package_name)
            continue

        def check_local_package(path, package_type):
            """Helper to check a local/precompiled package, its version, and dependencies."""
            if not path.is_dir():
                return False
            release_yaml_path = path / "release.yaml"
            next_step = (
                "OTA lookup skipped; repair the source or exclude it with repos_to_ignore."
                if package_type == "local source"
                else "Checking OTA."
            )
            if not release_yaml_path.is_file():
                print(
                    f"⚠️ Cannot verify {package_type} package '{package_name}' at {path}: "
                    f"release.yaml is missing. {next_step}"
                )
                return False
            try:
                with release_yaml_path.open(encoding="utf-8") as f:
                    release_info = yaml.safe_load(f)
                if not isinstance(release_info, dict):
                    raise ValueError("release.yaml must contain a mapping")
                dependencies = release_info.get("dependencies", [])
                if not isinstance(dependencies, list) or any(
                    not isinstance(dep, str) or not dep.strip() for dep in dependencies
                ):
                    raise ValueError(
                        "dependencies must be a list of package specifiers"
                    )
            except (OSError, yaml.YAMLError, ValueError) as error:
                print(
                    f"⚠️ Cannot verify {package_type} package '{package_name}' at {path}: "
                    f"{error}. {next_step}"
                )
                return False
            version_str = release_info.get("version")
            if version_str:
                try:
                    is_valid = spec.contains(parse_version(str(version_str)))
                except InvalidVersion:
                    is_valid = False
            else:
                is_valid = package_type == "local source" and not spec_str
            if not is_valid:
                if package_type == "local source" and not strict_local_version:
                    local_version_overrides[package_name] = {
                        "path": path,
                        "version": str(version_str or "unknown"),
                        "required": str(spec),
                    }
                    print(
                        f"⚠️ Using local source '{package_name}' at {path} with version "
                        f"'{version_str or 'unknown'}' despite required '{spec}' "
                        "(source selected by setup/build). OTA lookup skipped."
                    )
                    install_queue.extend(dependencies)
                    print(
                        "   Source will be built by 'raisin build'; continuing to resolve its dependencies."
                    )
                    return True
                print(
                    f"⚠️ {package_type} package '{package_name}' at {path} has version "
                    f"'{version_str or 'unknown'}', which does not satisfy '{spec}'. {next_step}"
                )
                if package_type == "local source":
                    print(
                        "   --strict-local-version makes this mismatch an error; "
                        "without it, the source is retained with a warning."
                    )
                return False
            install_queue.extend(dependencies)
            reason = (
                f"satisfies '{spec}'"
                if version_str
                else "no version constraint requested"
            )
            print(
                f"✅ Using {package_type} package '{package_name}=={version_str or 'unknown'}' "
                f"at {path}; {reason}. OTA lookup skipped."
            )
            if package_type == "local source":
                print(
                    "   Source will be built by 'raisin build'; this command only resolves its dependencies."
                )
            return True

        # Match setup/build: active local sources take precedence over binaries.
        precompiled_path = (
            transaction.package_base
            / package_name
            / os_type
            / os_version
            / architecture
            / build_type
        )
        local_src_path = script_dir_path / "src" / package_name
        if local_src_path.is_dir() and package_name not in repo_ignore_set:
            transaction.resolved_sources.add(package_name)
            if not check_local_package(local_src_path, "local source"):
                print(
                    f"❌ Local source '{package_name}' cannot satisfy '{spec}'; "
                    "a downloaded binary would not be used by the build."
                )
                is_successful = False
            continue
        if package_name in repo_ignore_set and local_src_path.is_dir():
            print(
                f"ℹ️ Local source '{package_name}' at {local_src_path} is excluded "
                "by repos_to_ignore; resolving an installed or OTA binary."
            )
        if refresh_from_ota:
            print(
                f"ℹ️ OTA selection requested for '{package_name}'; checking OTA "
                "instead of reusing an existing installed package."
            )
        else:
            if check_local_package(precompiled_path, "release/install"):
                continue

        # Priority 3: OTA Server
        try:
            ota_result = None
            selection = (
                f"timestamp '{at_timestamp}'"
                if at_timestamp
                else (
                    f"archive version '{archive_version}'"
                    if archive_version
                    else (
                        f"tag '{tag}'"
                        if str(tag).lower() != "none"
                        else "latest by publication time"
                    )
                )
            )
            print(
                f"🔎 Querying OTA for '{package_name}' (required: '{spec}', "
                f"archive: '{get_archive_name(build_type, archive_name)}', {selection}, "
                f"platform: {os_type}-{os_version}-{architecture}, build: {build_type})."
            )
            if at_timestamp:
                # Timestamp-based download (time-travel)

                ota_result = download_package_at_timestamp(
                    package_name,
                    at_timestamp,
                    build_type,
                    script_dir_path / "release" / "install",
                    transaction=transaction,
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
                    transaction=transaction,
                )
            if ota_result:
                try:
                    version = parse_version(str(ota_result.get("version", "")))
                except InvalidVersion:
                    version = None
                if version is None or not spec.contains(version):
                    print(
                        f"❌ OTA returned '{package_name}=={ota_result.get('version')}', "
                        f"which does not satisfy '{spec}'."
                    )
                    is_successful = False
                    continue
                downloaded_packages[package_name] = ota_result
                install_queue.extend(ota_result.get("dependencies", []))
                expanded_dependencies.add(package_name)
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
                    f"❌ Could not resolve '{package_name}' (required: '{spec}') from OTA. "
                    "No local package was selected; see the version, metadata and OTA diagnostics above."
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
    "--all",
    "all_packages",
    is_flag=True,
    help="Install all packages in the selected OTA archive and their dependencies. Active local sources still take precedence; unrelated installed packages are retained.",
)
@click.option(
    "--upgrade",
    is_flag=True,
    help="Query OTA for package updates, defaulting to the latest tag. Keeps active sources and newer installed binaries; checks archive and content hashes before reusing the same version.",
)
@click.option(
    "--include-local",
    is_flag=True,
    help="Also resolve dependencies of local src/ packages alongside the requested packages. Source packages are not built by this command.",
)
@click.option(
    "--strict-local-version",
    is_flag=True,
    help="Fail on active src/ version mismatches. By default, keep sources as setup/build does, warn and resolve their dependencies. Metadata and binary errors still fail.",
)
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
        "latest-by-time selection on OTA. An explicit tag refreshes packages "
        "from OTA instead of reusing installed binaries. Active local sources "
        "still take precedence and are never replaced by this command."
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
    include_local=False,
    strict_local_version=False,
    upgrade=False,
    all_packages=False,
):
    """
    Download and install packages from the OTA server.

    Specified packages resolve their dependencies. Add --include-local to also
    resolve dependencies of local src/ repositories. Without package targets,
    local source roots are automatic. Use --all to install every package in an
    OTA archive; without targets or sources, no whole archive is installed.
    Active sources take precedence over installed or OTA binaries, including
    when a tag is specified. Source version mismatches warn and continue with
    that source's dependencies. Compatible
    installed binaries are reused unless an OTA selection is explicit.
    Downloads are prepared in versions/ and activated together only after
    dependency checks succeed. Sources are built separately by 'raisin build'.

    --strict-local-version makes source version mismatches (including unknown
    versions with explicit constraints) an error. By default, those sources
    are retained with a warning and summary.
    Unreadable source manifests, missing dependencies and binary conflicts fail.

    --upgrade queries latest OTA packages unless --tag selects another channel.
    It never silently downgrades installed binaries. The same version is reused
    only when its immutable content hashes match; otherwise it is
    fetched again so republished builds and missing provenance are handled.
    Identical content in a new archive refreshes metadata without downloading.
    --upgrade cannot be combined with --archive-version or --at. --all cannot
    be combined with package targets or --at. --all retains unrelated packages.

    \b
    Examples:
        raisin install                               # Resolve local source dependencies
        raisin install --all                         # Install the selected OTA archive's packages
        raisin install --all --upgrade               # Refresh all archive packages from latest
        raisin install --include-local               # Resolve local source dependencies
        raisin install raisin_gui --include-local    # GUI plus local source dependencies
        raisin install raisin_gui --strict-local-version  # Fail on source version mismatches
        raisin install raisin_gui --upgrade           # Update binaries from latest, retaining sources
        raisin install raisin_gui --upgrade --tag stable  # Update within the stable channel
        raisin install raisin_network                # Install specific package
        raisin install raisin_network==1.1.0         # Install specific version
        raisin install --type debug                  # Install debug builds
        raisin install --all --archive-version v2024.01   # Install a pinned archive
        raisin install --all --archive-name team-robot    # Install a custom archive
        raisin install raisin_gui --at 2024-01-15     # Install a package at a timestamp
        raisin install raisin_gui --tag latest       # Refresh binaries; keep active local sources
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
        elif all_packages:
            click.echo(f"📥 Installing all selected OTA archive packages ({bt})...")
        elif packages:
            click.echo(f"📥 Installing {len(packages)} package(s) ({bt})...")
        elif include_local:
            click.echo(f"📥 Resolving dependencies of local source packages ({bt})...")
        else:
            click.echo(f"📥 Resolving workspace packages ({bt})...")
        succeeded = install_command(
            packages,
            bt,
            archive_version,
            archive_name,
            at_timestamp,
            tag=tag,
            include_local=include_local,
            strict_local_version=strict_local_version,
            upgrade=upgrade,
            all_packages=all_packages,
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
