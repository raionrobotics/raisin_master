"""The runtime prefix, assembled from the packages OTA delivered.

`release/install` holds what was delivered, one tree per package and platform;
nothing executes from it. `<workspace>/install` is what a node runs: every
package merged into one prefix, with the device's own configuration laid on top.
This module builds the second from the first.

It knows nothing about `src/` or compiling, and that is the boundary it exists
to hold. `raisin setup` used to be the only way to build this prefix, and setup
also prepares a source build, so an agent that ran it inherited every source
check: a robot with a leftover `src/` failed its install in the guard that
compares sources against binaries. A robot runs what it was delivered, whatever
else is in the workspace.

Two callers, deliberately the same code:

- the agent calls `assemble`, and nothing else;
- `raisin setup` calls the pieces, with its source overlay between them, and
  passes the repositories it builds from source as `skip`.

Here rather than in `commands/`, because the agent can only call what is
installed with it. `commands/` is not packaged, and the checkout on a robot is
whatever provisioning cloned, never updated by OTA; this package is pinned by
the agent and arrives with it.
"""

import glob
import os
import shutil
import stat
from pathlib import Path
from typing import Collection, List

from .client import OtaContext


def deploy_packages(
    context: OtaContext, prefix: Path, skip: Collection[str] = ()
) -> List[Path]:
    """Copy every delivered package built for this platform into `prefix`.

    Build types of one package are merged into the same prefix. Packages named
    in `skip` are left out.

    Raises on the first copy that fails. A prefix missing packages and
    reported as deployed is a node that starts on half a release.

    Returns:
        The package directories copied, in the order they were copied.
    """
    pattern = os.path.join(
        context.workspace,
        "release",
        "install",
        "*",
        context.os_type,
        context.os_version,
        context.architecture,
        "*",
    )
    deployed = []
    for source in glob.glob(pattern):
        source = Path(source)
        if not source.is_dir():
            continue
        # .../install/<package>/<os>/<os_version>/<arch>/<build_type>
        if source.parents[3].name in skip:
            continue
        shutil.copytree(source, prefix, dirs_exist_ok=True)
        deployed.append(source)

    _make_executable(prefix / "bin")
    return deployed


def make_scripts_executable(prefix: Path) -> None:
    """Mark every `*.sh` under `<prefix>/scripts` executable."""
    scripts_root = prefix / "scripts"
    if not scripts_root.is_dir():
        return
    for script_path in scripts_root.rglob("*.sh"):
        if script_path.is_file():
            try:
                mode = script_path.stat().st_mode
                script_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except OSError:
                print(f"⚠️  Failed to set executable: {script_path}")


def copy_device_resources(prefix: Path, home: Path) -> None:
    """Lay `<home>/.raisin/<name>/resource` over `<prefix>/resource/<name>/resource`.

    `.raisin` is what provisioning writes for this one device, so it goes in
    after the packages and replaces their defaults. `home` is passed rather
    than read because the agent's own HOME is not the workspace owner's.
    """
    target_dir = "resource"
    for root, dirs, files in os.walk(Path(home) / ".raisin"):
        if target_dir in dirs:
            source_dir = os.path.join(root, target_dir)
            dest_dir = os.path.join(
                prefix, "resource", os.path.basename(root), target_dir
            )

            for item in os.listdir(source_dir):
                s = os.path.join(source_dir, item)
                d = os.path.join(dest_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)


def assemble(context: OtaContext, home: Path) -> List[Path]:
    """Build `<workspace>/install` from scratch out of the delivered packages.

    What a node needs and nothing a compiler needs: no generated headers, no
    CMake files, and no reading of `src/`.

    Returns:
        The package directories copied.
    """
    prefix = Path(context.workspace) / "install"
    if prefix.exists():
        shutil.rmtree(prefix)
    prefix.mkdir(parents=True)

    deployed = deploy_packages(context, prefix)
    make_scripts_executable(prefix)
    copy_device_resources(prefix, home)
    return deployed


def _make_executable(directory: Path) -> None:
    if not directory.exists():
        return
    for root, _dirs, files in os.walk(directory):
        for file in files:
            os.chmod(os.path.join(root, file), 0o755)
