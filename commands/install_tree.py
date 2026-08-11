"""Versioned install tree with a single atomic commit point.

    release/versions/<gen>-<version>/   one complete package tree
    release/install -> versions/<gen>-<version>

`release/install` keeps the path every other consumer already uses
(`repo_dependency_check`, `index`); only its type changes, from a real
directory to a symlink. Nothing a run produces is live until the symlink moves,
so a failed install needs no compensation — it simply never commits — and a
rollback is one atomic operation rather than a sequence of undo steps.

Directories carry a generation prefix so that re-installing the version that is
already live still stages into a fresh directory instead of mutating the tree
underneath a running system.
"""

import os
import re
import shutil
from pathlib import Path
from typing import List, Optional, Tuple

_VERSIONS_DIR = "versions"
_CURRENT_LINK = "install"
_PREVIOUS_FILE = ".previous-version"
_LEGACY_VERSION = "legacy"

_GENERATION_RE = re.compile(r"^(\d{4})-(.+)$")


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def release_for(install_path) -> Path:
    """The release directory that owns a given `.../release/install` path."""
    return Path(install_path).parent


def versions_dir(release) -> Path:
    return Path(release) / _VERSIONS_DIR


def current_link(release) -> Path:
    return Path(release) / _CURRENT_LINK


def _previous_file(release) -> Path:
    return Path(release) / _PREVIOUS_FILE


def _split_generation(name: str) -> Optional[Tuple[int, str]]:
    match = _GENERATION_RE.match(name)
    return (int(match.group(1)), match.group(2)) if match else None


def _generations(release) -> List[Tuple[int, str, Path]]:
    """Every staged or committed version directory, oldest generation first."""
    base = versions_dir(release)
    if not base.is_dir():
        return []

    found = []
    for entry in base.iterdir():
        if not entry.is_dir():
            continue
        parsed = _split_generation(entry.name)
        if parsed:
            found.append((parsed[0], parsed[1], entry))
    return sorted(found, key=lambda item: item[0])


def _next_generation(release) -> int:
    generations = _generations(release)
    return (generations[-1][0] + 1) if generations else 1


def _current_dir_name(release) -> Optional[str]:
    link = current_link(release)
    if not link.is_symlink():
        return None

    name = Path(os.readlink(link)).name
    # A dangling link means the version was removed underneath us. Reporting it
    # anyway would tell the OTA server this robot runs software that is not on
    # its disk, so an unresolvable link counts as nothing installed.
    if not (versions_dir(release) / name).is_dir():
        return None
    return name


def _newest_available(release) -> Optional[str]:
    generations = _generations(release)
    return generations[-1][2].name if generations else None


def ensure_tree(release) -> Optional[str]:
    """Repair the live symlink after manual surgery. Returns what it did, or None.

    `release/install` is one `rm` away from being wrong, and the package data
    usually survives whatever happened to the link — so recover from the
    versions on disk rather than treating the robot as empty and silently
    reinstalling from scratch.
    """
    link = current_link(release)

    if link.is_symlink():
        if _current_dir_name(release) is not None:
            return None  # healthy
        recovered = _newest_available(release)
        if recovered:
            _point_current_at(release, recovered)
            return f"relinked release/install to {recovered} (was dangling)"
        try:
            link.unlink()
        except OSError:
            pass
        return "removed a dangling release/install link"

    if link.is_dir():
        # Either a pre-versioning tree or a directory someone restored on top.
        if migrate_legacy_tree(release):
            return "adopted release/install directory as a version"
        return None

    recovered = _newest_available(release)
    if recovered:
        _point_current_at(release, recovered)
        return f"restored missing release/install link to {recovered}"
    return None


def current_version(release) -> Optional[str]:
    """Version the live symlink points at, or None if nothing is committed."""
    name = _current_dir_name(release)
    if not name:
        return None
    parsed = _split_generation(name)
    return parsed[1] if parsed else name


def previous_version(release) -> Optional[str]:
    """Version a rollback would restore."""
    name = _previous_dir_name(release)
    if not name:
        return None
    parsed = _split_generation(name)
    return parsed[1] if parsed else name


def _previous_dir_name(release) -> Optional[str]:
    try:
        name = _previous_file(release).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not name or not (versions_dir(release) / name).is_dir():
        return None
    return name


def _write_previous(release, dir_name: Optional[str]) -> None:
    path = _previous_file(release)
    try:
        if dir_name is None:
            if path.exists():
                path.unlink()
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dir_name, encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Commit point
# ---------------------------------------------------------------------------


def _point_current_at(release, dir_name: str) -> None:
    """Repoint the live symlink. This is the only step that changes what runs."""
    link = current_link(release)
    tmp = link.with_name(link.name + ".tmp")
    try:
        if tmp.is_symlink() or tmp.exists():
            tmp.unlink()
    except OSError:
        pass

    # Relative so the tree survives being moved or mounted elsewhere.
    os.symlink(os.path.join(_VERSIONS_DIR, dir_name), tmp, target_is_directory=True)
    os.replace(tmp, link)


def migrate_legacy_tree(release) -> bool:
    """Convert a pre-versioning `release/install` directory into generation 1.

    Moves rather than copies: an install tree is large, and a copy would need
    twice the disk on exactly the robots least likely to have it.
    """
    link = current_link(release)
    if link.is_symlink():
        return False
    if not link.is_dir():
        return False

    target = (
        versions_dir(release) / f"{_next_generation(release):04d}-{_LEGACY_VERSION}"
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    link.rename(target)
    _point_current_at(release, target.name)
    return True


def _clone_tree(src: Path, dst: Path) -> None:
    """Hardlink-clone so a partial install keeps untouched packages for free."""
    shutil.copytree(src, dst, copy_function=os.link, symlinks=True)


def stage_version(release, version: str) -> Path:
    """Prepare a new tree seeded from the live one. Nothing here is live yet."""
    staging = versions_dir(release) / f"{_next_generation(release):04d}-{version}"
    staging.parent.mkdir(parents=True, exist_ok=True)

    current = _current_dir_name(release)
    current_dir = versions_dir(release) / current if current else None
    if current_dir and current_dir.is_dir():
        _clone_tree(current_dir, staging)
    else:
        staging.mkdir(parents=True, exist_ok=True)
    return staging


def replace_package_dir(staging: Path, relative: Path) -> Path:
    """Clear a package directory inside a staged tree before writing into it.

    A staged tree is hardlink-cloned from the live one, so its files share
    inodes with the version a rollback would restore. Writing into an existing
    file would edit that version too. Removing the directory first breaks the
    link; the OTA extract path already does exactly this, and anything else
    writing into a staged tree must too.
    """
    target = staging / relative
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    return target


def _resolve_version_dir(release, version: str) -> Optional[Path]:
    matches = [entry for gen, name, entry in _generations(release) if name == version]
    return matches[-1] if matches else None


def commit_version(release, version: str) -> Optional[str]:
    """Make a staged version live. Returns the directory now current."""
    target = _resolve_version_dir(release, version)
    if target is None:
        return None

    outgoing = _current_dir_name(release)
    _point_current_at(release, target.name)
    if outgoing and outgoing != target.name:
        _write_previous(release, outgoing)
    return target.name


def rollback(release) -> Optional[str]:
    """Restore the previous version. Returns its version, or None if there is none."""
    previous = _previous_dir_name(release)
    if not previous:
        return None

    _point_current_at(release, previous)

    # The version before the restored one becomes the next rollback target, so
    # a second failure does not bounce back onto the version just rejected.
    ordered = [name for _, _, entry in _generations(release) for name in (entry.name,)]
    try:
        index = ordered.index(previous)
    except ValueError:
        index = 0
    _write_previous(release, ordered[index - 1] if index > 0 else None)

    parsed = _split_generation(previous)
    return parsed[1] if parsed else previous


def discard_staging(release, version: str) -> None:
    """Remove an uncommitted staged tree."""
    target = _resolve_version_dir(release, version)
    if target is None or target.name == _current_dir_name(release):
        return
    shutil.rmtree(target, ignore_errors=True)


def prune_versions(release, keep: int = 2) -> List[str]:
    """Drop old generations, never the live one or its rollback target."""
    generations = _generations(release)
    protected = {_current_dir_name(release), _previous_dir_name(release)}
    keep = max(1, keep)

    removed = []
    for _, _, entry in generations[:-keep] if keep < len(generations) else []:
        if entry.name in protected:
            continue
        shutil.rmtree(entry, ignore_errors=True)
        removed.append(entry.name)
    return removed
