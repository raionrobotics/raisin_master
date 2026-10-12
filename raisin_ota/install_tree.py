"""Versioned install tree with a single atomic commit point.

    release/versions/<gen>-<version>/   one complete package tree
    release/install -> versions/<gen>-<version>

`release/install` keeps the path every other consumer already uses
(`repo_dependency_check`, `index`); only its type changes, from a real
directory to a symlink. Nothing a run produces is live until the symlink moves,
so a failed install needs no compensation — it simply never commits — and a
rollback is one atomic operation rather than a sequence of undo steps.

Each commit records what it replaced in `release/.rollback`, and `rollback`
consumes that record: it undoes the last commit, once, and only that.

Directories carry a generation prefix so that re-installing the version that is
already live still stages into a fresh directory instead of mutating the tree
underneath a running system.
"""

import errno
import json
import os
import re
import shutil
from pathlib import Path
from typing import List, Optional, Tuple


class InstallTreeUnusable(Exception):
    """The versioned tree cannot be prepared where it has been placed.

    Almost always a layout question rather than a transient fault: mounting a
    bigger partition at `release/install` puts it on a different filesystem
    from `release/versions`, and neither the rename that adopts an existing
    tree nor the hardlink clone that stages a new one crosses that boundary.
    Raised with the cause named so the operator can move the mount instead of
    reading a traceback.
    """


_VERSIONS_DIR = "versions"
_CURRENT_LINK = "install"
_ROLLBACK_FILE = ".rollback"
# Written by earlier releases: the rollback target, and the install session that
# committed last. Read once, for a robot that committed before upgrading, and
# removed by the first commit after it.
_LEGACY_PREVIOUS_FILE = ".previous-version"
_LEGACY_SESSION_FILE = ".current-session"
_STAGING_MARKER = ".staging"
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


def _rollback_file(release) -> Path:
    return Path(release) / _ROLLBACK_FILE


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


def _is_our_link(link: Path) -> bool:
    """Whether this symlink is one this module created.

    Ours are always relative and inside `versions/`. Pointing
    `release/install` at another disk is how an operator moves a large package
    tree off a small root filesystem, and that link is not ours to repair —
    "repairing" it would put the next install back on the disk they moved it
    off, while reporting that something was fixed.
    """
    try:
        target = os.readlink(link)
    except OSError:
        return False
    if os.path.isabs(target):
        return False
    return Path(target).parts[:1] == (_VERSIONS_DIR,)


def _newest_available(release) -> Optional[str]:
    # A process killed before commit can leave the newest generation behind.
    # Repairing a missing link must never turn that partial tree into a release.
    generations = [item for item in _generations(release) if not _is_staging(item[2])]
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
        if not _is_our_link(link):
            return None  # someone else's link; leave it exactly as it is
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
    """Version a rollback would restore, or None when it would restore none."""
    record = _read_rollback(release)
    name = record.get("to") if record else None
    if not name or not (versions_dir(release) / name).is_dir():
        return None
    parsed = _split_generation(name)
    return parsed[1] if parsed else name


def rolls_back_to_none(release) -> bool:
    """Whether `rollback` would take the tree back to no version at all.

    True when the commit it would undo had nothing live before it -- a first
    install. Asked before rolling back by a caller with something of its own to
    remove first, so that a stop between the two leaves the commit in place for
    the next rollback to find.
    """
    record = _read_rollback(release)
    return (
        record is not None
        and record["to"] is None
        and _current_dir_name(release) in (record["from"], None)
    )


# ---------------------------------------------------------------------------
# Rollback record
# ---------------------------------------------------------------------------
#
# `release/.rollback` is what undoes the last commit, and nothing else:
#
#     {"from": "<gen committed>", "to": "<gen live before it>" | null}
#
# Written before the link moves and consumed by the rollback that undoes it,
# so it exists exactly while there is a commit to undo. `to` is null for a
# commit with nothing live before it -- a first install -- said rather than
# inferred from a file being absent: absent means there is nothing to undo.


def _read_rollback(release) -> Optional[dict]:
    """The record of the last commit, or None when there is none to undo.

    Unreadable is None too. A rollback that cannot tell where to go does
    nothing, which leaves the robot where it is rather than somewhere a guess
    put it.

    An earlier release's `.previous-version` wins when there is one. A commit
    here removes it before writing this record, so one still on disk was
    written since -- by that release committing after this one, or before this
    one ever committed -- and this record, if any, is older than it.
    """
    legacy = Path(release) / _LEGACY_PREVIOUS_FILE
    if legacy.exists() or legacy.is_symlink():
        return _legacy_rollback(release)
    try:
        record = json.loads(_rollback_file(release).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    source, target = record.get("from"), record.get("to")
    if not isinstance(source, str) or not source:
        return None
    if target is not None and (not isinstance(target, str) or not target):
        return None
    return {"from": source, "to": target}


def _legacy_rollback(release) -> Optional[dict]:
    """A robot that last committed before this record existed.

    Its `.previous-version` named the target and nothing named what it undid,
    so the live version stands in for it. Empty or unreadable is nothing to
    undo: it is not read as a first install -- that guess is what this record
    replaces.
    """
    try:
        target = (
            (Path(release) / _LEGACY_PREVIOUS_FILE).read_text(encoding="utf-8").strip()
        )
    except (OSError, ValueError):
        return None
    current = _current_dir_name(release)
    if not target or not current or target == current:
        return None
    return {"from": current, "to": target}


def _write_rollback(release, source: str, target: Optional[str]) -> None:
    """Record the commit about to happen. Raises rather than leave it unrecorded.

    A link moved with no record behind it is a commit nothing can undo, so a
    failure here stops the commit before the link moves. An earlier release's
    files go first: left, they would outrank this record (`_read_rollback`).
    """
    for name in (_LEGACY_PREVIOUS_FILE, _LEGACY_SESSION_FILE):
        (Path(release) / name).unlink(missing_ok=True)
    path = _rollback_file(release)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({"from": source, "to": target}), encoding="utf-8")
    os.replace(tmp, path)


def _clear_rollback(release) -> None:
    for name in (_ROLLBACK_FILE, _LEGACY_PREVIOUS_FILE, _LEGACY_SESSION_FILE):
        (Path(release) / name).unlink(missing_ok=True)


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
    try:
        link.rename(target)
    except OSError as exc:
        raise InstallTreeUnusable(_layout_hint(link, target.parent, exc)) from exc
    _point_current_at(release, target.name)
    return True


def _layout_hint(source, destination, exc: BaseException) -> str:
    """Explain a filesystem refusal in terms of what an operator can change."""
    if getattr(exc, "errno", None) == errno.EXDEV:
        return (
            f"{source} and {destination} are on different filesystems. The "
            "versioned install tree moves and hardlinks between them, which "
            "the kernel will not do across a mount point — mount the whole "
            "release/ directory rather than release/install."
        )
    return f"could not prepare the install tree at {destination}: {exc}"


def _clone_tree(src: Path, dst: Path) -> None:
    """Hardlink-clone so a partial install keeps untouched packages for free."""
    shutil.copytree(src, dst, copy_function=os.link, symlinks=True)


def safe_component(value: str, what: str) -> str:
    """`value`, if it can be one directory name. A `ValueError` naming it if not.

    Names arriving from the server end up as directory names: a version becomes
    `versions/<gen>-<version>`, a package name a directory under the install
    base. A separator in one of them leaves the tree it was meant to stay in,
    and on a robot the process writing it is root.

    Measured before this existed, staging into a throwaway tree:

        '1.0.0'                        -> release/versions/0001-1.0.0        inside
        '../ESCAPED'                   -> release/versions/0002-../ESCAPED   inside
        '1.0/../../../OUTSIDE/pwned'   -> OUTSIDE/pwned                      OUTSIDE

    Note the middle line. The generation prefix defeats a bare `..` by accident
    — `0002-..` is a literal name, not the parent — which is why this needs a
    separator to work and why the code reads as safe. `..` is refused anyway:
    the prefix is a coincidence of the naming scheme, not a guard, and a later
    change to it would turn that line into an escape with nothing failing.

    Refused rather than sanitised. A value this tool cannot use as a name is not
    one it should rename: a tree on disk under a name the server does not know
    is a robot the fleet cannot reason about.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{what} is empty, so it cannot name a directory")
    if "/" in value or "\\" in value or "\x00" in value or value == "..":
        raise ValueError(
            f"{what} {value!r} cannot be a directory name; refusing to write "
            f"outside the tree it belongs in"
        )
    return value


def stage_version(release, version: str) -> Path:
    """Prepare a new tree seeded from the live one. Nothing here is live yet."""
    # Before the mkdir below, which creates the parent and would otherwise leave
    # a directory behind on the way to refusing.
    version = safe_component(version, "version")
    staging = versions_dir(release) / f"{_next_generation(release):04d}-{version}"
    staging.parent.mkdir(parents=True, exist_ok=True)

    current = _current_dir_name(release)
    current_dir = versions_dir(release) / current if current else None
    if current_dir and current_dir.is_dir():
        try:
            _clone_tree(current_dir, staging)
        except (OSError, shutil.Error) as exc:
            shutil.rmtree(staging, ignore_errors=True)
            raise InstallTreeUnusable(
                _layout_hint(current_dir, staging.parent, exc)
            ) from exc
    else:
        staging.mkdir(parents=True, exist_ok=True)

    # Marked until committed, so a tree left behind by a crash is recognisable
    # as abandoned rather than counted as a version worth retaining.
    try:
        (staging / _STAGING_MARKER).write_text("", encoding="utf-8")
    except OSError:
        # An unmarked partial tree is eligible for symlink recovery. Refuse
        # to prepare packages there if its crash marker could not be written.
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return staging


def _is_staging(version_dir: Path) -> bool:
    return (version_dir / _STAGING_MARKER).exists()


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


def commit_version(
    release, version: str, session: Optional[str] = None
) -> Optional[str]:
    """Make a staged version live. Returns the directory now current.

    What was live before it is recorded first, so `rollback` can undo exactly
    this commit -- and when nothing was live, that is recorded too.

    `session` is accepted for the callers that pass it and is not used. It used
    to mark commits of one install, so that a second kept the first's rollback
    target; but a failed install keeps its session so the retry can resume it,
    and the retry's commit was taken for the same install committing twice --
    it recorded nothing, and its rollback took a robot with a version back to
    none. The only caller that committed twice for one install was `--all`,
    removed in 46a940c.
    """
    target = _resolve_version_dir(release, version)
    if target is None:
        return None

    outgoing = _current_dir_name(release)
    if outgoing == target.name:
        # Already live, so this commit changes nothing and there is nothing new
        # to undo. Recording it would read as a first install.
        return target.name
    _write_rollback(release, target.name, outgoing)
    _point_current_at(release, target.name)

    # Keep the marker until the atomic switch succeeds. A crash or refused
    # rename before that point must not leave a recovery-eligible partial tree.
    try:
        (target / _STAGING_MARKER).unlink()
    except OSError:
        pass

    return target.name


def rollback(release) -> Optional[str]:
    """Undo the last commit. Returns the version restored, or None.

    The tree goes back to what was live before that commit -- no version at
    all, for a first install -- and the version it undid is marked abandoned,
    so `ensure_tree` never relinks it and pruning removes it. The record is
    consumed: a second rollback with no commit between does nothing.

    Nothing is done when there is no record, or when the link is no longer on
    either end of it -- someone else moved it, and putting it back would undo
    their change rather than this commit.

    Safe to repeat after a crash part way through: each step is the same
    whether or not it already ran.
    """
    record = _read_rollback(release)
    if record is None:
        return None
    source, target = record["from"], record["to"]

    link = current_link(release)
    if link.is_symlink() and not _is_our_link(link):
        return None
    current = _current_dir_name(release)
    if target is None:
        if current not in (source, None):
            return None
    elif current not in (source, target):
        return None
    if target is not None and not (versions_dir(release) / target).is_dir():
        return None

    abandoned = versions_dir(release) / source
    if abandoned.is_dir():
        (abandoned / _STAGING_MARKER).write_text("", encoding="utf-8")
    if target is None:
        link.unlink(missing_ok=True)
    else:
        _point_current_at(release, target)
    _clear_rollback(release)

    if target is None:
        return None
    parsed = _split_generation(target)
    return parsed[1] if parsed else target


def discard_staging(release, version: str) -> None:
    """Remove an uncommitted staged tree."""
    target = _resolve_version_dir(release, version)
    if target is None or target.name == _current_dir_name(release):
        return
    shutil.rmtree(target, ignore_errors=True)


def prune_versions(release, keep: int = 2) -> List[str]:
    """Drop old generations, never the live one or its rollback target.

    Abandoned staging trees are removed outright rather than counted toward
    `keep`: nothing points at them, and being the newest generations they would
    otherwise take the slots real versions should hold — so `keep=2` would stop
    meaning two versions.
    """
    generations = _generations(release)
    record = _read_rollback(release)
    protected = {_current_dir_name(release), record and record["to"]}
    keep = max(1, keep)

    removed = []
    committed = []
    for _, _, entry in generations:
        if _is_staging(entry) and entry.name not in protected:
            shutil.rmtree(entry, ignore_errors=True)
            removed.append(entry.name)
        else:
            committed.append(entry)

    for entry in committed[:-keep] if keep < len(committed) else []:
        if entry.name in protected:
            continue
        shutil.rmtree(entry, ignore_errors=True)
        removed.append(entry.name)
    return removed
