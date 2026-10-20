"""One ZIP name/permission boundary for robot and build-machine extraction.

Callers own the destination hierarchy and exclude concurrent writers. This is
not a sandbox for an attacker concurrently changing the extraction directory.
"""

from contextlib import ExitStack
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import zipfile

PERMITTED_MODE = 0o755
_WINDOWS_NAMES = os.name == "nt"
_DESCRIPTOR_CHMOD = (
    all(
        hasattr(os, flag)
        for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "fchmod")
    )
    and os.open in os.supports_dir_fd
)


def checked_members(archive: zipfile.ZipFile) -> list:
    """Validate the entire member set BEFORE extracting or removing old files.

    extractall normalizes unsafe names; raw-path chmod would not. Refuse those
    names rather than letting two writers interpret the same ZIP differently.
    https://docs.python.org/3.9/library/zipfile.html#zipfile.ZipFile.extract
    """
    members = []
    seen = set()
    for entry in archive.infolist():
        name = entry.filename
        relative = PurePosixPath(name)
        if (
            not name
            or entry.orig_filename != name
            or "\\" in name
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in name)
            or relative.is_absolute()
            or PureWindowsPath(name).drive
            or ".." in relative.parts
            or (not relative.parts and not entry.is_dir())
            or relative in seen
        ):
            raise zipfile.BadZipFile("unsafe or ambiguous package entry")
        if _WINDOWS_NAMES and any(
            any(char in '<>:"|?*' for char in part)
            or part.endswith((" ", "."))
            or PureWindowsPath(part).is_reserved()
            for part in relative.parts
        ):
            raise zipfile.BadZipFile("unsafe Windows package entry")
        seen.add(relative)
        members.append((entry, relative.parts))
    return members


def _validate_target(root, entry, parts):
    try:
        info = root.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISDIR(info.st_mode) or _reparse(info):
            raise zipfile.BadZipFile("unsafe package destination")
    target = root
    for index, part in enumerate(parts):
        target /= part
        try:
            info = target.lstat()
        except FileNotFoundError:
            break
        final_file = index == len(parts) - 1 and not entry.is_dir()
        if (
            _reparse(info)
            or (final_file and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))
            or (not final_file and not stat.S_ISDIR(info.st_mode))
        ):
            raise zipfile.BadZipFile("aliased package destination")


def _reparse(info):
    return bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def validate_targets(
    archive: zipfile.ZipFile, into: Path, *, best_effort=False
) -> list:
    """Validate all aliases before effects; ordinary mode-I/O errors may warn."""
    accepted = []
    for entry, parts in checked_members(archive):
        try:
            _validate_target(Path(into), entry, parts)
        except OSError as error:
            if not best_effort:
                raise
            print(f"⚠️ Could not set the mode of '{entry.filename}': {error}")
        else:
            accepted.append((entry, parts))
    return accepted


def restore_modes(archive: zipfile.ZipFile, into: Path) -> None:
    """Restore only publisher file permissions, without following ZIP aliases.

    ZIP extraction drops executable bits. Retain the existing best-effort mode
    restoration and0755 ceiling, but path/type/alias violations refuse the ZIP.
    """
    members = validate_targets(archive, into, best_effort=True)
    for entry, parts in members:
        stored = (entry.external_attr >> 16) & 0o7777
        if entry.is_dir() or not stored:
            continue
        try:
            if not _DESCRIPTOR_CHMOD:
                # Windows lacks POSIX nofollow directory FDs. Keep its existing
                # chmod behavior after whole-set name/physical-alias validation.
                # Both paths require the caller-owned, stable hierarchy above.
                Path(into).joinpath(*parts).chmod(stored & PERMITTED_MODE)
                continue
            with ExitStack() as stack:
                parent = os.open(
                    into, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                )
                stack.callback(os.close, parent)
                for part in parts[:-1]:
                    parent = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=parent,
                    )
                    stack.callback(os.close, parent)
                flags = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                try:
                    fd = os.open(parts[-1], os.O_RDONLY | flags, dir_fd=parent)
                except PermissionError:
                    # Owned0200 outputs can be overwritten but not read. No
                    # TRUNC/CREAT or write occurs: this FD is only for fchmod.
                    fd = os.open(parts[-1], os.O_WRONLY | flags, dir_fd=parent)
                stack.callback(os.close, fd)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise zipfile.BadZipFile("aliased or non-file package destination")
                os.fchmod(fd, stored & PERMITTED_MODE)
        except OSError as error:
            print(f"⚠️ Could not set the mode of '{entry.filename}': {error}")
