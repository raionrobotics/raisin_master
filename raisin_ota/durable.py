"""Writes that survive a power cut, not only a crash.

A rename is atomic, not durable. Write-then-rename keeps a file whole when the
process dies; after a power cut -- common on a robot -- the new name can be
gone, or present over data that never reached the disk. A file another step
relies on is flushed before that step.

Public because the OTA agent keeps state of the same kind -- the marks its
recovery starts from -- and one implementation serves both.
"""

import os
import uuid
from pathlib import Path


def fsync_directory(directory) -> None:
    """Make the names in `directory` durable.

    Best effort: not every filesystem opens a directory for fsync, and one that
    does not has nothing more to offer here.
    """
    try:
        descriptor = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def write_durably(path, text: str) -> None:
    """Replace `path` with `text`, on disk before this returns.

    Raises rather than report a failure some other way: a caller that must not
    go on without the file -- a commit that may not move its link unrecorded --
    needs to be stopped, and one that can go on catches it.

    The temporary file is named afresh each time and removed on failure, so a
    caller needs no lock to keep two writers apart and leaves nothing behind.
    It is created with the umask's mode, like the file it replaces.
    """
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with open(tmp, "x", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    fsync_directory(path.parent)
