"""Writes that survive a power cut, not only a crash.

A rename is atomic, not durable. Write-then-rename keeps a file whole when the
process dies; after a power cut -- common on a robot -- the new name can be
gone, or present over data that never reached the disk. A file another step
relies on is flushed before that step.

Public because the OTA agent keeps state of the same kind -- the marks its
recovery starts from -- and one implementation serves both.
"""

import os
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
    """Replace `path` with `text`, on disk before this returns."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    fsync_directory(path.parent)
