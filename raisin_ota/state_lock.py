"""One process at a time may change a workspace's install state.

The CLI and resident agent share more than the live install symlink. They also
share resumable partial downloads, the event queue and the current install
session. Atomic files keep each individual write whole; they do not make an
install spanning all four areas safe to interleave with another install.

This lock is deliberately advisory. It coordinates the two supported writers,
not arbitrary software with filesystem access. The kernel owns the lock, so a
process crash or SIGKILL releases it without a stale-lock cleanup protocol.
The file remains only to tell a losing process who currently holds the lock.
"""

import errno
import json
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - the robot and CI are POSIX
    fcntl = None


_LOCK_FILE = ".raisin-install.lock"
_MAX_METADATA_BYTES = 4096


class InstallStateBusy(RuntimeError):
    """Another supported writer already owns this workspace's install state."""

    def __init__(self, path: Path, holder: Optional[dict] = None):
        self.path = Path(path)
        self.holder = holder or {}
        name = str(self.holder.get("name") or "an unknown process")
        pid = self.holder.get("pid")
        since = self.holder.get("acquiredAt")
        details = name
        if isinstance(pid, int):
            details += f" (pid {pid})"
        if isinstance(since, str) and since:
            details += f", since {since}"
        super().__init__(
            f"install state for {self.path.parent} is busy; held by {details}"
        )


class InstallStateLockUnavailable(RuntimeError):
    """This platform or lock path cannot provide the required crash-safe lock."""


def install_state_lock_path(workspace) -> Path:
    """The one lock identity every install-state writer must use."""
    return Path(workspace).resolve() / _LOCK_FILE


class InstallStateLock:
    """Non-blocking, crash-released exclusive lock for one workspace."""

    def __init__(self, workspace, holder: str):
        self.path = install_state_lock_path(workspace)
        self.holder = str(holder).strip() or "unnamed install writer"
        self._fd: Optional[int] = None

    def __enter__(self):
        if fcntl is None:
            raise InstallStateLockUnavailable(
                "install-state locking requires POSIX flock support"
            )

        fd = self._open_lock_file()
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno not in (errno.EAGAIN, errno.EACCES):
                    raise
                holder = self._read_holder(fd)
                raise InstallStateBusy(self.path, holder) from None

            self._write_holder(fd)
            self._fd = fd
            return self
        except Exception:
            os.close(fd)
            raise

    def __exit__(self, _error_type, _error, _traceback):
        fd, self._fd = self._fd, None
        if fd is None:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return False

    def _open_lock_file(self) -> int:
        """Open a regular, non-symlink lock file shared across service users."""
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        created = False
        try:
            fd = os.open(
                self.path,
                flags | no_follow | os.O_CREAT | os.O_EXCL,
                0o666,
            )
            created = True
        except FileExistsError:
            try:
                fd = os.open(self.path, flags | no_follow)
            except OSError as error:
                raise InstallStateLockUnavailable(
                    f"cannot open install-state lock {self.path}: {error}"
                ) from error
        except OSError as error:
            raise InstallStateLockUnavailable(
                f"cannot create install-state lock {self.path}: {error}"
            ) from error

        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise InstallStateLockUnavailable(
                    f"install-state lock is not a regular file: {self.path}"
                )
            # The agent may run as root while the CLI runs as the workspace
            # owner. The file contains no authority or secret, and flock is the
            # protection; make the inode openable by both identities.
            if created:
                os.fchmod(fd, 0o666)
            return fd
        except Exception:
            os.close(fd)
            raise

    def _write_holder(self, fd: int) -> None:
        metadata = {
            "name": self.holder[:200],
            "pid": os.getpid(),
            "acquiredAt": datetime.now(timezone.utc).isoformat(),
        }
        encoded = (json.dumps(metadata, sort_keys=True) + "\n").encode("utf-8")
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        remaining = memoryview(encoded)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError(
                    "install-state holder metadata write made no progress"
                )
            remaining = remaining[written:]

    @staticmethod
    def _read_holder(fd: int) -> dict:
        # The winner holds the kernel lock before it can publish metadata. A
        # contender retries only the description, never the lock itself.
        for attempt in range(5):
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                raw = os.read(fd, _MAX_METADATA_BYTES)
                value = json.loads(raw.decode("utf-8"))
                if isinstance(value, dict) and value.get("name"):
                    return value
            except (OSError, UnicodeError, json.JSONDecodeError):
                pass
            if attempt < 4:
                time.sleep(0.01)
        return {}


def install_state_lock(workspace, holder: str) -> InstallStateLock:
    """Return a fail-fast lock context for one complete install-state action."""
    return InstallStateLock(workspace, holder)
