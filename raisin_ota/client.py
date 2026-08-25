"""
OTA client for RAISIN.

Handles all interactions with the raisin-ota-server:
- SSH challenge-response authentication (no passwords)
- Package upload (used by publish command)
- Package download (used by install command)

Uses DEFAULT_OTA_ENDPOINT by default. Override with RAISIN_OTA_ENDPOINT env var.
All operations fail gracefully — OTA is supplementary, never blocks existing flows.
"""

import base64
import errno
import json
import os
import random
import re
import hashlib
import shutil
import stat
import struct
import subprocess
import tempfile
import time
import uuid
import zipfile

import requests
import yaml
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import install_tree
from .install_tree import safe_component

# Module-level cached auth token (lives for the CLI session)
_cached_token = None

# Prevents repeated auth attempts after a failure within the same session
_auth_failed = False

# Module-level archive manifest cache to avoid repeated API calls
# Key: (archive_name, platform_str) → Value: (packages_list, archive_id, archive_version)
_archive_cache = {}

# Correlates all OTA package downloads and the final software snapshot from
# one CLI process.
_install_session_id = None

# Debounces per-package installs into one software snapshot report per archive
# at the end of the CLI process.
_pending_snapshot_reports = {}

# Caches file-backed robot API keys by path and file stat metadata.

# Default archive name prefix (build_type is appended for debug)
DEFAULT_ARCHIVE_NAME = "raisin-robot"

# Default OTA server endpoint
DEFAULT_OTA_ENDPOINT = "https://raisin-ota-api.raionrobotics.com/api"

# Persistent token cache file name (stored in script_directory)
_TOKEN_CACHE_FILE = ".ota_token_cache.json"

# Per-install metadata file written after OTA extraction
_INSTALL_METADATA_FILE = "ota-install.json"

# Correlation id for one install, persisted so a crashed run resumes the same
# session rather than inventing a new one.
_INSTALL_SESSION_FILE = ".ota-session.json"
_INSTALL_SESSION_TTL_SECONDS = 24 * 60 * 60

# Install events are buffered on disk so an offline robot still reports what
# happened once it can reach the server again.
_INSTALL_EVENT_QUEUE_FILE = ".ota-install-events.jsonl"
_INSTALL_EVENT_STATE_FILE = ".ota-install-events.state.json"
_INSTALL_EVENT_BATCH_LIMIT = 100

# An offline robot buffers indefinitely, so the queue needs a ceiling. Newest
# events are kept: they describe the state the fleet still needs to know about.
_MAX_BUFFERED_INSTALL_EVENTS = 1000
_TERMINAL_EVENT_TYPES = frozenset({"succeeded", "failed", "rolled_back"})

# First failure of the current attempt. A terminal event means the attempt
# finished, so the decision is deferred to the end of the run instead of being
# emitted from inside the package loop while downloads are still going.
_pending_install_failure = None

# Robot API key configuration. The key file is intentionally outside the repo.
_ROBOT_API_KEY_FILE = "robot-api-key"  # pragma: allowlist secret
_ROBOT_API_KEY_ENV = "RAISIN_ROBOT_API_KEY"  # pragma: allowlist secret
_ROBOT_API_KEY_FILE_ENV = "RAISIN_ROBOT_API_KEY_FILE"  # pragma: allowlist secret
_ROBOT_NODE_ENV = "RAISIN_ROBOT_NODE"
_ROBOT_NODE_KEY_ENV = "RAISIN_ROBOT_NODE_KEY"
_ROBOT_CONFIG_FILES = ("configuration_setting.yaml", "secrets.yaml")

# Caches parsed local config by path and file stat metadata.

# Client identity attached to robot OTA audit/history records.
DEFAULT_CLIENT_VERSION = "raisin-cli"


# ============================================================================
# Runtime context
# ============================================================================


def _normalize_optional_string(value) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    if not value or value.lower() in {"none", "null"}:
        return None
    return value


@dataclass(frozen=True)
class RobotIdentity:
    """Who this process is to the OTA server.

    Resolving this — environment, config files, a key file under someone's
    HOME — is the caller's job. A robot on a service account and a developer
    at a shell answer it differently, and a human running the tool on a robot
    must not be attributed to the robot just because a key file is on disk.
    """

    api_key: str
    node_key: str
    client_version: str = DEFAULT_CLIENT_VERSION


@dataclass(frozen=True)
class OtaContext:
    """Where this process works and what platform it is working for.

    The CLI fills these from its own startup; an agent supplies them directly.
    Reading them from a CLI module would tie the core to a process that only
    exists in one of its two callers.
    """

    workspace: Path
    os_type: str
    os_version: str
    architecture: str
    robot: Optional[RobotIdentity] = None

    @property
    def platform(self) -> str:
        """Platform string as the OTA server names it, e.g. ubuntu-24.04-arm64."""
        return f"{self.os_type}-{self.os_version}-{self.architecture}"

    def package_dir(self, base: Path, package: str, build_type: str) -> Path:
        """Where one package's files live under an install tree.

        The package name comes from the server's manifest and becomes a
        directory, so it is checked here — the one place the layout is built,
        and the place every caller that writes a package goes through. Without
        it, `../ESCAPED` put a package tree outside the install base and
        `a/../../../../OUTSIDE` put it anywhere the process could write, which
        on a robot is anywhere at all.

        `build_type` is checked with it, but for a weaker reason and it is worth
        being clear about the difference: it is *caller*-supplied, not
        server-supplied — a `click.Choice(["debug", "release"])` on the CLI and
        an environment-settable default in the agent. Nothing in a server
        response reaches it. So this half is depth on a path component rather
        than a vector being closed.
        """
        return (
            Path(base)
            / safe_component(package, "package name")
            / self.os_type
            / self.os_version
            / self.architecture
            / safe_component(build_type, "build type")
        )


_context = None


def configure(context: OtaContext) -> None:
    """Point the core at a workspace and platform. Call once at startup."""
    global _context
    _context = context


def _client_version() -> str:
    robot = _ctx().robot
    return robot.client_version if robot else DEFAULT_CLIENT_VERSION


def _ctx() -> OtaContext:
    if _context is None:
        raise RuntimeError(
            "OTA core is not configured; call ota_client.configure(OtaContext(...)) "
            "before using it."
        )
    return _context


def parse_version_specifier(spec_str):
    """Parse a version specifier string into a SpecifierSet.

    Kept here rather than imported: the CLI's utils module pulls in process
    globals at import time, and this function needs none of them.

        ""            -> >=0.0.0 (any version)
        ">=1.0.0"     -> standard specifier
        ">=1.0,<2.0"  -> compound specifier
        "1.0.0"       -> treated as ==1.0.0

    Returns a SpecifierSet, or None when the string cannot be parsed.
    """
    try:
        spec_str = (spec_str or "").strip()
        if not spec_str:
            return SpecifierSet(">=0.0.0")

        specifiers = re.findall(r"[<>=!~]+[\d.]+", spec_str)
        if specifiers:
            formatted = ", ".join(specifiers)
            formatted = formatted.replace(">, =", ">=").replace("< =", "<=")
            return SpecifierSet(formatted)

        if re.match(r"^[\d.]+$", spec_str):
            return SpecifierSet(f"=={spec_str}")

        return None
    except InvalidSpecifier:
        return None


# ============================================================================
# Configuration
# ============================================================================


def get_ota_endpoint() -> str:
    """Read RAISIN_OTA_ENDPOINT env var, or use default.

    Returns the OTA server endpoint. Uses DEFAULT_OTA_ENDPOINT if env var is not set.
    """
    return os.environ.get("RAISIN_OTA_ENDPOINT", DEFAULT_OTA_ENDPOINT).strip()


def get_ssh_key_path() -> Path:
    """Get SSH private key path for OTA authentication.

    Resolution order:
        1. RAISIN_SSH_KEY environment variable (if set)
        2. First existing key from: id_ed25519, id_ecdsa, id_rsa
        3. Default to ~/.ssh/id_ed25519 (even if not exists)
    """
    # 1. Check env var
    env_key = os.environ.get("RAISIN_SSH_KEY", "").strip()
    if env_key:
        return Path(env_key).expanduser()

    # 2. Try common key locations in order of preference
    ssh_dir = Path.home() / ".ssh"
    for key_name in ("id_ed25519", "id_ecdsa", "id_rsa"):
        key_path = ssh_dir / key_name
        if key_path.exists():
            return key_path

    # 3. Default fallback
    return ssh_dir / "id_ed25519"


def _robot_state_path(filename: str) -> Path:
    """Robot state that has to outlive a build.

    `<workspace>/install` is deleted and recreated by every full build
    (`setup.py`), so anything kept there is gone by the next run. That is fatal
    for the event queue in particular: buffering exists so a robot that was
    offline when an install failed still reports on a later run, and a build in
    between must not erase what it was going to say. `release/` already holds
    the install tree's own state and no build removes it.

    A file left at the old location is carried over rather than abandoned: an
    upgrade must not throw away reports the previous client had buffered.
    """
    current = _ctx().workspace / "release" / filename
    legacy = _ctx().workspace / "install" / filename
    if legacy.exists() and not current.exists():
        try:
            current.parent.mkdir(parents=True, exist_ok=True)
            legacy.replace(current)
        except OSError:
            # Keep reading the old copy rather than losing it.
            return legacy
    return current


def _install_session_path() -> Path:
    return _robot_state_path(_INSTALL_SESSION_FILE)


def _read_install_session() -> Optional[str]:
    """Recover the session an interrupted install was using, if still current."""
    try:
        data = json.loads(_install_session_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None

    session_id = data.get("installSessionId")
    started_at = data.get("startedAt")
    if not isinstance(session_id, str) or not session_id:
        return None
    if not isinstance(started_at, (int, float)):
        return None
    if time.time() - started_at > _INSTALL_SESSION_TTL_SECONDS:
        return None
    return session_id


def _persist_install_session(session_id: str) -> None:
    path = _install_session_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"installSessionId": session_id, "startedAt": time.time()}),
            encoding="utf-8",
        )
    except OSError:
        pass


def get_install_session_id() -> str:
    """Return the install session id, resuming an interrupted one if present.

    A retry after a crash has to keep the same id: the server pins download
    authorization to what desired state resolved at session start, and the
    partial files on disk belong to that session.
    """
    global _install_session_id
    if _install_session_id:
        return _install_session_id

    resumed = _read_install_session()
    _install_session_id = resumed or str(uuid.uuid4())
    if not resumed:
        _persist_install_session(_install_session_id)
    return _install_session_id


def _archive_identity_from_tree(
    install_base_path: Path, build_type: str
) -> Optional[tuple]:
    """(archive_id, name, version) recorded in whatever tree is live right now.

    Read back rather than remembered: after a rollback the live tree is the
    *previous* archive, and only its own install metadata knows which one that
    was. A tree adopted from a pre-versioning install has no such metadata and
    yields None.

    Scoped to this machine's platform. The pattern used to be
    `*/*/*/*/<build>/…`, and those four wildcards are
    `<package>/<os_type>/<os_version>/<architecture>` — so the OS, the version
    and the architecture were all accepted as anything and whichever path sorted
    first won. `archiveId` is per-platform, so a robot that installed its own
    software never saw it; a tree that came from somewhere else did — a golden
    image cloned across hardware, a disk swap, a workspace restored from another
    robot's backup. An x86 machine holding an arm64 tree reported itself as
    running the arm64 archive, and the agent comparing that against what it was
    assigned could conclude it was already converged: install nothing, report
    nothing, and read as a quiet healthy node forever.

    The platform is not an argument and does not need to be — the process said
    what it was at startup. This asked the tree instead. `_unusable_packages`
    already scopes through `package_dir`, and the sibling reader
    `_collect_archive_snapshot_packages` rejects a foreign entry on
    `metadata["platform"]`; this was the one that checked neither.

    Derived from `package_dir` rather than spelled out again, so a change to the
    tree's shape cannot leave this reading the old one.
    """
    scoped = _ctx().package_dir(Path(install_base_path), "*", build_type)
    pattern = str(scoped.relative_to(Path(install_base_path)) / _INSTALL_METADATA_FILE)
    for metadata_path in sorted(Path(install_base_path).glob(pattern)):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(metadata, dict) or metadata.get("source") != "archive":
            continue

        archive_id = _normalize_optional_string(metadata.get("archiveId"))
        name = _normalize_optional_string(metadata.get("archiveName"))
        version = _normalize_optional_string(metadata.get("archiveVersion"))
        if archive_id and name and version:
            return (archive_id, name, version)
    return None


def _report_restored_snapshot(
    install_base_path: Path, build_type: str, install_session_id: str
) -> None:
    """Tell the server what the robot is running after a rollback.

    A snapshot is otherwise only sent on a successful commit, so a rollback
    that stays silent leaves the fleet view showing the version that was just
    reverted — software the robot is no longer running.
    """
    identity = _archive_identity_from_tree(install_base_path, build_type)
    if identity is None:
        print(
            "⚠️ Rolled back to a tree with no archive metadata; the server "
            "still lists the version that was reverted."
        )
        return

    archive_id, archive_name, archive_version = identity
    _report_snapshot_from_install_metadata(
        install_base_path=install_base_path,
        archive_id=archive_id,
        archive_name=archive_name,
        archive_version=archive_version,
        platform_str=_ctx().platform,
        build_type=build_type,
        install_session_id=install_session_id,
    )


def _unusable_packages(install_base_path: Path, requested, build_type: str) -> list:
    """Requested packages that are not actually present in the live tree.

    This is the post-switch check. There is no process to probe — raisin_master
    installs software, it does not run it — so what it verifies is that the
    thing just made live is complete and readable.
    """
    broken = []
    for name in sorted(requested):
        package_dir = _ctx().package_dir(install_base_path, name, build_type)
        try:
            if not package_dir.is_dir() or not any(package_dir.iterdir()):
                broken.append(name)
        except OSError:
            broken.append(name)
    return broken


def _version_retention() -> int:
    """How many install trees to keep, including the live one."""
    raw = os.environ.get("RAISIN_INSTALL_KEEP_VERSIONS", "").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 2


def _utc_now_iso() -> str:
    """Client clock for `occurredAt`, at millisecond resolution.

    Whole seconds would let two events of one attempt tie, and the server
    orders a delayed batch by this field.
    """
    now = time.time()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
    return f"{stamp}.{int(now % 1 * 1000):03d}Z"


def _install_event_queue_path() -> Path:
    return _robot_state_path(_INSTALL_EVENT_QUEUE_FILE)


def _install_event_state_path() -> Path:
    return _robot_state_path(_INSTALL_EVENT_STATE_FILE)


def _read_install_event_queue() -> list:
    """Read the buffered events, skipping any line corruption."""
    try:
        raw = _install_event_queue_path().read_text(encoding="utf-8")
    except (OSError, ValueError):
        return []

    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _write_install_event_queue(events: list) -> None:
    path = _install_event_queue_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    except OSError as e:
        print(f"⚠️ Failed to write OTA install-event queue: {e}")


def _append_install_event(event: dict) -> None:
    path = _install_event_queue_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        print(f"⚠️ Failed to buffer OTA install event: {e}")


def _read_install_event_state() -> dict:
    try:
        data = json.loads(_install_event_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _install_event_marker_seen(session_id: str, marker: str) -> bool:
    return bool(_read_install_event_state().get(session_id, {}).get(marker))


def _mark_install_event(session_id: str, marker: str) -> None:
    """Persist the marker so a restarted process does not re-emit the event."""
    state = _read_install_event_state()
    state.setdefault(session_id, {})[marker] = True
    path = _install_event_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state), encoding="utf-8")
    except OSError:
        pass


def robot_reporting_enabled() -> bool:
    """Whether this machine has a robot identity to attribute reports to.

    `raisin_master` also runs on developer workstations, which have no robot
    credential. Buffering install events there would grow a file that can never
    be flushed, so nothing is recorded in the first place.
    """
    return _ctx().robot is not None


def note_install_failure(
    stage: str, error_code: Optional[str], message: Optional[str] = None
) -> None:
    """Remember why this attempt is going to fail, without ending it yet.

    The first cause wins: an attempt reports one terminal event, and the first
    failure is what explains the rest.
    """
    global _pending_install_failure
    if _pending_install_failure is None:
        _pending_install_failure = (stage, error_code or ERROR_UNKNOWN, message)


def pending_install_failure() -> Optional[tuple]:
    """(stage, error_code) of this attempt's first failure, if any."""
    if _pending_install_failure is None:
        return None
    return (_pending_install_failure[0], _pending_install_failure[1])


def clear_pending_install_failure() -> None:
    global _pending_install_failure
    _pending_install_failure = None


def install_attempt_started() -> bool:
    """Whether this session already reported a `started` event."""
    return _install_event_marker_seen(get_install_session_id(), "started")


def report_install_outcome(overall_success: bool) -> Optional[dict]:  # noqa: C901
    """Close the attempt with exactly one terminal event.

    Only the caller knows whether the run as a whole worked, and a noted
    failure outranks it: `install_command` returns True when *any* package
    landed, so a partial archive install would otherwise report success.
    """
    if not install_attempt_started():
        return None

    failure = _pending_install_failure
    if failure is not None:
        stage, error_code, message = failure
        return record_install_event(
            "failed", stage=stage, error_code=error_code, error_message=message
        )
    if overall_success:
        return record_install_event("succeeded")
    return record_install_event(
        "failed",
        error_code=ERROR_UNKNOWN,
        error_message="install did not complete",
    )


def record_install_event(
    event_type: str,
    stage: Optional[str] = None,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
    attempt: Optional[int] = None,
    archive_id: Optional[str] = None,
    archive_name: Optional[str] = None,
    archive_version: Optional[str] = None,
    platform: Optional[str] = None,
    detail: Optional[dict] = None,
    install_session_id: Optional[str] = None,
) -> Optional[dict]:
    """Buffer one install-attempt event.

    An attempt emits exactly one `started` and exactly one terminal event, so
    the guard is persisted rather than held in memory: a crashed run that
    resumes its session must not report a second `started`.

    Returns the event, or None when the guard suppressed it.
    """
    if not robot_reporting_enabled():
        return None

    session_id = install_session_id or get_install_session_id()
    marker = "terminal" if event_type in _TERMINAL_EVENT_TYPES else event_type
    if marker in ("started", "terminal") and _install_event_marker_seen(
        session_id, marker
    ):
        return None

    event = {
        "eventId": str(uuid.uuid4()),
        "installSessionId": session_id,
        "eventType": event_type,
        "occurredAt": _utc_now_iso(),
        "clientVersion": _client_version(),
    }
    for key, value in (
        ("stage", stage),
        ("errorCode", error_code),
        ("errorMessage", error_message),
        ("attempt", attempt),
        ("archiveId", archive_id),
        ("archiveName", archive_name),
        ("archiveVersion", archive_version),
        ("platform", platform),
        ("detail", detail),
    ):
        if value is not None:
            event[key] = value

    _append_install_event(event)
    if marker in ("started", "terminal"):
        _mark_install_event(session_id, marker)
    return event


@dataclass(frozen=True)
class RobotCallOutcome:
    """Why a robot-facing call did not do what was asked.

    Shared because the *decisions* are shared: anything looping over these has
    to back off when throttled, stop when its credential is refused, and
    simply try again when it could not reach the server. Copying the six
    fields into each result type is how two of them drift apart and a caller
    starts handling one case on one call and not the other.

    Subclasses add what the call actually produced.
    """

    status: Optional[int] = None
    throttled: bool = False
    retry_after: Optional[float] = None
    unauthorized: bool = False
    unreachable: bool = False
    detail: Optional[str] = None


@dataclass(frozen=True)
class FlushResult(RobotCallOutcome):
    """Whether the buffered events went.

    `drained` rather than `ok`: "the call succeeded" and "the queue is empty"
    are different facts, and a server that acknowledges half a batch has
    answered fine and left work behind.
    """

    drained: bool = False
    remaining: int = 0


def _retry_after_seconds(response) -> Optional[float]:
    """`Retry-After` as seconds, or None.

    Not defaulted: how long to wait when the server does not say is a policy
    decision, and inventing a number here would hide that it was never given.
    """
    raw = getattr(response, "headers", {}) or {}
    value = raw.get("Retry-After")
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def flush_install_events() -> FlushResult:
    """Send buffered install events, keeping anything the server did not ack.

    Never raises. `drained` is true only when the queue is empty afterwards,
    and the reason it is not travels on the result: a caller that flushes on a
    schedule has to know whether to back off, stop, or simply try again.
    """
    remaining = _read_install_event_queue()
    if not remaining:
        return FlushResult(drained=True)

    headers = _robot_auth_headers()
    if not headers:
        # A machine with no robot identity has nothing to report *as*. Not a
        # refusal by the server, and not something to back off from.
        return FlushResult(
            remaining=len(remaining), detail="no robot credential configured"
        )

    request_headers = dict(headers)
    request_headers["Content-Type"] = "application/json"
    base = get_ota_endpoint().rstrip("/")
    url = f"{base}/robots/me/install-events"

    failure = {}
    while remaining:
        batch = remaining[:_INSTALL_EVENT_BATCH_LIMIT]
        try:
            resp = requests.post(
                url, headers=request_headers, json={"events": batch}, timeout=15
            )
            if resp.status_code == 429:
                failure = {
                    "status": 429,
                    "throttled": True,
                    "retry_after": _retry_after_seconds(resp),
                    "detail": "throttled by the OTA server",
                }
                break
            if resp.status_code in (401, 403):
                failure = {
                    "status": resp.status_code,
                    "unauthorized": True,
                    "detail": "the OTA server refused this robot credential",
                }
                break
            resp.raise_for_status()
            data = _unwrap_response(resp.json()) or {}
        except (requests.ConnectionError, requests.Timeout) as e:
            failure = {"unreachable": True, "detail": str(e)}
            break
        except (requests.RequestException, ValueError) as e:
            print(f"⚠️ Failed to report OTA install events: {e}")
            failure = {"detail": str(e)}
            break

        acks = data.get("acks") if isinstance(data, dict) else None
        acked = {
            ack.get("eventId")
            for ack in (acks or [])
            if isinstance(ack, dict) and ack.get("eventId")
        }
        # The loop only terminates by draining the queue, so it has to be the
        # queue that is checked. A response can be non-empty and still acknowledge
        # nothing we sent — ids from another node, or from a batch already
        # dropped — and testing the response instead reposts the same batch
        # forever.
        before = len(remaining)
        remaining = [e for e in remaining if e.get("eventId") not in acked]
        if len(remaining) == before:
            print(
                "⚠️ OTA server acknowledged none of the install events in this "
                "batch; keeping the queue."
            )
            break

    dropped = len(remaining) - _MAX_BUFFERED_INSTALL_EVENTS
    if dropped > 0:
        # Keep the newest: they describe where the robot actually ended up.
        remaining = remaining[-_MAX_BUFFERED_INSTALL_EVENTS:]
        print(
            f"⚠️ OTA install-event buffer is full; discarded {dropped} of the "
            "oldest event(s)."
        )

    _write_install_event_queue(remaining)
    if remaining:
        print(f"ℹ️  {len(remaining)} OTA install event(s) buffered for a later run.")
    return FlushResult(drained=not remaining, remaining=len(remaining), **failure)


def clear_install_session() -> None:
    """Retire the session so the next install starts a fresh one."""
    global _install_session_id
    clear_pending_install_failure()
    retired = _install_session_id
    _install_session_id = None
    try:
        _install_session_path().unlink()
    except OSError:
        pass

    # Drop the once-per-session guards too, or the state file grows for the
    # life of the robot.
    if not retired:
        return
    state = _read_install_event_state()
    if state.pop(retired, None) is None:
        return
    try:
        _install_event_state_path().write_text(json.dumps(state), encoding="utf-8")
    except OSError:
        pass


def archive_is_pinned(
    archive_name: Optional[str] = None, archive_version: Optional[str] = None
) -> bool:
    """Whether this install targets one deliberately chosen archive.

    A pin is a decision someone made about this machine, so nothing may quietly
    substitute another archive, another tag, or GitHub releases for it. It can
    come from the command line, or per-node from `RAISIN_ARCHIVE_NAME` — an
    operator who exports that on a robot has pinned that robot.

    Both the core and `install_command` have to agree on what counts, which is
    why they ask here instead of each deciding for themselves.
    """
    return bool(
        archive_name or archive_version or os.environ.get("RAISIN_ARCHIVE_NAME")
    )


def get_archive_name(build_type: str, archive_name: Optional[str] = None) -> str:
    """Get archive name based on build type.

    Convention:
        - release → 'raisin-robot'
        - debug → 'raisin-robot-debug'
    """
    base = archive_name or os.environ.get("RAISIN_ARCHIVE_NAME", DEFAULT_ARCHIVE_NAME)
    if build_type.lower() == "debug":
        if archive_name and base.endswith("-debug"):
            return base
        return f"{base}-debug"
    return base


# ============================================================================
# Token Persistence
# ============================================================================


def _get_token_cache_path() -> Path:
    """Path to the persistent token cache file."""
    return _ctx().workspace / _TOKEN_CACHE_FILE


def _is_jwt_expired(token: str) -> bool:
    """Check if a JWT token is expired by decoding its payload.

    Decodes the JWT payload (no signature verification — just reading
    the ``exp`` claim) and returns True if the token expires within
    30 seconds.
    """
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.b64decode(padded))
        exp = payload.get("exp")
        if exp is None:
            return False
        return time.time() > (exp - 30)
    except Exception:
        return True


def _load_cached_token() -> Optional[str]:
    """Load token from persistent cache file if it's still valid.

    Uses the ``expiresAt`` timestamp saved alongside the token rather
    than re-parsing the JWT, so this works for opaque tokens too.
    """
    cache_path = _get_token_cache_path()
    try:
        if not cache_path.is_file():
            return None
        with open(cache_path, "r") as f:
            data = json.loads(f.read())
        token = data.get("accessToken")
        endpoint = data.get("endpoint")
        expires_at = data.get("expiresAt", 0)
        if endpoint != get_ota_endpoint():
            return None
        if not token:
            return None
        # 30-second buffer to avoid using a token that's about to expire
        if time.time() > (expires_at - 30):
            return None
        return token
    except Exception:
        return None


def _extract_jwt_expiry(token: str) -> float:
    """Try to read the ``exp`` claim from a JWT. Returns epoch seconds.

    Falls back to 1 hour from now if the token can't be parsed.
    """
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.b64decode(padded))
        exp = payload.get("exp")
        if exp is not None:
            return float(exp)
    except Exception:
        pass
    return time.time() + 3600


def _save_token(token: str):
    """Save token and its expiry to persistent cache file."""
    try:
        cache_path = _get_token_cache_path()
        data = {
            "accessToken": token,
            "endpoint": get_ota_endpoint(),
            "expiresAt": _extract_jwt_expiry(token),
        }
        with open(cache_path, "w") as f:
            f.write(json.dumps(data))
    except Exception:
        pass


def _clear_cached_token():
    """Clear both in-memory and persistent token caches, and reset failure flag."""
    global _cached_token, _auth_failed
    _cached_token = None
    _auth_failed = False
    try:
        cache_path = _get_token_cache_path()
        if cache_path.is_file():
            cache_path.unlink()
    except Exception:
        pass


# ============================================================================
# SSH Authentication
# ============================================================================


def _sign_nonce(nonce: str, key_path: Path) -> str:
    """Sign a nonce with an SSH private key.

    Imported lazily: signing is the only thing here that needs
    `cryptography`, and it belongs to the user-authenticated path. A robot
    authenticates with its own credential and never reaches this, so it
    should not have to install a native extension to run.
    """
    try:
        from . import ssh as ota_ssh
    except ImportError as e:  # pragma: no cover - depends on the install extra
        raise RuntimeError(
            "SSH authentication needs the 'cryptography' package. "
            "Install the ssh extra, or use a robot credential instead."
        ) from e

    return ota_ssh.sign_nonce(nonce, key_path)


def _get_ssh_fingerprint(key_path: Path) -> str:
    """Run ssh-keygen -lf <key.pub> and return hex-encoded SHA256 fingerprint.

    The OTA server expects the fingerprint as a hex string without the
    ``SHA256:`` prefix that ssh-keygen normally prints.
    """
    pub_key = key_path.with_suffix(".pub") if key_path.suffix != ".pub" else key_path
    result = subprocess.run(
        ["ssh-keygen", "-lf", str(pub_key)],
        capture_output=True,
        text=True,
        check=True,
    )
    # Output format: "256 SHA256:<base64> user@host (ED25519)"
    parts = result.stdout.strip().split()
    sha256_b64 = parts[1].split(":", 1)[1]  # strip "SHA256:" prefix
    # Convert base64 → raw bytes → hex
    padded = sha256_b64 + "=" * (-len(sha256_b64) % 4)
    return base64.b64decode(padded).hex()


def authenticate() -> Optional[str]:
    """Return a valid JWT access token, authenticating only if necessary.

    Token resolution order:
    1. In-memory cache (fastest, same CLI session)
    2. Persistent file cache (~/.ota_token_cache.json)
    3. SSH challenge-response against the OTA server

    Tokens are checked for JWT expiry before reuse.
    Returns access token string, or None on failure.
    """
    global _cached_token, _auth_failed

    # 1. In-memory cache (same CLI session — always trust it; if expired
    #    the server returns 401 and the retry handler clears the cache)
    if _cached_token:
        return _cached_token

    # Don't retry after a failure in the same session
    if _auth_failed:
        return None

    # 2. Persistent file cache
    file_token = _load_cached_token()
    if file_token:
        _cached_token = file_token
        return _cached_token

    # 3. SSH challenge-response
    endpoint = get_ota_endpoint()
    key_path = get_ssh_key_path()

    if not key_path.exists():
        print(f"⚠️ SSH key not found at {key_path}. Skipping OTA.")
        _auth_failed = True
        return None

    try:
        fingerprint = _get_ssh_fingerprint(key_path)
        base = endpoint.rstrip("/")

        # Step 1: Request challenge
        resp = requests.post(
            f"{base}/auth/ssh/challenge",
            json={"fingerprint": fingerprint},
            timeout=10,
        )
        resp.raise_for_status()
        nonce = _unwrap_response(resp.json())["nonce"]

        # Step 2: Sign nonce locally
        signature = _sign_nonce(nonce, key_path)

        # Step 3: Verify signature with server
        resp = requests.post(
            f"{base}/auth/ssh/verify",
            json={
                "fingerprint": fingerprint,
                "nonce": nonce,
                "signature": signature,
            },
            timeout=10,
        )
        resp.raise_for_status()
        _cached_token = _unwrap_response(resp.json())["accessToken"]
        _save_token(_cached_token)
        return _cached_token

    except FileNotFoundError:
        print("⚠️ ssh-keygen not found. Skipping OTA authentication.")
        _auth_failed = True
        return None
    except subprocess.CalledProcessError as e:
        print(f"⚠️ SSH key operation failed: {e.stderr.strip()}. Skipping OTA.")
        _auth_failed = True
        return None
    except requests.RequestException as e:
        print(f"⚠️ OTA server unreachable: {e}. Skipping OTA.")
        _auth_failed = True
        return None
    except (KeyError, ValueError) as e:
        print(f"⚠️ Unexpected OTA auth response: {e}. Skipping OTA.")
        _auth_failed = True
        return None


def _unwrap_response(resp_json):
    """Unwrap the OTA server's standard response envelope.

    The server wraps all JSON responses in ``{"success": bool, "data": ...}``.
    Returns the inner ``data`` payload, or the original value if not wrapped.
    """
    if isinstance(resp_json, dict) and "data" in resp_json:
        return resp_json["data"]
    return resp_json


def _auth_headers(token: str) -> dict:
    """Build Authorization header dict for authenticated requests."""
    return {"Authorization": f"Bearer {token}"}


def _get_auth_context() -> Optional[tuple]:
    """Get authenticated context for OTA API calls.

    Returns:
        Tuple of (base_url, headers) on success, None on auth failure.
        base_url is the endpoint with trailing slash stripped.
    """
    token = authenticate()
    if not token:
        return None
    base = get_ota_endpoint().rstrip("/")
    headers = _auth_headers(token)
    return (base, headers)


# ============================================================================
# Upload Functions (used by publish command)
# ============================================================================


def _compute_sha256(file_path: Path) -> str:
    """SHA256 hex digest of file, read in 8KB chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def upload_package(
    archive_path: Path,
    package_name: str,
    version: str,
    build_type: str,
    _retry: bool = True,
) -> bool:
    """Upload a package archive to the OTA server.

    Steps:
    1. Authenticate (SSH challenge-response)
    2. Compute SHA256 of archive for deduplication
    3. Check if blob already exists on server
    4. Upload blob if needed
    5. Ensure package record exists
    6. Create manifest entry
    7. Create version tag

    Returns True on success, False on failure. Never raises.
    """
    ctx = _get_auth_context()
    if not ctx:
        return False
    base, headers = ctx

    try:
        # 1. Compute SHA256
        sha256 = _compute_sha256(archive_path)
        platform_str = _ctx().platform

        # 2. Check if blob already exists (deduplication)
        resp = requests.get(
            f"{base}/blobs/{sha256}/exists", headers=headers, timeout=10
        )
        resp.raise_for_status()
        blob_exists = _unwrap_response(resp.json()).get("exists", False)

        # 3. Upload blob if needed.
        #
        # The endpoint streams the body straight to storage and hashes it on the
        # way through, so it takes the archive as the raw request body and reads
        # the expected digest from `x-content-sha256`. A multipart form carrying
        # the digest as a field is refused before anything is read, which is
        # what publish had been sending.
        if not blob_exists:
            blob_headers = dict(headers)
            blob_headers["x-content-sha256"] = sha256
            blob_headers["Content-Type"] = "application/zip"
            with open(archive_path, "rb") as f:
                resp = requests.post(
                    f"{base}/blobs",
                    headers=blob_headers,
                    data=f,
                    timeout=120,
                )
                resp.raise_for_status()

        # 4. Ensure package record exists
        found = _search_packages(base, headers, package_name)
        if found is None:
            # Creating the record now would risk a duplicate for a package that
            # may well exist — the lookup never got an answer either way.
            print(f"⚠️ OTA upload aborted: could not look up '{package_name}'")
            return False

        existing = next(
            (p for p in found if p.get("name") == package_name),
            None,
        )
        if existing:
            package_id = existing["id"]
        else:
            resp = requests.post(
                f"{base}/packages",
                headers=headers,
                json={"name": package_name},
                timeout=10,
            )
            resp.raise_for_status()
            package_id = _unwrap_response(resp.json())["id"]

        # 5. Create manifest
        resp = requests.post(
            f"{base}/packages/{package_id}/manifests",
            headers=headers,
            json={
                "version": version,
                "platform": platform_str,
                "buildType": build_type,
                "blobHash": sha256,
            },
            timeout=10,
        )
        resp.raise_for_status()

        # 6. Create version tag
        resp = requests.post(
            f"{base}/packages/{package_id}/tags",
            headers=headers,
            json={
                "tag": f"v{version.lstrip('vV')}",
                "version": version,
                "platform": platform_str,
                "buildType": build_type,
            },
            timeout=10,
        )
        resp.raise_for_status()

        return True

    except requests.HTTPError as e:
        if _retry and e.response is not None and e.response.status_code == 401:
            # Token may have expired — clear caches and retry auth once
            _clear_cached_token()
            token = authenticate()
            if token:
                print("🔄 Re-authenticated with OTA server, retrying upload...")
                return upload_package(
                    archive_path, package_name, version, build_type, _retry=False
                )
        print(f"⚠️ OTA upload failed: {e}")
        return False
    except requests.RequestException as e:
        print(f"⚠️ OTA upload failed: {e}")
        return False


# ============================================================================
# Download Functions (used by install command)
# ============================================================================


def _fetch_archive_manifest(
    archive_name: str,
    platform_str: str,
    archive_version: Optional[str] = None,
):
    """Fetch available archive manifest from OTA server.

    Args:
        archive_name: Name of the archive (e.g., 'raisin-robot', 'raisin-robot-debug')
        platform_str: Platform string (e.g., 'ubuntu-24.04-x86_64')
        archive_version: Optional specific version (e.g., 'v2024.01'). If None,
            fetches the latest available archive.

    Returns:
        Tuple of (packages_list, archive_id, archive_version) on success, None on failure.
        Uses a module-level cache to avoid repeated calls during a single install run.
    """
    cache_key = (archive_name, platform_str, archive_version)
    if cache_key in _archive_cache:
        return _archive_cache[cache_key]

    ctx = _get_auth_context()
    if not ctx:
        return None
    base, headers = ctx

    try:
        # Use the server's exact `version` filter when pinning an archive.
        # Do not send `search=<version>`: search is fuzzy and has historically
        # mixed sibling archive names into requests such as dso@1.0.3.
        params = {
            "name": archive_name,
            "platform": platform_str,
            "status": "available",
        }
        if archive_version:
            # Normalize the `v` prefix so callers can use either `1.0.3` or
            # `v1.0.3` without depending on how the server stores versions.
            params["version"] = archive_version.lstrip("vV")

        resp = requests.get(
            f"{base}/archives",
            headers=headers,
            params=params,
            timeout=10,
        )
        resp.raise_for_status()
        result_data = _unwrap_response(resp.json())
        # Response is paginated: {archives: [...], total, page, ...}
        archives = (
            result_data.get("archives", [])
            if isinstance(result_data, dict)
            else result_data
        )

        # Strict client-side filter: even though we sent `name=...` and
        # `platform=...`, the server has been observed to ignore both filters
        # when other params are present, returning archives with different
        # names AND different platforms (e.g. an x86_64 archive surfacing in
        # response to an arm64 query). Guard against that explicitly.
        archives = [
            a
            for a in archives
            if a.get("name") == archive_name and a.get("platform") == platform_str
        ]
        if not archives:
            return None

        archive = None
        if archive_version:
            v_stripped = archive_version.lstrip("vV")
            for a in archives:
                # Use `or ""` rather than `.get(key, "")` because the server
                # returns the key with a null value when version is unset,
                # and the dict default only applies when the key is missing.
                a_ver = a.get("version") or ""
                if a_ver == archive_version or a_ver.lstrip("vV") == v_stripped:
                    archive = a
                    break
            if not archive:
                # Version pinned but not present for this archive name. Do not
                # silently fall back to "most recent" — that's how `dso 1.0.3`
                # got resolved to a sibling archive in the past.
                return None
        else:
            archive = archives[0]

        result = (
            archive.get("packages", []),
            archive.get("id"),
            archive.get("version"),
        )
        _archive_cache[cache_key] = result
        return result

    except requests.RequestException as e:
        print(f"⚠️ OTA server unreachable: {e}")
        return None


def _fetch_archive_by_tag(
    archive_name: str,
    platform_str: str,
    tag: str,
    _retry: bool = True,
):
    """Fetch an archive resolved through a tag (e.g., 'stable').

    Two-step resolution:
      1. GET /archive-tags/by-name?archiveName=&tagName= to find the archive id
         for the requested platform.
      2. GET /archives/{archive_id} to get the package manifest list.

    Args:
        archive_name: Archive base name (e.g., 'raisin-robot').
        platform_str: Platform (e.g., 'ubuntu-24.04-arm64').
        tag: Tag name to resolve (e.g., 'stable').
        _retry: When True (default), a 401 response triggers a single
            re-auth + retry. Set to False internally on the retry to
            prevent infinite loops.

    Returns:
        Tuple of (packages_list, archive_id, archive_version) on success, None
        if the tag doesn't exist for that platform or the server is unreachable.
    """
    cache_key = ("__by_tag__", archive_name, platform_str, tag)
    if cache_key in _archive_cache:
        return _archive_cache[cache_key]

    ctx = _get_auth_context()
    if not ctx:
        return None
    base, headers = ctx

    try:
        resp = requests.get(
            f"{base}/archive-tags/by-name",
            headers=headers,
            params={"archiveName": archive_name, "tagName": tag},
            timeout=10,
        )
        resp.raise_for_status()
        tag_data = _unwrap_response(resp.json())
        if not isinstance(tag_data, dict):
            return None
        manifests = tag_data.get("manifests", []) or []
        manifest = next(
            (m for m in manifests if m.get("platform") == platform_str),
            None,
        )
        if not manifest:
            return None

        archive_id = manifest.get("archiveId")
        if not archive_id:
            return None

        resp2 = requests.get(
            f"{base}/archives/{archive_id}",
            headers=headers,
            timeout=10,
        )
        resp2.raise_for_status()
        archive = _unwrap_response(resp2.json())
        if not isinstance(archive, dict):
            return None

        result = (
            archive.get("packages", []),
            archive.get("id"),
            archive.get("version"),
        )
        _archive_cache[cache_key] = result
        return result

    except requests.HTTPError as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        if status == 404:
            return None
        if status == 401 and _retry:
            # Cached token likely expired — clear and retry once, matching
            # the pattern used by upload_package. Without this, an expired
            # token would surface as a misleading "tag not found" error.
            _clear_cached_token()
            if authenticate():
                print("🔄 Re-authenticated with OTA server, retrying tag lookup...")
                return _fetch_archive_by_tag(
                    archive_name, platform_str, tag, _retry=False
                )
        print(f"⚠️ OTA server error fetching tag '{tag}': {e}")
        return None
    except requests.RequestException as e:
        print(f"⚠️ OTA server unreachable: {e}")
        return None


_STABLE_FALLBACK_TAG = "stable"


def _fetch_archive_with_stable_fallback(
    archive_name: str,
    platform_str: str,
    tag: str,
):
    """Resolve ``tag`` against OTA, falling back to 'stable' before giving up.

    Resolution order:
      1. The requested ``tag`` (e.g. 'latest', 'beta', etc.).
      2. 'stable' — skipped if ``tag`` is already 'stable'.
      3. None  — callers should then fall back to GitHub releases.

    This keeps tagged installs resilient: a devel user whose 'latest' tag
    hasn't been promoted yet still lands on the OTA-blessed 'stable'
    archive rather than skipping straight to GitHub, while explicit
    `--tag X` requests still try X first.
    """
    manifest = _fetch_archive_by_tag(archive_name, platform_str, tag)
    if manifest is not None:
        return manifest

    if tag != _STABLE_FALLBACK_TAG:
        print(
            f"↪️  Tag '{tag}' not found on OTA — trying "
            f"'{_STABLE_FALLBACK_TAG}' as a fallback..."
        )
        manifest = _fetch_archive_by_tag(
            archive_name, platform_str, _STABLE_FALLBACK_TAG
        )
        if manifest is not None:
            print(
                f"  ✓ Using '{_STABLE_FALLBACK_TAG}' archive for "
                f"'{archive_name}' on {platform_str}."
            )
            return manifest

    return None


def _stream_download(url: str, download_path: Path, error_context: str = "") -> tuple:
    """Stream download a file from a URL, with resume, verification and retry.

    Args:
        url: Full URL to download from.
        download_path: Local path to save the file.
        error_context: Context string for error messages (e.g., package name).

    Returns:
        (ok, error_code); error_code is None on success and otherwise a member
        of the install-event error taxonomy.
    """
    ctx = _get_auth_context()
    if not ctx:
        return (False, ERROR_UNKNOWN)
    _, headers = ctx
    return _download_to_path(
        url, download_path, headers=headers, error_context=error_context
    )


def _robot_auth_headers(install_session_id: Optional[str] = None) -> Optional[dict]:
    """Build robot-authenticated headers, or return None when unconfigured."""
    robot = _ctx().robot
    if robot is None:
        return None

    session_id = install_session_id or get_install_session_id()
    return {
        "Authorization": f"Robot {robot.api_key}",
        "X-Client-Version": robot.client_version,
        "X-Install-Session-Id": session_id,
        "X-Robot-Node": robot.node_key,
    }


@dataclass(frozen=True)
class RobotCallResult(RobotCallOutcome):
    """What a robot-facing call produced, and why it did not.

    A CLI only ever needed "did I get a document" — every failure meant "no
    opinion, carry on". A resident agent has to act differently for each, so
    the reason travels with the result.

    The mechanism reports; deciding what to do is the caller's.
    """

    value: Optional[dict] = None

    @property
    def ok(self) -> bool:
        return self.value is not None

    def __bool__(self) -> bool:
        return self.ok


def fetch_robot_desired_state() -> RobotCallResult:
    """Ask the OTA server what this robot node is supposed to be running.

    Never raises — desired state is an optional refinement of the caller's own
    archive selection — but the reason for an empty answer is carried on the
    result rather than discarded.
    """
    headers = _robot_auth_headers()
    if not headers:
        return RobotCallResult(detail="no robot credential configured")

    base = get_ota_endpoint().rstrip("/")
    try:
        resp = requests.get(
            f"{base}/robots/me/desired-state", headers=headers, timeout=10
        )
        if resp.status_code == 404:
            # Either the node is not registered or the server predates the
            # endpoint. Both mean "no opinion", not "install nothing" — and
            # neither is a reason to stop asking.
            return RobotCallResult(status=404, detail="no desired state for this node")
        if resp.status_code == 429:
            return RobotCallResult(
                status=429,
                throttled=True,
                retry_after=_retry_after_seconds(resp),
                detail="throttled by the OTA server",
            )
        if resp.status_code in (401, 403):
            return RobotCallResult(
                status=resp.status_code,
                unauthorized=True,
                detail="the OTA server refused this robot credential",
            )
        resp.raise_for_status()
        state = _unwrap_response(resp.json())
        return RobotCallResult(
            value=state if isinstance(state, dict) else None, status=resp.status_code
        )
    except (requests.ConnectionError, requests.Timeout) as e:
        return RobotCallResult(unreachable=True, detail=str(e))
    except (requests.RequestException, ValueError) as e:
        print(f"⚠️ Failed to fetch OTA desired state: {e}")
        return RobotCallResult(detail=str(e))


def _resolve_desired_state(platform_str: str) -> tuple:
    """Fold the server's desired state into an archive selection.

    Returns (halted, archive_name, archive_version, manifest). Name and version
    are None whenever the server has no usable opinion, leaving the caller's own
    selection untouched.

    `manifest` is the same `(packages, archive_id, version)` tuple
    `_fetch_archive_manifest` produces, built from `target.packages`. That field
    is what lets a robot install with its API key alone: the per-package
    download endpoint needs a packageId, and every manifest route is closed to a
    robot credential. A server that does not send it yields None here, and the
    caller falls back to the JWT route.
    """
    result = fetch_robot_desired_state()
    if result.unauthorized:
        # Worth saying plainly: a revoked or mistyped credential otherwise
        # reads as "the server has no opinion", and the legacy-route warnings
        # that follow point at the wrong thing.
        print(f"⚠️ {result.detail}.")
    state = result.value
    if not state:
        return (False, None, None, None)

    if state.get("halt"):
        sources = ", ".join(state.get("haltSources") or []) or "an unknown scope"
        print(f"⛔ OTA installs are halted for this node by: {sources}.")
        return (True, None, None, None)

    target = state.get("target")
    if not isinstance(target, dict):
        reason = state.get("reason")
        if reason == "target_unresolved":
            detail = state.get("unresolvedDetail") or "no detail given"
            print(
                "⚠️ The OTA server has an archive assigned to this node but "
                f"could not resolve it: {detail}."
            )
        elif reason == "no_target":
            # Say this plainly: an unassigned node is in a normal state, but
            # the legacy-route warnings that follow read as a broken
            # credential rather than as "nobody told this robot what to run".
            print(
                "ℹ️  No archive is assigned to this robot node yet. "
                "Assign one on the OTA server to install as this robot; "
                "continuing on the legacy route, which authenticates as a user."
            )
        elif reason == "unconfigured":
            print(
                "ℹ️  This robot node is not configured on the OTA server yet. "
                "Register it before assigning an archive; continuing on the "
                "legacy route, which authenticates as a user."
            )
        else:
            # The server has more reasons than this client knows, and it gains
            # them faster than a fleet updates. A reason we cannot interpret is
            # still information — reporting it unrecognised is what keeps a new
            # server state from arriving as silence, which is how `unconfigured`
            # went unnoticed until a migration produced it.
            print(
                f"ℹ️  The OTA server reports no target for this node "
                f"(reason: {reason or 'none given'}), which this client does "
                f"not recognise. Continuing on the legacy route."
            )
        return (False, None, None, None)

    target_platform = _normalize_optional_string(target.get("platform"))
    if target_platform and target_platform != platform_str:
        print(
            f"⚠️ OTA desired state targets '{target_platform}' but this node "
            f"is '{platform_str}'. Ignoring it."
        )
        return (False, None, None, None)

    name = _normalize_optional_string(target.get("name"))
    version = _normalize_optional_string(target.get("version"))
    if not name or not version:
        return (False, None, None, None)

    print(
        f"🛰️  OTA desired state ({state.get('reason')}): "
        f"{name} v{version} on {target_platform or platform_str}"
    )

    manifest = None
    packages = target.get("packages")
    archive_id = _normalize_optional_string(target.get("archiveId"))
    if isinstance(packages, list) and packages and archive_id:
        manifest = (packages, archive_id, version)

    return (False, name, version, manifest)


class ContentHashMismatch(Exception):
    """Downloaded bytes did not match the digest the server advertised."""


class OtaInstallHalted(Exception):
    """The OTA server told this node to stop installing.

    Raised rather than returned so no caller can mistake it for "no archive
    available" and go looking somewhere else. A halt is an instruction; an
    empty result is an absence, and the two must not share a representation.
    """


# Error codes from the server's install-event contract
# (docs/ota-install-event-contract.md). The server treats these as data and
# never branches on them — classification is the client's job, because the
# client is the only party that knows what actually happened.
ERROR_NETWORK = "network"
ERROR_TIMEOUT = "timeout"
ERROR_HASH_MISMATCH = "hash_mismatch"
ERROR_DISK_FULL = "disk_full"
ERROR_SERVER_ERROR = "server_error"
ERROR_UNKNOWN = "unknown"

# Retrying only helps when the cause is transient. A 4xx, a full disk or an
# unclassified failure will answer the same way on the next attempt.
_RETRYABLE_ERROR_CODES = frozenset(
    {ERROR_NETWORK, ERROR_TIMEOUT, ERROR_SERVER_ERROR, ERROR_HASH_MISMATCH}
)


def classify_download_error(exc: BaseException) -> str:
    """Map a download failure onto the install-event error taxonomy."""
    if isinstance(exc, ContentHashMismatch):
        return ERROR_HASH_MISMATCH
    # ConnectTimeout subclasses both Timeout and ConnectionError, so timeout
    # must be tested first to keep the more specific answer.
    if isinstance(exc, requests.Timeout):
        return ERROR_TIMEOUT
    if isinstance(exc, requests.ConnectionError):
        return ERROR_NETWORK
    if isinstance(exc, requests.HTTPError):
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if isinstance(status, int) and 500 <= status < 600:
            return ERROR_SERVER_ERROR
        return ERROR_UNKNOWN
    if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
        return ERROR_DISK_FULL
    return ERROR_UNKNOWN


def is_retryable_error_code(error_code: str) -> bool:
    """Whether backoff should spend another attempt on this failure."""
    return error_code in _RETRYABLE_ERROR_CODES


# Retry/backoff tuning. A synchronised fleet reboots together, so jitter is
# what keeps the retry burst from arriving in lockstep.
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_MAX_SECONDS = 30.0
_MAX_DOWNLOAD_ATTEMPTS = 4

# Partial downloads live beside the target under this suffix, never at the
# final path — the installer must never see a half-written archive.
_PART_SUFFIX = ".part"

# A partial nobody came back for is not worth resuming: the archive may have
# moved on, and nothing else ever removes it.
_PART_MAX_AGE_SECONDS = 24 * 60 * 60

# Refuse a download that would leave no room to unpack what it just fetched.
_DISK_HEADROOM_BYTES = 16 * 1024 * 1024


def _part_state_path(part_path: Path) -> Path:
    return part_path.with_name(part_path.name + ".json")


def _write_part_state(part_path: Path, content_hash: Optional[str]) -> None:
    """Record the digest a partial file belongs to, so a later process can resume."""
    if not content_hash:
        return
    try:
        _part_state_path(part_path).write_text(
            json.dumps({"contentHash": content_hash}), encoding="utf-8"
        )
    except OSError:
        pass


def _read_part_state(part_path: Path) -> Optional[str]:
    try:
        data = json.loads(_part_state_path(part_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    value = data.get("contentHash")
    return value if isinstance(value, str) and value else None


def _discard_part(part_path: Path) -> None:
    for path in (part_path, _part_state_path(part_path)):
        try:
            if path.exists():
                path.unlink()
        except OSError:
            pass


def _digest_of_prefix(path: Path, length: int):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        remaining = length
        while remaining > 0:
            chunk = f.read(min(8192, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
    return digest


def _content_range_start(response_headers) -> Optional[int]:
    """First byte offset of a 206 slice, per `Content-Range: bytes <s>-<e>/<t>`."""
    raw = response_headers.get("Content-Range")
    if not isinstance(raw, str):
        return None
    match = re.match(r"\s*bytes\s+(\d+)-", raw)
    return int(match.group(1)) if match else None


def _announced_body_length(response_headers) -> Optional[int]:
    """Bytes the server says this response body carries, if it says."""
    try:
        return int(response_headers.get("Content-Length"))
    except (TypeError, ValueError):
        return None


def _assert_disk_space(part_path: Path, response_headers) -> None:
    """Fail before writing rather than filling the disk and dying mid-stream."""
    incoming = _announced_body_length(response_headers)
    if incoming is None:
        return

    try:
        free = shutil.disk_usage(part_path.parent).free
    except OSError:
        return

    if free < incoming + _DISK_HEADROOM_BYTES:
        raise OSError(
            errno.ENOSPC,
            f"needs {incoming + _DISK_HEADROOM_BYTES} bytes, {free} free",
        )


def _attempt_download(
    url: str,
    part_path: Path,
    download_path: Path,
    headers: Optional[dict],
    params: Optional[dict],
    timeout: int,
) -> None:
    """One download attempt. Raises on any failure; renames into place on success."""
    known_hash = _read_part_state(part_path)
    try:
        existing = part_path.stat().st_size
    except OSError:
        existing = 0

    # A partial with no recorded digest cannot be validated after resuming, so
    # it is cheaper to discard it than to risk splicing two different objects.
    if existing and not known_hash:
        _discard_part(part_path)
        existing = 0

    if existing:
        try:
            age = time.time() - part_path.stat().st_mtime
        except OSError:
            age = 0
        if age > _PART_MAX_AGE_SECONDS:
            _discard_part(part_path)
            existing = 0

    request_headers = dict(headers or {})
    if existing:
        request_headers["Range"] = f"bytes={existing}-"
        request_headers["If-Range"] = f'"{known_hash}"'

    part_path.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(
        url, headers=request_headers, params=params, stream=True, timeout=timeout
    ) as resp:
        # 416 answers a Range we should not have asked for: the partial is
        # already the whole object — a crash between the digest check and the
        # rename leaves exactly that — or longer than the server's copy. It is
        # our request that was wrong, not the server that is unwell, so it
        # classifies as `unknown` and is never retried. Start over now rather
        # than spending an attempt, or the package fails identically on every
        # run until the partial ages out.
        if resp.status_code == 416 and existing:
            _discard_part(part_path)
            # `existing` is 0 on the way back in, so no Range is sent and this
            # branch cannot be taken again.
            return _attempt_download(
                url, part_path, download_path, headers, params, timeout
            )
        resp.raise_for_status()

        # A 200 in response to a Range request means the object changed and the
        # server is sending the whole thing — the partial is now garbage.
        resume_from = existing
        if resume_from and resp.status_code != 206:
            _discard_part(part_path)
            resume_from = 0

        # A slice that does not begin where we asked would be appended at the
        # wrong offset; the hash check catches it only after the whole body has
        # been written, and blames the wrong thing.
        if resume_from:
            start = _content_range_start(resp.headers)
            if start is not None and start != resume_from:
                _discard_part(part_path)
                raise requests.ConnectionError(
                    f"server resumed at byte {start}, expected {resume_from}"
                )

        expected = _expected_content_hash(resp.headers)
        if not expected:
            print(
                f"⚠️ OTA server sent no content hash for "
                f"'{download_path.name}'; download integrity was not verified."
            )
        _assert_disk_space(part_path, resp.headers)
        _write_part_state(part_path, expected)

        digest = (
            _digest_of_prefix(part_path, resume_from)
            if resume_from
            else hashlib.sha256()
        )
        received = 0
        with open(part_path, "ab" if resume_from else "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                digest.update(chunk)
                received += len(chunk)
                f.write(chunk)

        # A connection cut cleanly between chunks raises nothing, so without
        # this a truncated body would be renamed into place whenever the server
        # sends no digest to check it against.
        announced = _announced_body_length(resp.headers)
        if announced is not None and received < announced:
            raise requests.ConnectionError(
                f"incomplete body: got {received} of {announced} bytes"
            )

    if expected and digest.hexdigest() != expected:
        _discard_part(part_path)
        raise ContentHashMismatch(f"expected {expected}, got {digest.hexdigest()}")

    part_path.replace(download_path)
    _discard_part(part_path)


def _download_to_path(
    url: str,
    download_path: Path,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    error_context: str = "",
    max_attempts: int = _MAX_DOWNLOAD_ATTEMPTS,
    timeout: int = 60,
) -> tuple:
    """Download to `download_path` with resume, verification and bounded retry.

    Returns `(ok, error_code)`; `error_code` is None on success and otherwise a
    member of the install-event taxonomy, ready to attach to a failed event.
    """
    part_path = download_path.with_name(download_path.name + _PART_SUFFIX)
    context = f" for '{error_context}'" if error_context else ""
    error_code = ERROR_UNKNOWN

    for attempt in range(max_attempts):
        try:
            _attempt_download(url, part_path, download_path, headers, params, timeout)
            return (True, None)
        except (requests.RequestException, OSError, ContentHashMismatch) as e:
            error_code = classify_download_error(e)
            print(f"⚠️ OTA download failed{context} [{error_code}]: {e}")

            if not is_retryable_error_code(error_code):
                break
            if attempt == max_attempts - 1:
                break

            window = min(_BACKOFF_BASE_SECONDS * (2**attempt), _BACKOFF_MAX_SECONDS)
            delay = random.uniform(window / 2, window)
            print(f"   retrying in {delay:.1f}s ({attempt + 2}/{max_attempts})")
            time.sleep(delay)

    return (False, error_code)


def _expected_content_hash(response_headers) -> Optional[str]:
    """Extract the sha256 the server claims for a download body.

    The by-key endpoints send the blob digest as `X-Content-Hash` and reuse it
    as the ETag, so fall back to the ETag when the explicit header is absent.
    """
    for header in ("X-Content-Hash", "ETag"):
        raw = response_headers.get(header)
        if not isinstance(raw, str):
            continue
        candidate = raw.strip().removeprefix("W/").strip('"')
        candidate = candidate.removeprefix("sha256:").lower()
        if re.fullmatch(r"[a-f0-9]{64}", candidate):
            return candidate
    return None


def _stream_robot_package_download(
    package_id: str,
    package_name: str,
    archive_name: str,
    archive_version: str,
    platform_str: str,
    download_path: Path,
    headers: dict,
) -> tuple:
    """Download a package through the robot-authenticated by-key endpoint."""
    base = get_ota_endpoint().rstrip("/")
    url = f"{base}/robots/me/archives/by-key/packages/{package_id}/download"
    params = {
        "name": archive_name,
        "platform": platform_str,
        "version": archive_version.lstrip("vV"),
    }
    return _download_to_path(
        url,
        download_path,
        headers=headers,
        params=params,
        error_context=package_name,
    )


def _download_package_blob(
    archive_id: str,
    package_id: str,
    package_name: str,
    download_path: Path,
    archive_name: Optional[str] = None,
    archive_version: Optional[str] = None,
    platform_str: Optional[str] = None,
    install_session_id: Optional[str] = None,
) -> tuple:
    """Download a single package blob from an archive.

    Returns (ok, error_code); error_code is None on success.
    """
    robot_headers = _robot_auth_headers(install_session_id)
    if robot_headers and archive_name and archive_version and platform_str:
        return _stream_robot_package_download(
            package_id=package_id,
            package_name=package_name,
            archive_name=archive_name,
            archive_version=archive_version,
            platform_str=platform_str,
            download_path=download_path,
            headers=robot_headers,
        )

    base = get_ota_endpoint().rstrip("/")
    url = f"{base}/archives/{archive_id}/packages/{package_id}/download"
    return _stream_download(url, download_path, package_name)


def _write_install_metadata(install_dir: Path, metadata: Optional[dict]) -> None:
    """Persist OTA install metadata next to the extracted package.

    This is written after extraction, so it does not affect the archive blob hash.
    """
    if not metadata:
        return

    metadata_path = install_dir / _INSTALL_METADATA_FILE
    try:
        metadata_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"📝 Recorded OTA metadata: {metadata_path}")
    except OSError as e:
        print(
            f"⚠️ Failed to write OTA metadata for '{install_dir.absolute().as_posix()}': {e}"
        )


def _extract_and_read_deps(
    download_file: Path,
    install_dir: Path,
    package_name: str,
    version: str,
    install_metadata: Optional[dict] = None,
) -> Optional[dict]:
    """Extract downloaded package and read dependencies.

    Returns dict with 'version' and 'dependencies' on success, None on failure.
    """
    if install_dir.exists():
        shutil.rmtree(install_dir)
    install_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(download_file, "r") as zip_ref:
            zip_ref.extractall(install_dir)
        download_file.unlink()
    except (zipfile.BadZipFile, OSError) as e:
        print(f"⚠️ Failed to extract OTA package '{package_name}': {e}")
        if download_file.exists():
            download_file.unlink()
        return None

    print(f"✅ Successfully installed '{package_name}=={version}' from OTA server.")
    _write_install_metadata(install_dir, install_metadata)

    # Read dependencies from release.yaml. The file ships inside the package,
    # so it is not necessarily well formed: `safe_load` happily returns a str
    # or a list, and `or {}` does not catch either — the install then died on
    # AttributeError instead of installing.
    dependencies = []
    release_yaml = install_dir / "release.yaml"
    if release_yaml.is_file():
        try:
            with open(release_yaml, "r") as f:
                release_info = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as e:
            print(f"⚠️ Could not read release.yaml for '{package_name}': {e}")
            release_info = None

        if isinstance(release_info, dict):
            declared = release_info.get("dependencies", [])
            if isinstance(declared, list):
                dependencies = declared
            elif declared:
                print(
                    f"⚠️ Ignoring malformed 'dependencies' in release.yaml for "
                    f"'{package_name}': expected a list."
                )
        elif release_info is not None:
            print(
                f"⚠️ Ignoring release.yaml for '{package_name}': expected a " "mapping."
            )

    result = {"version": version, "dependencies": dependencies}
    if install_metadata:
        result["otaMetadata"] = install_metadata
    return result


def _build_archive_install_metadata(
    package_name: str,
    package_id: str,
    package_tag: str,
    version: str,
    build_type: str,
    platform_str: str,
    archive_name: str,
    archive_id: str,
    actual_version: Optional[str],
    requested_archive_version: Optional[str],
    manifest_hash: Optional[str],
    blob_hash: Optional[str],
    install_session_id: Optional[str] = None,
) -> dict:
    """Build install metadata for archive-based OTA downloads."""
    return {
        "schemaVersion": 1,
        "source": "archive",
        "installedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "otaEndpoint": get_ota_endpoint(),
        "platform": platform_str,
        "buildType": build_type,
        "archiveName": archive_name,
        "archiveId": archive_id,
        "archiveVersion": actual_version,
        "requestedArchiveVersion": requested_archive_version,
        "installSessionId": install_session_id,
        "packageName": package_name,
        "packageId": package_id,
        "packageVersion": version,
        "packageTag": package_tag or f"v{version}",
        "manifestHash": manifest_hash,
        "blobHash": blob_hash,
    }


def manifest_hashes_by_package_id(packages: Optional[list]) -> dict:
    """Map packageId → manifestHash from an archive manifest package list."""
    hashes_by_id = {}
    for pkg in packages or []:
        if not isinstance(pkg, dict):
            continue
        pkg_id = str(pkg.get("packageId") or pkg.get("id") or "").strip()
        manifest_hash = str(pkg.get("manifestHash") or "").strip()
        if pkg_id and manifest_hash:
            hashes_by_id[pkg_id] = manifest_hash
    return hashes_by_id


def _snapshot_package_from_metadata(
    metadata: dict, manifest_hashes: Optional[dict] = None
) -> Optional[dict]:
    """Convert one ota-install.json document into a snapshot package item.

    `manifestHash` is required by the server for archive packages and must
    match the archive manifest exactly. Installs recorded before the field was
    written lack it, so recover it from the archive manifest rather than
    dropping the package: the server clears and replaces the node's whole
    package set on every snapshot, so an omission is recorded as "not
    installed" rather than "unknown".
    """
    package_id = str(metadata.get("packageId") or "").strip()
    package_name = str(metadata.get("packageName") or "").strip()
    version = str(metadata.get("packageVersion") or "").strip().lstrip("vV")
    manifest_hash = str(metadata.get("manifestHash") or "").strip()
    if not package_id or not package_name or not version:
        return None

    if not manifest_hash:
        manifest_hash = (manifest_hashes or {}).get(package_id, "")
        if manifest_hash:
            print(
                f"ℹ️  '{package_name}' has no recorded manifest hash; "
                "recovered it from the archive manifest for snapshot reporting."
            )

    if not manifest_hash:
        # Reporting it as a custom package is not an option: the server rejects
        # customPackages entries whose packageId is in the archive manifest.
        print(
            f"⚠️ Excluding '{package_name}=={version}' from the OTA software "
            "snapshot: no manifest hash on disk or in the archive manifest. "
            "The server will not show it as installed on this node."
        )
        return None

    return {
        "packageId": package_id,
        "packageName": package_name,
        "version": version,
        "manifestHash": manifest_hash,
    }


def _collect_archive_snapshot_packages(
    install_base_path: Path,
    archive_id: str,
    platform_str: str,
    build_type: str,
    manifest_hashes: Optional[dict] = None,
) -> list:
    """Collect currently installed package metadata for an archive."""
    metadata_pattern = f"*/*/*/*/{build_type}/{_INSTALL_METADATA_FILE}"
    packages_by_id = {}
    for metadata_path in sorted(install_base_path.glob(metadata_pattern)):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if not isinstance(metadata, dict):
                continue
        except (OSError, ValueError):
            continue

        if metadata.get("source") != "archive":
            continue
        if metadata.get("archiveId") != archive_id:
            continue
        if metadata.get("platform") != platform_str:
            continue
        if metadata.get("buildType") != build_type:
            continue

        package = _snapshot_package_from_metadata(metadata, manifest_hashes)
        if package:
            packages_by_id[package["packageId"]] = package

    return list(packages_by_id.values())


def report_software_snapshot(
    archive_id: str,
    archive_name: Optional[str],
    archive_version: Optional[str],
    platform_str: str,
    packages: list,
    install_session_id: Optional[str] = None,
) -> bool:
    """Report the robot's installed software snapshot to the OTA server."""
    if not packages:
        return False

    headers = _robot_auth_headers(install_session_id)
    if not headers:
        return False

    session_id = install_session_id or get_install_session_id()
    payload = {
        "archiveId": archive_id,
        "archivePackages": packages,
        "installSessionId": session_id,
        "clientVersion": _client_version(),
    }
    if archive_name:
        payload["name"] = archive_name
    if archive_version:
        payload["version"] = archive_version.lstrip("vV")
    if platform_str:
        payload["platform"] = platform_str

    request_headers = dict(headers)
    request_headers["Content-Type"] = "application/json"
    base = get_ota_endpoint().rstrip("/")
    try:
        resp = requests.post(
            f"{base}/robots/me/software-snapshot",
            headers=request_headers,
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        return True
    except requests.RequestException as e:
        print(f"⚠️ Failed to report OTA software snapshot: {e}")
        return False


def _queue_snapshot_report(
    install_base_path: Path,
    archive_id: str,
    archive_name: str,
    archive_version: Optional[str],
    platform_str: str,
    build_type: str,
    install_session_id: str,
    manifest_hashes: Optional[dict] = None,
) -> None:
    key = (archive_id, platform_str, build_type, install_session_id)
    pending = _pending_snapshot_reports.get(key)
    # Successive single-package installs each contribute the slice of the
    # archive manifest they resolved; keep the union so the deferred report can
    # still backfill hashes for packages installed earlier in this process.
    merged_hashes = dict(pending["manifest_hashes"]) if pending else {}
    merged_hashes.update(manifest_hashes or {})
    _pending_snapshot_reports[key] = {
        "install_base_path": install_base_path,
        "archive_id": archive_id,
        "archive_name": archive_name,
        "archive_version": archive_version,
        "platform_str": platform_str,
        "build_type": build_type,
        "install_session_id": install_session_id,
        "manifest_hashes": merged_hashes,
    }


def flush_pending_snapshot_reports() -> None:
    reports = list(_pending_snapshot_reports.values())
    _pending_snapshot_reports.clear()
    for report in reports:
        _report_snapshot_from_install_metadata(**report)


def _report_snapshot_from_install_metadata(
    install_base_path: Path,
    archive_id: str,
    archive_name: str,
    archive_version: Optional[str],
    platform_str: str,
    build_type: str,
    install_session_id: str,
    manifest_hashes: Optional[dict] = None,
) -> bool:
    packages = _collect_archive_snapshot_packages(
        install_base_path=install_base_path,
        archive_id=archive_id,
        platform_str=platform_str,
        build_type=build_type,
        manifest_hashes=manifest_hashes,
    )
    if not packages:
        return False

    if report_software_snapshot(
        archive_id=archive_id,
        archive_name=archive_name,
        archive_version=archive_version,
        platform_str=platform_str,
        packages=packages,
        install_session_id=install_session_id,
    ):
        print(
            "🛰️  Reported OTA software snapshot "
            f"({len(packages)} packages, session {install_session_id})."
        )
        return True
    return False


def download_package(
    package_name: str,
    spec_str: str,
    build_type: str,
    install_base_path: Path,
    archive_version: Optional[str] = None,
    archive_name: Optional[str] = None,
    tag: Optional[str] = "stable",
) -> Optional[dict]:
    """Download a single package from the OTA server's archive.

    Looks up the package in the archive manifest for the current platform,
    checks version compatibility, downloads and extracts to install_base_path.

    Args:
        package_name: Name of the package to download.
        spec_str: Version specifier string (e.g. ">=1.0", "==1.1.0", "" for any).
        build_type: "debug" or "release".
        install_base_path: Path to release/install/ directory.
        archive_version: Optional specific archive version (e.g., 'v2024.01').
            When set, takes precedence over `tag`.
        archive_name: Optional archive base name override. If set, this takes
            precedence over RAISIN_ARCHIVE_NAME.
        tag: Tag name to resolve (default 'stable'). When set and
            `archive_version` is None, the archive is fetched via the tag.
            Pass None to fall back to legacy latest-by-time selection.

    Returns:
        dict with 'version' and 'dependencies' on success, None on failure.
    """
    from packaging.version import parse as parse_version, InvalidVersion

    platform_str = _ctx().platform
    archive_name = get_archive_name(build_type, archive_name)

    # Selection priority mirrors download_all_from_archive:
    # archive_version > tag > legacy latest-by-time.
    if archive_version:
        manifest = _fetch_archive_manifest(archive_name, platform_str, archive_version)
    elif tag:
        manifest = _fetch_archive_with_stable_fallback(archive_name, platform_str, tag)
        if manifest is None:
            # Neither the requested tag nor 'stable' resolved on OTA.
            # Return None so install.py falls back to GitHub releases.
            print(
                f"⚠️ No OTA archive found for '{archive_name}' on {platform_str} "
                f"with tag '{tag}' or 'stable' — falling back to GitHub releases."
            )
            return None
    else:
        manifest = _fetch_archive_manifest(archive_name, platform_str, None)

    if manifest is None:
        return None

    packages, archive_id, actual_version = manifest
    if not archive_id:
        return None

    # Parse version specifier
    spec = parse_version_specifier(spec_str)
    if spec is None:
        return None

    # Find best matching package in archive
    # Manifest entries have tagName (e.g. "v1.0.0") instead of version
    best_pkg = None
    best_version = None
    for pkg in packages:
        name = pkg.get("packageName") or pkg.get("name", "")
        if name != package_name:
            continue
        tag = pkg.get("tagName") or pkg.get("version", "")
        pkg_version_str = tag.lstrip("vV") if tag else ""
        try:
            pkg_version = parse_version(pkg_version_str)
            if spec.contains(pkg_version):
                if best_version is None or pkg_version > best_version:
                    best_version = pkg_version
                    best_pkg = pkg
        except InvalidVersion:
            continue

    if not best_pkg:
        return None

    # Download the package
    pkg_id = best_pkg.get("packageId") or best_pkg.get("id")
    if not pkg_id:
        return None
    tag = best_pkg.get("tagName") or best_pkg.get("version", "")
    version = tag.lstrip("vV") if tag else "0.0.0"

    install_dir = _ctx().package_dir(install_base_path, package_name, build_type)

    download_file = _ctx().workspace / "install" / f"{package_name}-ota-{version}.zip"

    install_session_id = get_install_session_id()

    # Keep the live symlink healthy, but note the limitation: this path writes
    # into the tree that is already live, so a single-package install has no
    # atomic switch and no rollback. install.py calls it once per package, so
    # staging here would mint a version per package. Bringing it under the same
    # transaction as download_all_from_archive is follow-up work.
    install_tree.ensure_tree(install_tree.release_for(install_base_path))

    record_install_event(
        "started",
        archive_id=archive_id,
        archive_name=archive_name,
        archive_version=actual_version,
        platform=platform_str,
        install_session_id=install_session_id,
    )

    print(f"⬇️  Downloading '{package_name}' v{version} from OTA server...")
    download_ok, _download_error = _download_package_blob(
        archive_id,
        pkg_id,
        package_name,
        download_file,
        archive_name=archive_name,
        archive_version=actual_version,
        platform_str=platform_str,
        install_session_id=install_session_id,
    )
    if not download_ok:
        note_install_failure(
            "download", _download_error, f"download of '{package_name}' failed"
        )
        return None

    install_metadata = _build_archive_install_metadata(
        package_name=package_name,
        package_id=pkg_id,
        package_tag=tag,
        version=version,
        build_type=build_type,
        platform_str=platform_str,
        archive_name=archive_name,
        archive_id=archive_id,
        actual_version=actual_version,
        requested_archive_version=archive_version,
        manifest_hash=best_pkg.get("manifestHash"),
        blob_hash=best_pkg.get("blobHash"),
        install_session_id=install_session_id,
    )

    result = _extract_and_read_deps(
        download_file,
        install_dir,
        package_name,
        version,
        install_metadata=install_metadata,
    )
    if not result:
        note_install_failure(
            "unpack", "unpack_failed", f"could not unpack '{package_name}'"
        )
    if result:
        _queue_snapshot_report(
            install_base_path=install_base_path,
            archive_id=archive_id,
            archive_name=archive_name,
            archive_version=actual_version,
            platform_str=platform_str,
            build_type=build_type,
            install_session_id=install_session_id,
            manifest_hashes=manifest_hashes_by_package_id(packages),
        )
    return result


def download_all_from_archive(
    build_type: str,
    install_base_path: Path,
    archive_version: Optional[str] = None,
    package_filter: Optional[list] = None,
    archive_name: Optional[str] = None,
    tag: Optional[str] = "stable",
) -> dict:
    """Download all packages from an archive.

    Args:
        build_type: "debug" or "release".
        install_base_path: Path to release/install/ directory.
        archive_version: Optional specific archive version (e.g., 'v2024.01').
            When set, takes precedence over `tag`.
        package_filter: Optional list of package names to download. If None,
            downloads all packages in the archive.
        archive_name: Optional archive base name override. If set, this takes
            precedence over RAISIN_ARCHIVE_NAME.
        tag: Tag name to resolve (default 'stable'). When set and
            `archive_version` is None, the archive is fetched via the tag
            and a missing tag aborts the install with a SystemExit.
            Pass None to fall back to legacy latest-by-time selection.

    Returns:
        dict mapping package_name to {'version': str, 'dependencies': list}
        for successfully downloaded packages. Empty dict on complete failure.
    """
    platform_str = _ctx().platform

    release = install_tree.release_for(install_base_path)
    repaired = install_tree.ensure_tree(release)
    if repaired:
        print(f"🔧 {repaired}")

    # An explicit name or version from the caller is a deliberate pin and
    # outranks whatever the fleet has assigned. Only ask the server what to run
    # when the caller expressed no preference.
    caller_pinned_archive = archive_is_pinned(archive_name, archive_version)
    archive_name = get_archive_name(build_type, archive_name)

    desired_manifest = None
    if not caller_pinned_archive:
        halted, desired_name, desired_version, desired_manifest = (
            _resolve_desired_state(platform_str)
        )
        if halted:
            raise OtaInstallHalted("the OTA server has halted installs for this node")
        if desired_name and desired_version:
            archive_name, archive_version = desired_name, desired_version

    # Selection priority: desired state > archive_version > tag > legacy latest.
    # The desired-state manifest comes first because it is the only route a
    # robot credential can read; everything below it needs a user token.
    if desired_manifest:
        manifest = desired_manifest
    elif archive_version:
        manifest = _fetch_archive_manifest(archive_name, platform_str, archive_version)
    elif tag:
        manifest = _fetch_archive_with_stable_fallback(archive_name, platform_str, tag)
        if manifest is None:
            # Neither the requested tag nor 'stable' resolved on OTA.
            # Return empty so install.py falls back to GitHub releases
            # for each repo declared in configuration_setting.yaml.
            print(
                f"⚠️ No OTA archive found for '{archive_name}' on {platform_str} "
                f"with tag '{tag}' or 'stable' — falling back to GitHub "
                f"releases for each package."
            )
            return {}
    else:
        manifest = _fetch_archive_manifest(archive_name, platform_str, None)

    if manifest is None:
        print(f"⚠️ No archive found for '{archive_name}' on {platform_str}")
        return {}

    packages, archive_id, actual_version = manifest
    if not archive_id:
        return {}

    # The version names the directory this install commits into, and the
    # generation pattern needs a non-empty one. `None` produces a directory
    # called `0002-None` that `commit_version` can never resolve; an empty
    # string produces `0002-`, which the pattern cannot see at all, so the next
    # run stages into the same name. Neither can be committed or rolled back to.
    if not actual_version:
        print(
            f"⚠️ Archive '{archive_name}' came back without a version; "
            f"refusing to install an archive that cannot be named."
        )
        return {}

    print(f"📦 Using archive: {archive_name} v{actual_version}")
    install_session_id = get_install_session_id()
    event_context = {
        "archive_id": archive_id,
        "archive_name": archive_name,
        "archive_version": actual_version,
        "platform": platform_str,
        "install_session_id": install_session_id,
    }
    record_install_event("started", **event_context)

    # Everything below lands in a staging tree cloned from the live one.
    # Nothing the robot runs changes until commit_version() moves the symlink.
    staging = install_tree.stage_version(release, actual_version)
    requested = (
        set(package_filter)
        if package_filter
        else {(pkg.get("packageName") or pkg.get("name", "")) for pkg in packages}
        - {""}
    )

    results = {}
    for pkg in packages:
        name = pkg.get("packageName") or pkg.get("name", "")
        if not name:
            continue
        if package_filter and name not in package_filter:
            continue

        pkg_id = pkg.get("packageId") or pkg.get("id")
        if not pkg_id:
            continue

        tag = pkg.get("tagName") or pkg.get("version", "")
        version = tag.lstrip("vV") if tag else "0.0.0"

        # _extract_and_read_deps removes this directory before unpacking, which
        # is what breaks the hardlink shared with the previous version.
        install_dir = _ctx().package_dir(staging, name, build_type)

        download_file = _ctx().workspace / "install" / f"{name}-ota-{version}.zip"

        print(f"⬇️  Downloading '{name}' v{version} from OTA server...")
        download_ok, _download_error = _download_package_blob(
            archive_id,
            pkg_id,
            name,
            download_file,
            archive_name=archive_name,
            archive_version=actual_version,
            platform_str=platform_str,
            install_session_id=install_session_id,
        )
        if not download_ok:
            note_install_failure(
                "download", _download_error, f"download of '{name}' failed"
            )
            continue

        install_metadata = _build_archive_install_metadata(
            package_name=name,
            package_id=pkg_id,
            package_tag=tag,
            version=version,
            build_type=build_type,
            platform_str=platform_str,
            archive_name=archive_name,
            archive_id=archive_id,
            actual_version=actual_version,
            requested_archive_version=archive_version,
            manifest_hash=pkg.get("manifestHash"),
            blob_hash=pkg.get("blobHash"),
            install_session_id=install_session_id,
        )

        result = _extract_and_read_deps(
            download_file,
            install_dir,
            name,
            version,
            install_metadata=install_metadata,
        )
        if result:
            results[name] = result
        else:
            note_install_failure(
                "unpack", "unpack_failed", f"could not unpack '{name}'"
            )

    missing = sorted(requested - set(results))
    if missing:
        # A partial archive is not an installed archive: leave the previous
        # version live and report why, rather than committing something the
        # robot was never asked to run.
        print(
            f"⚠️ Not committing '{archive_name}' v{actual_version}: "
            f"{len(missing)} package(s) missing ({', '.join(missing[:3])}"
            f"{'…' if len(missing) > 3 else ''})."
        )
        install_tree.discard_staging(release, actual_version)
        note_install_failure(
            *(pending_install_failure() or ("unpack", "unpack_failed")),
            f"incomplete archive install: missing {', '.join(missing)}",
        )
        return {}

    # Moving the symlink is what makes an install real. If it did not move,
    # nothing was installed — and the health check below would read the tree
    # that is still live and pass, so silence here reports the previous
    # version's packages as a successful install of this one.
    committed = install_tree.commit_version(
        release, actual_version, session=install_session_id
    )
    if committed is None:
        print(
            f"⚠️ Could not switch release/install to '{archive_name}' "
            f"v{actual_version}; the previous version keeps running."
        )
        install_tree.discard_staging(release, actual_version)
        note_install_failure(
            "unpack",
            ERROR_UNKNOWN,
            f"commit failed for {archive_name} v{actual_version}",
        )
        return {}

    print(f"🔀 Switched release/install to {archive_name} v{actual_version}.")

    broken = _unusable_packages(install_base_path, requested, build_type)
    if broken:
        restored = install_tree.rollback(release)
        note_install_failure(
            "health_check",
            "health_check_failed",
            f"unusable after switch: {', '.join(broken)}",
        )
        if restored:
            print(
                f"↩️  Rolled back to v{restored}: {len(broken)} package(s) "
                "unusable after the switch."
            )
            record_install_event(
                "rolled_back",
                stage="health_check",
                error_code="health_check_failed",
                error_message=f"unusable after switch: {', '.join(broken)}",
                **event_context,
            )
            _report_restored_snapshot(install_base_path, build_type, install_session_id)
        else:
            # Nothing to restore, so this is not a rollback — the contract
            # reserves `rolled_back` for an attempt that came back.
            print(
                f"⚠️ {len(broken)} package(s) unusable after the switch and no "
                "previous version to restore."
            )
            record_install_event(
                "failed",
                stage="health_check",
                error_code="health_check_failed",
                error_message=f"unusable after switch: {', '.join(broken)}",
                **event_context,
            )
        return {}

    _report_snapshot_from_install_metadata(
        install_base_path=install_base_path,
        archive_id=archive_id,
        archive_name=archive_name,
        archive_version=actual_version,
        platform_str=platform_str,
        build_type=build_type,
        install_session_id=install_session_id,
        manifest_hashes=manifest_hashes_by_package_id(packages),
    )
    install_tree.prune_versions(release, keep=_version_retention())

    return results


# `GET /packages` caps `limit` at 100 and rejects anything larger outright.
_PACKAGE_PAGE_SIZE = 100


def _rejection_detail(response) -> str:
    """The server's own words for why it refused the request."""
    try:
        body = response.json()
    except ValueError:
        return (getattr(response, "text", "") or "").strip()[:200]

    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):
        return str(body)[:200]

    reasons = [
        item["message"]
        for item in error.get("validationErrors") or []
        if isinstance(item, dict) and item.get("message")
    ]
    return "; ".join(reasons) or str(error.get("message", ""))[:200]


def _get_packages_page(base, headers, params: dict, purpose: str) -> Optional[dict]:
    """One page of ``GET /packages``, or None if the request did not succeed.

    A refusal is announced rather than folded into an empty result. This
    endpoint validates its query strictly — an unexpected parameter is a 400,
    not an empty page — and reporting that as "no such package" sends whoever
    is reading the output to look on the wrong side of the wire.
    """
    try:
        resp = requests.get(
            f"{base}/packages", headers=headers, params=params, timeout=10
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
        if status is not None and 400 <= status < 500:
            print(f"⚠️ OTA server rejected {purpose} ({status}):")
            detail = _rejection_detail(response)
            if detail:
                print(f"   {detail}")
        else:
            print(f"⚠️ OTA server unreachable for {purpose}: {exc}")
        return None

    result = _unwrap_response(resp.json())
    if isinstance(result, list):  # an older server that returned a bare array
        return {"packages": result, "totalPages": 1}
    if not isinstance(result, dict):
        return {"packages": [], "totalPages": 1}

    packages = result.get("packages")
    return {
        "packages": packages if isinstance(packages, list) else [],
        "totalPages": result.get("totalPages") or 1,
    }


def _paginate_packages(
    base, headers, search: Optional[str], page_size: int, purpose: str
) -> Optional[list]:
    """Every matching package, or None if any page was refused.

    Returning what arrived before a refusal would present a truncated list as
    the complete one, which is the same failure this is here to remove.
    """
    collected = []
    page = 1
    while True:
        params = {"page": page, "limit": min(page_size, _PACKAGE_PAGE_SIZE)}
        if search is not None:
            params["search"] = search

        result = _get_packages_page(base, headers, params, purpose)
        if result is None:
            return None

        collected.extend(result["packages"])
        if page >= result["totalPages"] or not result["packages"]:
            return collected
        page += 1


def _search_packages(
    base, headers, search: str, page_size: int = _PACKAGE_PAGE_SIZE
) -> Optional[list]:
    return _paginate_packages(
        base, headers, search, page_size, f"the lookup for '{search}'"
    )


def _list_all_packages(page_size: int = _PACKAGE_PAGE_SIZE) -> Optional[list]:
    """Every package on the server, or None if it could not be listed."""
    ctx = _get_auth_context()
    if not ctx:
        return None
    base, headers = ctx
    return _paginate_packages(base, headers, None, page_size, "the package list")


def _fetch_package_id_by_name(
    package_name: str, page_size: int = _PACKAGE_PAGE_SIZE
) -> Optional[str]:
    """Package UUID for an exact name, or None if there is no such package.

    ``GET /packages`` offers no exact-name lookup: ``search`` is a substring
    match over name *and* description, so searching ``raisin`` also returns
    ``raisin_gui``, ``raisin_plugin`` and anything merely mentioning it. Taking
    the first hit would install a different package than the one asked for, so
    the name has to match exactly.
    """
    ctx = _get_auth_context()
    if not ctx:
        return None
    base, headers = ctx

    found = _search_packages(base, headers, package_name, page_size)
    if found is None:
        return None  # refused, and _get_packages_page has already said why

    package_id = next(
        (p.get("id") for p in found if p.get("name") == package_name),
        None,
    )
    if package_id is None:
        # Only claimed once the server actually answered. Saying "not found"
        # for a request the server refused points at the wrong problem.
        print(f"⚠️ Package '{package_name}' not found on OTA server.")
    return package_id


def _download_blob_by_hash(blob_hash: str, download_path: Path) -> bool:
    """Download a blob directly by its hash."""
    base = get_ota_endpoint().rstrip("/")
    url = f"{base}/blobs/{blob_hash}/download"
    ok, _error_code = _stream_download(url, download_path, f"blob {blob_hash[:8]}")
    return ok


def download_package_at_timestamp(
    package_name: str,
    timestamp: str,
    build_type: str,
    install_base_path: Path,
) -> Optional[dict]:
    """Download a package at a specific timestamp (time-travel).

    Uses the /packages/:id/manifests/at API to find the manifest that was
    current at the given timestamp, then downloads the blob directly.

    Args:
        package_name: Name of the package to download.
        timestamp: ISO 8601 timestamp (e.g., '2024-01-15' or '2024-01-15T10:00:00Z').
        build_type: "debug" or "release".
        install_base_path: Path to release/install/ directory.

    Returns:
        dict with 'version' and 'dependencies' on success, None on failure.
    """
    # Get package ID first (this handles its own auth)
    package_id = _fetch_package_id_by_name(package_name)
    if not package_id:
        return None

    ctx = _get_auth_context()
    if not ctx:
        return None
    base, headers = ctx
    platform_str = _ctx().platform

    try:
        # Fetch manifest at timestamp
        resp = requests.get(
            f"{base}/packages/{package_id}/manifests/at",
            headers=headers,
            params={
                "timestamp": timestamp,
                "platform": platform_str,
                "buildType": build_type,
            },
            timeout=10,
        )
        resp.raise_for_status()
        manifest = _unwrap_response(resp.json())

        if not manifest:
            print(f"⚠️ No manifest found for '{package_name}' at {timestamp}")
            return None

        blob_hash = manifest.get("blobHash")
        raw_version = manifest.get("version", "0.0.0")
        version = raw_version.lstrip("vV") if raw_version else "0.0.0"

        if not blob_hash:
            print(f"⚠️ Manifest for '{package_name}' has no blob hash")
            return None

        install_dir = _ctx().package_dir(install_base_path, package_name, build_type)

        download_file = (
            _ctx().workspace / "install" / f"{package_name}-ota-{version}.zip"
        )

        print(f"⬇️  Downloading '{package_name}' v{version} (at {timestamp})...")
        if not _download_blob_by_hash(blob_hash, download_file):
            return None

        install_metadata = {
            "schemaVersion": 1,
            "source": "timestamp",
            "installedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "otaEndpoint": get_ota_endpoint(),
            "platform": platform_str,
            "buildType": build_type,
            "requestedTimestamp": timestamp,
            "packageName": package_name,
            "packageId": package_id,
            "packageVersion": version,
            "packageTag": f"v{version}",
            "manifestHash": manifest.get("manifestHash"),
            "blobHash": blob_hash,
            "manifestId": manifest.get("id"),
            "manifestCreatedAt": manifest.get("createdAt"),
        }

        return _extract_and_read_deps(
            download_file,
            install_dir,
            package_name,
            version,
            install_metadata=install_metadata,
        )

    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            print(f"⚠️ No manifest found for '{package_name}' at {timestamp}")
        else:
            print(f"⚠️ OTA error: {e}")
        return None
    except requests.RequestException as e:
        print(f"⚠️ OTA server unreachable: {e}")
        return None


def download_all_at_timestamp(
    timestamp: str,
    build_type: str,
    install_base_path: Path,
    package_filter: Optional[list] = None,
) -> dict:
    """Download all packages at a specific timestamp.

    Fetches the list of all packages, then downloads each one's manifest
    at the given timestamp.

    Args:
        timestamp: ISO 8601 timestamp (e.g., '2024-01-15').
        build_type: "debug" or "release".
        install_base_path: Path to release/install/ directory.
        package_filter: Optional list of package names to download.

    Returns:
        dict mapping package_name to {'version': str, 'dependencies': list}
        for successfully downloaded packages.
    """
    ctx = _get_auth_context()
    if not ctx:
        return {}
    base, headers = ctx

    try:
        packages = _list_all_packages()
        if packages is None:
            return {}

        if not packages:
            print("⚠️ No packages found on OTA server.")
            return {}

        print(f"📦 Downloading packages at timestamp: {timestamp}")

        results = {}
        for pkg in packages:
            name = pkg.get("name", "")
            if not name:
                continue
            if package_filter and name not in package_filter:
                continue

            result = download_package_at_timestamp(
                name, timestamp, build_type, install_base_path
            )
            if result:
                results[name] = result

        return results

    except requests.RequestException as e:
        print(f"⚠️ OTA server unreachable: {e}")
        return {}
