"""Resolve this machine's robot credential for the OTA core.

Where a credential lives is a property of the machine, not of the OTA
protocol: a developer has a shell and a HOME, a robot has a service account
and a provisioned key file. The core takes an identity and asks no questions,
so this module answers them and hands the result to `ota_client.configure`.
"""

import json
import os
import stat
from pathlib import Path
from typing import Optional

import yaml

from commands import globals as g
from raisin_ota import RobotIdentity

# Robot API key configuration. The key file is intentionally outside the repo.
_ROBOT_API_KEY_FILE = "robot-api-key"  # pragma: allowlist secret
_ROBOT_API_KEY_ENV = "RAISIN_ROBOT_API_KEY"  # pragma: allowlist secret
_ROBOT_API_KEY_FILE_ENV = "RAISIN_ROBOT_API_KEY_FILE"  # pragma: allowlist secret
_ROBOT_NODE_ENV = "RAISIN_ROBOT_NODE"
_ROBOT_NODE_KEY_ENV = "RAISIN_ROBOT_NODE_KEY"
_ROBOT_CONFIG_FILES = ("configuration_setting.yaml", "secrets.yaml")

DEFAULT_CLIENT_VERSION = "raisin-cli"

_robot_api_key_cache = {}
_local_config_cache = {}
_robot_auth_warning_keys = set()


def _load_local_config() -> dict:
    """Best-effort read of local configuration without enforcing full config validity.

    Cached on file stat metadata: robot auth headers are rebuilt for every
    package download, and each rebuild resolves both the API key and the node
    key, so an uncached read re-parses the YAML twice per package.
    """
    script_dir_path = Path(g.script_directory)
    for filename in _ROBOT_CONFIG_FILES:
        config_path = script_dir_path / filename
        try:
            stat_result = config_path.stat()
        except OSError:
            continue
        if not stat.S_ISREG(stat_result.st_mode):
            continue

        cache_token = (stat_result.st_mtime_ns, stat_result.st_size)
        cached = _local_config_cache.get(config_path)
        if cached and cached[0] == cache_token:
            return cached[1]

        try:
            config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            return {}
        config = config if isinstance(config, dict) else {}
        _local_config_cache[config_path] = (cache_token, config)
        return config
    return {}


def _get_nested_config_value(config: dict, path: tuple) -> Optional[str]:
    current = config
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return _normalize_optional_string(current)


def _get_local_config_value(paths: tuple) -> Optional[str]:
    config = _load_local_config()
    for path in paths:
        value = _get_nested_config_value(config, path)
        if value:
            return value
    return None


def get_robot_api_key_path() -> Path:
    """Get the local robot API key path.

    Resolution order:
        1. RAISIN_ROBOT_API_KEY_FILE environment variable
        2. ~/.config/raisin/robot-api-key
    """
    env_path = os.environ.get(_ROBOT_API_KEY_FILE_ENV, "").strip()
    if env_path:
        return Path(env_path).expanduser()
    return Path.home() / ".config" / "raisin" / _ROBOT_API_KEY_FILE


def save_robot_api_key(api_key: str, path: Optional[Path] = None) -> Path:
    """Persist a robot API key with owner-only file permissions."""
    key = (api_key or "").strip()
    if not key:
        raise ValueError("Robot API key cannot be empty")

    target = Path(path).expanduser() if path else get_robot_api_key_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    temp_path = target.with_name(f".{target.name}.tmp")
    try:
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key + "\n")
        temp_path.replace(target)
    finally:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass

    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    _cache_robot_api_key(target, key)
    return target


def _read_robot_api_key_file_detailed(key_path: Path) -> tuple:
    """Read a key file, reporting whether a failure was already explained.

    Returns (key, explained). `explained` is True when the reason the key is
    unusable has already been printed — either by this call or by the earlier
    call that cached the result — so callers do not stack a second, vaguer
    warning on top of a specific one.
    """
    try:
        stat_result = key_path.stat()
    except FileNotFoundError:
        _robot_api_key_cache.pop(key_path, None)
        return (None, False)
    except OSError as e:
        print(f"⚠️ Failed to read robot API key file '{key_path}': {e}")
        return (None, True)

    cache_token = _api_key_cache_token(stat_result)
    cached = _robot_api_key_cache.get(key_path)
    if cached and cached[0] == cache_token:
        return (cached[1], cached[2])

    if os.name == "posix" and (stat_result.st_mode & 0o077):
        print(
            "⚠️ Ignoring robot API key file with insecure permissions: "
            f"{key_path} (run: chmod 600 {key_path})"
        )
        _robot_api_key_cache[key_path] = (cache_token, None, True)
        return (None, True)

    try:
        key = key_path.read_text(encoding="utf-8").strip()
    except OSError as e:
        print(f"⚠️ Failed to read robot API key file '{key_path}': {e}")
        return (None, True)

    cached_key = key or None
    _robot_api_key_cache[key_path] = (cache_token, cached_key, False)
    return (cached_key, False)


def _read_robot_api_key_file(key_path: Path) -> Optional[str]:
    return _read_robot_api_key_file_detailed(key_path)[0]


def get_robot_api_key() -> Optional[str]:
    """Read the robot API key from env or the local key file.

    Resolution order:
        1. RAISIN_ROBOT_API_KEY
        2. RAISIN_ROBOT_API_KEY_FILE
        3. configuration_setting.yaml/secrets.yaml robot.api_key
        4. ~/.config/raisin/robot-api-key

    File-backed keys are ignored on POSIX systems if group/other permissions
    are enabled.
    """
    env_key = os.environ.get(_ROBOT_API_KEY_ENV, "").strip()
    if env_key:
        return env_key

    env_key_file = os.environ.get(_ROBOT_API_KEY_FILE_ENV, "").strip()
    if env_key_file:
        # An explicitly pinned path is a deliberate choice. Do not fall through
        # to the config file or the default path when it does not resolve —
        # say so instead, or the robot quietly downloads as an anonymous client.
        key, explained = _read_robot_api_key_file_detailed(
            Path(env_key_file).expanduser()
        )
        if not key and not explained:
            _warn_robot_auth_config_once(
                f"unreadable_key_file:{env_key_file}",
                f"⚠️ {_ROBOT_API_KEY_FILE_ENV} points at '{env_key_file}' but no "
                "robot API key could be read from it. Using legacy OTA "
                "authentication instead.",
            )
        return key

    config_key = _get_local_config_value(
        (
            ("robot", "api_key"),
            ("robot", "apiKey"),
            ("ota", "robot_api_key"),
            ("robot_api_key",),
        )
    )
    if config_key:
        return config_key

    return _read_robot_api_key_file(get_robot_api_key_path())


def get_robot_node_key() -> Optional[str]:
    """Read the robot-local node key required by robot-authenticated endpoints."""
    for env_name in (_ROBOT_NODE_ENV, _ROBOT_NODE_KEY_ENV):
        env_value = _normalize_optional_string(os.environ.get(env_name))
        if env_value:
            return env_value

    return _get_local_config_value(
        (
            ("robot", "node"),
            ("robot", "node_key"),
            ("robot", "nodeKey"),
            ("ota", "robot_node"),
            ("robot_node",),
            ("robot_node_key",),
        )
    )


def _cache_robot_api_key(key_path: Path, api_key: Optional[str]) -> None:
    try:
        stat_result = key_path.stat()
    except OSError:
        _robot_api_key_cache.pop(key_path, None)
        return
    _robot_api_key_cache[key_path] = (
        _api_key_cache_token(stat_result),
        api_key,
        False,
    )


def _api_key_cache_token(stat_result) -> tuple:
    return (
        stat_result.st_mtime_ns,
        stat_result.st_size,
        stat_result.st_mode & 0o777,
    )


def _warn_robot_auth_config_once(key: str, message: str) -> None:
    if key in _robot_auth_warning_keys:
        return
    _robot_auth_warning_keys.add(key)
    print(message)


def get_client_version() -> str:
    """Return the OTA client identity used in robot audit/history records."""
    for env_name in ("RAISIN_OTA_CLIENT_VERSION", "RAISIN_CLIENT_VERSION"):
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    return DEFAULT_CLIENT_VERSION


def _normalize_optional_string(value) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    if not value or value.lower() in {"none", "null"}:
        return None
    return value


def resolve_robot_identity() -> Optional[RobotIdentity]:
    """Build the identity for the core, or None when this machine has none.

    A key without a node key is not a usable identity: the robot endpoints
    resolve a *node*, so half a credential would fail every request. Say so
    once and fall back to the user-authenticated route.
    """
    api_key = get_robot_api_key()
    if not api_key:
        return None

    node_key = get_robot_node_key()
    if not node_key:
        _warn_robot_auth_config_once(
            "missing_robot_node",
            "⚠️ Robot API key is configured but robot node is missing "
            "(set RAISIN_ROBOT_NODE or configuration_setting.yaml robot.node). "
            "Using legacy OTA authentication instead.",
        )
        return None

    return RobotIdentity(
        api_key=api_key, node_key=node_key, client_version=get_client_version()
    )
