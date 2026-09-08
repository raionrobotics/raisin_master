"""
Build-target configuration for RAISIN.

Separates the *build host* from the *target platform*. Host builds keep the
historical behaviour (``TargetConfig.host()``); a cross target carries its own
build directory, generated-header directory and install prefix so an Android
build can never erase or reuse host outputs.

SDK package closures and CMake feature settings come from platform-specific
``commands/sdk_<platform>_profile.yaml`` files. Android uses
``commands/sdk_android_profile.yaml``.
"""

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from commands import globals as g

PROFILES_DIR = Path(__file__).parent

ANDROID_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
ANDROID_STLS = ("c++_shared",)
BUILD_TYPES = ("Debug", "Release", "RelWithDebInfo", "MinSizeRel")

# -march= baseline per Android ABI. Deliberately conservative: the app ships to
# every device that satisfies minSdk, so the SDK must not require extensions the
# host default (armv8.2-a+crypto+fp16+dotprod) assumes.
ANDROID_MARCH = {
    "arm64-v8a": "armv8-a",
    "armeabi-v7a": "armv7-a",
    "x86_64": "x86-64",
    "x86": "i686",
}

# Feature flag -> packages the flag's enabled/disabled branch pulls in. Mirrors
# the conditionals in raisin_network/CMakeLists.txt and
# raisin_thread_pool/CMakeLists.txt, which the regex scanner cannot evaluate.
FEATURE_PACKAGES = {
    "RAISIN_NETWORK_ENABLE_DATA_LOGGER": {True: ["raisin_data_logger"], False: []},
    "RAISIN_NETWORK_ENABLE_PARAMETERS": {True: ["raisin_parameter"], False: []},
    "RAISIN_NETWORK_ENABLE_SHARED_MEMORY": {True: ["raisin_shared_memory"], False: []},
    "RAISIN_NETWORK_ENABLE_WEBSOCKET": {True: ["websocketpp"], False: []},
    "RAISIN_NETWORK_ENABLE_DYNAMIC_ENCRYPTION": {
        True: ["raisin_util"],
        False: ["raisin_empty_encryption"],
    },
    "RAISIN_THREAD_POOL_ENABLE_DATA_LOGGER": {
        True: ["raisin_util", "raisin_data_logger"],
        False: ["raisin_compat"],
    },
}

# Always required by raisin_network regardless of feature selection.
BASE_PACKAGES = ("raisin_thread_pool", "raisin_encryption")

# (flag, required_flag) - the first implies the second must be ON.
FEATURE_REQUIRES = (
    ("RAISIN_NETWORK_ENABLE_WEBSOCKET", "RAISIN_NETWORK_ENABLE_PARAMETERS"),
    ("RAISIN_NETWORK_ENABLE_NODE_FLOW", "RAISIN_NETWORK_ENABLE_SHARED_MEMORY"),
    ("RAISIN_THREAD_POOL_ENABLE_REALTIME", "RAISIN_THREAD_POOL_ENABLE_DATA_LOGGER"),
)


class TargetConfigError(Exception):
    """Raised for an invalid or inconsistent target selection."""


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().upper() in ("ON", "TRUE", "YES", "1")


@dataclass(frozen=True)
class TargetConfig:
    """Where a build runs (host) versus what it produces (platform/abi/api)."""

    platform: str = "host"
    profile: str = ""
    abi: str = ""
    api_level: int = 0
    ndk_dir: str = ""
    ndk_version: str = ""
    stl: str = ""
    build_type: str = "Release"
    march: str = ""
    packages: Tuple[str, ...] = ()
    message_packages: Tuple[str, ...] = ()
    source_repositories: Tuple[str, ...] = ()
    interface_repositories: Tuple[str, ...] = ()
    extra_headers: Dict[str, str] = field(default_factory=dict)
    cmake_options: Dict[str, str] = field(default_factory=dict)
    description: str = ""

    @staticmethod
    def host() -> "TargetConfig":
        return TargetConfig()

    @property
    def is_cross(self) -> bool:
        return self.platform != "host"

    @property
    def configuration_id(self) -> str:
        """Isolate every toolchain/profile variant, including NDK path changes.

        CMake cannot safely change compilers in an existing binary directory.
        Use the same identity for installed artifacts so a variant cannot
        overwrite an SDK that another consumer still uses.
        """
        settings = asdict(self)
        settings.pop("description")
        payload = json.dumps(settings, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    @property
    def slug(self) -> str:
        if not self.is_cross:
            return "host"
        return (
            f"{self.platform}-{self.abi}-api{self.api_level}-"
            f"{self.build_type.lower()}-{self.configuration_id}"
        )

    def build_dir(self) -> Path:
        """Top-level scratch directory. Matches the `cmake-*/*` gitignore rule."""
        if not self.is_cross:
            return Path(g.script_directory) / f"cmake-build-{self.build_type.lower()}"
        return Path(g.script_directory) / f"cmake-build-{self.slug}"

    def cmake_root_dir(self) -> Path:
        """Source directory holding the generated root CMakeLists.txt."""
        if not self.is_cross:
            return Path(g.script_directory)
        return self.build_dir() / "cmake_root"

    def cmake_binary_dir(self) -> Path:
        if not self.is_cross:
            return self.build_dir()
        return self.build_dir() / "build"

    def generated_dir(self) -> Path:
        """Generated message headers. Never shared between host and a cross target."""
        if not self.is_cross:
            return Path(g.script_directory) / "generated"
        return self.build_dir() / "generated"

    def install_dir(self) -> Path:
        """SDK outputs are independent of host install and OTA release packages."""
        if not self.is_cross:
            return Path(g.script_directory) / "install"
        return (
            Path(g.script_directory)
            / "sdk"
            / self.platform
            / str(self.api_level)
            / self.abi
            / self.build_type.lower()
            / self.configuration_id
        )

    def archive_dir(self) -> Path:
        return Path(g.script_directory) / "sdk" / self.platform / "archives"

    def cache_dir(self) -> Path:
        return Path(g.script_directory) / ".cache" / self.slug

    def cmake_args(self) -> List[str]:
        """CMake arguments that pin the toolchain for this target."""
        if not self.is_cross:
            return []
        toolchain = Path(self.ndk_dir) / "build" / "cmake" / "android.toolchain.cmake"
        return [
            f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
            f"-DANDROID_ABI={self.abi}",
            f"-DANDROID_PLATFORM=android-{self.api_level}",
            f"-DANDROID_STL={self.stl}",
            f"-DCMAKE_ANDROID_API={self.api_level}",
        ]

    def metadata(self) -> dict:
        return {
            "platform": self.platform,
            "profile": self.profile,
            "abi": self.abi,
            "api_level": self.api_level,
            "ndk_version": self.ndk_version,
            "stl": self.stl,
            "build_type": self.build_type,
            "march": self.march,
            "cxx_standard": 20,
            "configuration_id": self.configuration_id,
        }


def load_profiles(path: Optional[Path] = None, *, platform: str = "android") -> dict:
    """Load only the selected platform's SDK profiles; never fall back to another."""
    profile_path = path or PROFILES_DIR / f"sdk_{platform}_profile.yaml"
    try:
        with open(profile_path, "r", encoding="utf-8") as f:
            profiles = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as error:
        raise TargetConfigError(f"cannot load SDK profiles from {profile_path}: {error}") from error
    for name, profile in profiles.items():
        if profile.get("platform") != platform:
            raise TargetConfigError(
                f"profile '{name}' in {profile_path} targets "
                f"'{profile.get('platform')}', not {platform}"
            )
    return profiles


def validate_profile(name: str, profile: dict) -> None:
    """Fail loudly when the package allowlist and the feature flags disagree."""
    packages = set(profile.get("packages") or [])
    if not packages:
        raise TargetConfigError(f"profile '{name}': 'packages' must not be empty")

    options = {k: _as_bool(v) for k, v in (profile.get("cmake_options") or {}).items()}

    for flag, required in FEATURE_REQUIRES:
        if options.get(flag, True) and not options.get(required, True):
            raise TargetConfigError(
                f"profile '{name}': {flag}=ON requires {required}=ON"
            )

    network_logger = options.get("RAISIN_NETWORK_ENABLE_DATA_LOGGER", True)
    pool_logger = options.get("RAISIN_THREAD_POOL_ENABLE_DATA_LOGGER", True)
    if network_logger != pool_logger:
        raise TargetConfigError(
            f"profile '{name}': raisin_network and raisin_thread_pool must use the "
            "same data-logger capability"
        )

    # raisin_network pulls raisin_compat when either data logging or OpenSSL is off.
    needed = set(BASE_PACKAGES)
    if not network_logger or not options.get("RAISIN_NETWORK_ENABLE_OPENSSL", True):
        needed.add("raisin_compat")
    for flag, branches in FEATURE_PACKAGES.items():
        needed.update(branches[options.get(flag, True)])

    missing = sorted(needed - packages)
    if missing:
        raise TargetConfigError(
            f"profile '{name}': cmake_options require package(s) {missing} that are "
            "not in the 'packages' allowlist"
        )

    extra = sorted(
        p
        for p in packages
        if p in _all_feature_packages() and p not in needed
    )
    if extra:
        raise TargetConfigError(
            f"profile '{name}': package(s) {extra} are in the allowlist but no "
            "enabled cmake_option needs them"
        )


def _all_feature_packages() -> set:
    names = set()
    for branches in FEATURE_PACKAGES.values():
        for pkgs in branches.values():
            names.update(pkgs)
    return names


def discover_ndk(explicit: str = "") -> Tuple[str, str]:
    """Return (ndk_dir, ndk_version). Raises if no usable NDK is found."""
    candidates = []
    if explicit:
        candidate = Path(explicit).expanduser().resolve()
        if not (candidate / "build/cmake/android.toolchain.cmake").is_file():
            raise TargetConfigError(
                f"--ndk '{explicit}' is not an Android NDK: "
                "build/cmake/android.toolchain.cmake is missing. "
                "Fix --ndk or omit it to enable automatic discovery."
            )
        return str(candidate), _ndk_version(candidate)
    for env in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "ANDROID_NDK"):
        value = os.environ.get(env)
        if value:
            candidates.append(Path(value))
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        sdk = os.environ.get(env)
        if sdk and (Path(sdk) / "ndk").is_dir():
            versions = sorted(
                (p for p in (Path(sdk) / "ndk").iterdir() if p.is_dir()),
                key=lambda p: [int(x) for x in re.findall(r"\d+", p.name)] or [0],
            )
            candidates.extend(reversed(versions))

    for candidate in candidates:
        candidate = candidate.expanduser().resolve()
        toolchain = candidate / "build" / "cmake" / "android.toolchain.cmake"
        if toolchain.is_file():
            try:
                return str(candidate), _ndk_version(candidate)
            except TargetConfigError:
                continue

    raise TargetConfigError(
        "no Android NDK found. Pass --ndk, or set ANDROID_NDK_HOME, or install an "
        "NDK under $ANDROID_HOME/ndk/."
    )


def _ndk_version(ndk_dir: Path) -> str:
    properties = ndk_dir / "source.properties"
    if properties.is_file():
        match = re.search(
            r"^Pkg\.Revision\s*=\s*(\d+\.\d+\.\d+(?:-beta\d+)?)\s*$",
            properties.read_text(encoding="utf-8"), re.MULTILINE,
        )
        if match:
            return match.group(1)
    raise TargetConfigError(f"cannot read a valid NDK Pkg.Revision from {properties}")


def resolve_android_target(
    profile_name: str = "android_comm",
    abi: str = "arm64-v8a",
    api_level: int = 24,
    ndk: str = "",
    stl: str = "c++_shared",
    build_type: str = "RelWithDebInfo",
    march: str = "",
    profiles: Optional[dict] = None,
) -> TargetConfig:
    """Build a validated Android TargetConfig, or raise TargetConfigError."""
    all_profiles = profiles if profiles is not None else load_profiles(platform="android")
    if profile_name not in all_profiles:
        raise TargetConfigError(
            f"unknown profile '{profile_name}' (available: "
            f"{', '.join(sorted(all_profiles)) or 'none'})"
        )
    profile = all_profiles[profile_name]
    if profile.get("platform") != "android":
        raise TargetConfigError(
            f"profile '{profile_name}' targets '{profile.get('platform')}', not android"
        )
    validate_profile(profile_name, profile)

    if abi not in ANDROID_ABIS:
        raise TargetConfigError(
            f"unsupported Android ABI '{abi}' (supported: {', '.join(ANDROID_ABIS)})"
        )
    if stl not in ANDROID_STLS:
        raise TargetConfigError(
            f"unsupported ANDROID_STL '{stl}': the SDK contains multiple shared "
            "libraries and requires c++_shared."
        )
    if build_type not in BUILD_TYPES:
        raise TargetConfigError(
            f"unsupported build type '{build_type}' (supported: {', '.join(BUILD_TYPES)})"
        )
    if not 21 <= int(api_level) <= 99:
        raise TargetConfigError(f"implausible Android API level '{api_level}'")

    ndk_dir, ndk_version = discover_ndk(ndk)

    return TargetConfig(
        platform="android",
        profile=profile_name,
        abi=abi,
        api_level=int(api_level),
        ndk_dir=ndk_dir,
        ndk_version=ndk_version,
        stl=stl,
        build_type=build_type,
        march=march or ANDROID_MARCH[abi],
        packages=tuple(profile.get("packages") or ()),
        message_packages=tuple(profile.get("message_packages") or ()),
        source_repositories=tuple(profile.get("source_repositories") or ()),
        interface_repositories=tuple(profile.get("interface_repositories") or ()),
        extra_headers=dict(profile.get("extra_headers") or {}),
        cmake_options={
            k: ("ON" if _as_bool(v) else "OFF")
            for k, v in (profile.get("cmake_options") or {}).items()
        },
        description=(profile.get("description") or "").strip(),
    )
