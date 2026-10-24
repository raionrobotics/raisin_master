#!/usr/bin/env python3
"""Build and run the actual installed raisin_tf against its SDK prefix."""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


HERE = Path(__file__).resolve().parent
PROFILE_RELATIVE = Path("share/raisin/raisin-sdk-build-profile.json")


def fail(message: str, result: Optional[subprocess.CompletedProcess] = None) -> None:
    if result is not None:
        message += f"\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    raise RuntimeError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_checked(
    command: list[str], timeout: int, env: Optional[dict[str, str]] = None
) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as error:
        fail(f"command timed out after {timeout}s: {shlex.join(command)}")
    if result.returncode:
        fail(f"command failed ({result.returncode}): {shlex.join(command)}", result)
    return result


def runtime_environment(prefix: Path) -> tuple[dict[str, str], list[str]]:
    """Load SDK shared libraries from the qualified prefix before host paths."""
    environment = os.environ.copy()
    library_dirs = [
        prefix / name for name in ("lib", "lib64") if (prefix / name).is_dir()
    ]
    existing_dirs = [
        entry
        for entry in environment.get("LD_LIBRARY_PATH", "").split(os.pathsep)
        if entry
    ]
    ordered_dirs = [str(path) for path in library_dirs] + existing_dirs
    if ordered_dirs:
        environment["LD_LIBRARY_PATH"] = os.pathsep.join(dict.fromkeys(ordered_dirs))
    return environment, [str(path) for path in library_dirs]


def _parse_output(output: str) -> dict:
    observations = []
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            observations.append(item)
    before = next((item for item in observations if item.get("stage") == "before_set"), None)
    passed = any(item.get("stage") == "actual_tf_roundtrip_passed" for item in observations)
    if before is None or not passed:
        raise RuntimeError("probe did not report the expected alignment and TF roundtrip evidence")
    return before


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path, help="installed SDK prefix (read-only)")
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="empty scratch directory to retain build evidence; defaults to a new /tmp directory",
    )
    parser.add_argument("--timeout", type=int, default=180, help="per-command timeout in seconds")
    parser.add_argument(
        "--allow-unportable-native-sdk",
        action="store_true",
        help="opt in only when this host CPU is compatible with a native-built SDK",
    )
    args = parser.parse_args()

    cmake = shutil.which("cmake")
    if not cmake:
        fail("cmake was not found on PATH")
    if args.timeout < 1:
        fail("--timeout must be positive")

    prefix = args.prefix.expanduser().resolve(strict=True)
    if not prefix.is_dir():
        fail(f"SDK prefix is not a directory: {prefix}")
    profile_path = prefix / PROFILE_RELATIVE
    tf_config = prefix / "lib/cmake/raisin_tf/raisin_tfConfig.cmake"
    if not profile_path.is_file():
        fail(f"SDK build profile is missing: {profile_path}")
    if not tf_config.is_file():
        fail(f"installed raisin_tf package is missing: {tf_config}")

    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        fail("SDK build profile must be a JSON object")
    target = profile.get("target", {})
    compiler_info = profile.get("compiler", {})
    cpu = profile.get("cpu", {})
    eigen = profile.get("eigen", {})
    if not all(isinstance(value, dict) for value in (target, compiler_info, cpu, eigen)):
        fail("SDK build profile target/compiler/cpu/eigen sections must be JSON objects")
    compiler = compiler_info.get("cxx", {})
    if not isinstance(compiler, dict):
        fail("SDK build profile compiler.cxx section must be a JSON object")
    march = cpu.get("march")
    profile_kind = cpu.get("profile_kind")
    max_align = eigen.get("max_align_bytes")
    isometry_align = eigen.get("isometry3d_align_bytes")
    eigen_fingerprint = eigen.get("core_header_and_usage_fingerprint_sha256")

    if target.get("system") != "Linux":
        fail(f"this installed-only probe currently supports Linux SDKs; got {target.get('system')!r}")
    if not target.get("processor") or not march:
        fail("SDK metadata must name the target processor and RAISIN_MARCH profile")
    if profile_kind == "native-only" and not args.allow_unportable_native_sdk:
        fail("native-only SDK requires --allow-unportable-native-sdk after CPU compatibility is reviewed")
    if profile_kind not in {"native-only", "named-cpu-profile"}:
        fail(f"unsupported SDK CPU profile kind: {profile_kind!r}")
    if not isinstance(max_align, int) or not isinstance(isometry_align, int):
        fail("SDK metadata must record numeric Eigen and Isometry3d alignment")
    if not isinstance(eigen_fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", eigen_fingerprint):
        fail("SDK metadata must record the Eigen Core/usage SHA-256 fingerprint")

    if args.work_dir:
        work_dir = args.work_dir.expanduser().resolve()
        if prefix == work_dir or prefix in work_dir.parents or work_dir in prefix.parents:
            fail("--work-dir must not equal, contain, or be inside the read-only SDK prefix")
        if work_dir.exists() and any(work_dir.iterdir()):
            fail(f"--work-dir must be empty: {work_dir}")
        work_dir.mkdir(parents=True, exist_ok=True)
    else:
        work_dir = Path(tempfile.mkdtemp(prefix="raisin-installed-tf-abi-"))

    build_dir = work_dir / "build"
    configure_command = [
        cmake,
        "-S",
        str(HERE),
        "-B",
        str(build_dir),
        f"-DCMAKE_PREFIX_PATH={prefix}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "-DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY=ON",
        "-DCMAKE_FIND_PACKAGE_NO_SYSTEM_PACKAGE_REGISTRY=ON",
        "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        "-DCMAKE_CXX_FLAGS=",
        f"-DPROBE_EXPECTED_SYSTEM={target['system']}",
        f"-DPROBE_EXPECTED_PROCESSOR={target['processor']}",
        f"-DPROBE_EXPECTED_CXX_ID={compiler.get('id', '')}",
        f"-DPROBE_EXPECTED_CXX_VERSION={compiler.get('version', '')}",
        f"-DPROBE_EXPECTED_EIGEN_MAX_ALIGN_BYTES={max_align}",
        f"-DPROBE_EXPECTED_ISOMETRY3D_ALIGN_BYTES={isometry_align}",
        f"-DPROBE_EXPECTED_EIGEN_FINGERPRINT={eigen_fingerprint}",
    ]
    if args.allow_unportable_native_sdk:
        configure_command.append("-DRAISIN_ALLOW_UNPORTABLE_NATIVE_SDK=ON")
    configured = run_checked(configure_command, args.timeout)

    cache = (build_dir / "CMakeCache.txt").read_text(encoding="utf-8")
    package_dir = next(
        (line.partition("=")[2] for line in cache.splitlines() if line.startswith("raisin_tf_DIR:PATH=")),
        None,
    )
    if not package_dir or Path(package_dir).resolve() != (prefix / "lib/cmake/raisin_tf").resolve():
        fail(f"CMake selected an unexpected raisin_tf package directory: {package_dir!r}")

    imported_match = re.search(r"RAISIN_TF_IMPORTED_LOCATION=(.+)", configured.stdout)
    if not imported_match:
        fail("CMake did not report the imported raisin_tf library location", configured)
    tf_library = Path(imported_match.group(1).strip()).resolve()
    if prefix not in tf_library.parents or not tf_library.is_file():
        fail(f"raisin_tf library is outside the selected SDK prefix: {tf_library}")

    compile_commands = json.loads((build_dir / "compile_commands.json").read_text(encoding="utf-8"))
    probe_command = next(
        (item["command"] for item in compile_commands if item.get("file", "").endswith("probe.cpp")),
        None,
    )
    if not probe_command:
        fail("CMake did not record a compile command for probe.cpp")
    march_flags = [token for token in shlex.split(probe_command) if token.startswith("-march=")]
    if not march_flags or any(flag != f"-march={march}" for flag in march_flags):
        fail(f"installed target did not supply one compatible march profile: {march_flags!r}")

    run_checked([cmake, "--build", str(build_dir), "--parallel", "1"], args.timeout)
    binary = build_dir / "tf_sdk_abi_probe"
    runtime_env, runtime_library_dirs = runtime_environment(prefix)
    executed = run_checked([str(binary)], args.timeout, env=runtime_env)
    observation = _parse_output(executed.stdout)
    if observation.get("eigen_max_align") != max_align:
        fail(f"runtime Eigen max alignment differs from metadata: {observation!r}")
    if observation.get("eigen_alignment") != isometry_align:
        fail(f"runtime Isometry3d alignment differs from metadata: {observation!r}")

    result = {
        "passed": True,
        "sdk_prefix": str(prefix),
        "work_dir": str(work_dir),
        "cpu_profile": march,
        "compiler": compiler,
        "eigen_max_align_bytes": observation["eigen_max_align"],
        "isometry3d_align_bytes": observation["eigen_alignment"],
        "pose_mod32": observation["pose_mod32"],
        "march_flags": march_flags,
        "runtime_library_dirs": runtime_library_dirs,
        "raisin_tf_config_sha256": sha256(tf_config),
        "raisin_tf_library_sha256": sha256(tf_library),
        "sdk_profile_sha256": sha256(profile_path),
        "actual_tf_roundtrip": "passed",
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"installed SDK ABI probe: {error}", file=sys.stderr)
        raise SystemExit(1)
