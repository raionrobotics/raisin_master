# Installed SDK CPU and Eigen ABI

The host build selects a CPU profile with `RAISIN_MARCH`. On non-Windows builds
with a GNU/Clang-family compiler, the top-level build uses that value for the
producer, and `raisin_install()` exports the same `-march` requirement to
consumers of targets that link `Eigen3::Eigen`. This is required because Eigen's
fixed-size vector alignment can change with the compiler target. A successful
link alone does not prove that producer and consumer agree on that ABI.

The installed prefix contains `share/raisin/raisin-sdk-build-profile.json`.
It records the target system and processor, C/C++ compiler IDs and versions,
the selected `RAISIN_MARCH`, the observed `EIGEN_MAX_ALIGN_BYTES` and
`alignof(Eigen::Isometry3d)`, and a fingerprint of the `Eigen/Core` entry
header and imported target usage settings when Eigen is available to the
build-profile check. A `null` Eigen alignment means the build could not
observe that value; it is not evidence that Eigen is unused.

## Consumer rules

- Import the library through its installed CMake package and link its exported
  target. Do not link the shared library by file path while bypassing target
  usage requirements.
- An Eigen-backed target carries the recorded named CPU profile into the
  consumer's C++ compile command. Keep the matching compiler and Eigen headers
  in use across the producer and consumer build. If a consumer links imported
  Eigen-backed targets built with different `RAISIN_MARCH` values, CMake
  rejects the incompatible interface profiles during generation.
- SDKs built with `RAISIN_MARCH=native` are machine-specific. Importing an
  Eigen-backed package fails unless the consumer explicitly sets
  `RAISIN_ALLOW_UNPORTABLE_NATIVE_SDK=ON`. That opt-in is only for a consumer
  on a CPU compatible with the producer; it does not create a portable CPU
  baseline or validate a different host.
- The current export rule covers non-Windows GNU/Clang-family C++ targets
  linking the canonical `Eigen3::Eigen` target. It does not establish a
  Windows, Apple, other compiler, or arbitrary Eigen package support matrix.

## Rebuild boundary

Changing `RAISIN_MARCH`, the compiler/toolchain, Eigen version, or Eigen ABI
definitions requires rebuilding the affected SDK libraries together and
publishing a new immutable SDK archive. Do not replace only `raisin_tf` inside
an existing SDK prefix. Validate the installed-only `raisin::tf::Transform`
roundtrip against the published binary before declaring a profile supported.

Run the installed-only gate against a freshly installed SDK prefix with:

```sh
python3 tests/installed_sdk_abi/run.py --prefix /path/to/sdk-prefix
```

The runner keeps a scratch build directory, verifies the selected SDK package,
compiler and Eigen fingerprint, confirms the imported target supplies the
recorded `-march`, and then builds/runs the real `raisin::tf::Transform`
set/get/send roundtrip. It never writes into the SDK prefix. For a `native`
profile, pass `--allow-unportable-native-sdk` only after confirming this host
is compatible with the producer CPU.

The repository fixture test verifies CMake export propagation and native
profile refusal. It is not a substitute for the installed-only roundtrip
against a newly published SDK binary.
