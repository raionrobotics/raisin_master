#!/usr/bin/env python3
"""
Tests for the SDK build command, target configuration and packaging.

Covers CLI dispatch, platform profiles, Android target selection, dependency
closure, host/SDK isolation, and SDK metadata and consumer compatibility.

Usage:
    python3 test_build_sdk.py
    python3 -m unittest test_build_sdk
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from dataclasses import replace
from unittest.mock import Mock, patch

from click.testing import CliRunner

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from commands import globals as g
from commands import sdk_target_config as tc
from raisin import cli

SCRIPT_DIR = Path(__file__).resolve().parent
FAKE_NDK_VERSION = "28.2.13676358"


def make_fake_ndk(root: Path) -> Path:
    ndk = root / "ndk" / FAKE_NDK_VERSION
    (ndk / "build" / "cmake").mkdir(parents=True)
    (ndk / "build" / "cmake" / "android.toolchain.cmake").write_text("")
    (ndk / "source.properties").write_text(f"Pkg.Revision = {FAKE_NDK_VERSION}\n")
    return ndk


class BuildSdkCommandTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        g.init_globals(script_directory=self.tmp.name)
        self.ndk = make_fake_ndk(Path(self.tmp.name))

    def invoke(self, args):
        with patch("raisin.init_environment"):
            return CliRunner().invoke(cli, args)

    def test_android_command_builds_and_packages_with_optional_archive(self):
        for archive_enabled in (True, False):
            with self.subTest(archive=archive_enabled):
                stages = Mock()
                with patch("commands.setup.setup", stages.setup), \
                        patch("commands.build_sdk.generate_sdk_cmake", stages.generate), \
                        patch("commands.build_sdk.configure_and_build", stages.build), \
                        patch("commands.build_sdk.package_sdk", stages.package), \
                        patch("commands.build_sdk.archive_sdk", stages.archive):
                    args = [
                        "build_sdk", "android", "--ndk", str(self.ndk),
                        "--abi", "x86_64", "--api", "26", "--build-type", "Debug",
                    ]
                    if not archive_enabled:
                        args.append("--no-archive")
                    result = self.invoke(args)
                self.assertEqual(result.exit_code, 0, result.output)
                expected = ["setup", "generate", "build", "package"]
                if archive_enabled:
                    expected.append("archive")
                self.assertEqual([call[0] for call in stages.mock_calls], expected)
                target = stages.build.call_args.args[0]
                self.assertEqual(
                    (target.platform, target.abi, target.api_level, target.build_type),
                    ("android", "x86_64", 26, "Debug"),
                )
                self.assertEqual(stages.setup.call_args.kwargs["target"], target)
                stages.generate.assert_called_once_with(target, stages.setup.return_value)
                self.assertEqual(stages.package.call_args.args[0], target)
                if archive_enabled:
                    stages.archive.assert_called_once_with(target)

    def test_profile_listing_needs_no_toolchain_or_build(self):
        with patch("commands.sdk_target_config.discover_ndk") as ndk, \
                patch("commands.setup.setup") as setup, \
                patch("commands.build_sdk.configure_and_build") as build:
            result = self.invoke(["build_sdk", "android", "--list-profiles"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("android_comm  [android]", result.output)
        ndk.assert_not_called()
        setup.assert_not_called()
        build.assert_not_called()


class SdkProfileFilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_platform_files_are_loaded_independently(self):
        for platform in ("android", "linux"):
            (self.root / f"sdk_{platform}_profile.yaml").write_text(
                f"comm:\n  platform: {platform}\n"
            )
        with patch.object(tc, "PROFILES_DIR", self.root):
            for platform in ("android", "linux"):
                self.assertEqual(tc.load_profiles(platform=platform)["comm"]["platform"],
                                 platform)

    def test_missing_platform_file_does_not_fall_back_to_android(self):
        (self.root / "sdk_android_profile.yaml").write_text("comm:\n  platform: android\n")
        with patch.object(tc, "PROFILES_DIR", self.root):
            with self.assertRaisesRegex(tc.TargetConfigError, "sdk_linux_profile.yaml"):
                tc.load_profiles(platform="linux")

    def test_profile_cannot_belong_to_another_platform(self):
        profile = self.root / "sdk_android_profile.yaml"
        profile.write_text("comm:\n  platform: linux\n")
        with self.assertRaisesRegex(tc.TargetConfigError, "not android"):
            tc.load_profiles(profile, platform="android")


class SdkDependenciesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        g.init_globals(script_directory=str(self.root), os_type="ubuntu",
                       os_version="24.04", architecture="x86_64")
        self.target = replace(
            tc.resolve_android_target(ndk=str(make_fake_ndk(self.root))),
            packages=("raisin_network",), message_packages=("std_msgs",), extra_headers={},
        )
        self.assertEqual(self.target.source_repositories, ("raisin_third_party_common", "raisin"))
        self.assertEqual(self.target.interface_repositories, ("raisin_ros2_messages",))
        for name in self.target.source_repositories:
            (self.root / "src" / name).mkdir(parents=True)
        self.core = self.root / "src/raisin/raisin_network"
        self.core.mkdir()
        (self.core / "CMakeLists.txt").write_text("project(raisin_network)\n")
        (self.root / "templates").symlink_to(SCRIPT_DIR / "templates", target_is_directory=True)
        (self.root / "configuration_setting.yaml").write_text("user_type: devel\n")
        self.archive = self.root / "release/install/raisin_ros2_messages/ubuntu/24.04/x86_64/release"

    def add_source(self):
        repository = self.root / "src/raisin_ros2_messages"
        package = repository / "messages/std_msgs"
        (package / "msg").mkdir(parents=True)
        (package / "msg/String.msg").write_text("string source_data\n")
        (package / "include/std_msgs").mkdir(parents=True)
        (package / "include/std_msgs/helper.hpp").write_text("// source helper\n")
        (repository / "CMakeLists.txt").write_text('message(FATAL_ERROR "Do not build ROS projects")\n')

    def add_release(self):
        (self.archive / "messages/std_msgs/msg").mkdir(parents=True)
        (self.archive / "messages/std_msgs/msg/String.msg").write_text("string release_data\n")
        (self.archive / "messages/std_msgs/msg/Stale.msg").write_text("int32 value\n")
        (self.archive / "generated/include/std_msgs/msg").mkdir(parents=True)
        (self.archive / "generated/include/std_msgs/msg/string.hpp").write_text("// release header\n")
        (self.archive / "lib").mkdir()
        (self.archive / "lib/host.so").write_bytes(b"host binary")

    def prepare(self, ignored_repos=()):
        from commands.setup import setup
        with patch("commands.setup.get_repos_to_ignore", return_value=list(ignored_repos)), \
                patch("commands.setup.update_cmake_file", side_effect=AssertionError("host generator")), \
                redirect_stdout(StringIO()):
            return setup(target=self.target)

    def test_release_interfaces_work_without_message_source_or_host_build(self):
        from commands.setup import TARGET_INTERFACE_SOURCES
        self.add_release()
        self.assertEqual(self.prepare(), [str(self.core)])
        self.assertEqual(TARGET_INTERFACE_SOURCES["raisin_ros2_messages"]["kind"], "release")
        header = self.target.generated_dir() / "include/std_msgs/msg/string.hpp"
        self.assertEqual(header.read_text(), "// release header\n")
        self.assertFalse((self.target.install_dir() / "lib/host.so").exists())

    def test_source_interfaces_generate_headers_without_release_or_ros_cmake(self):
        from commands.setup import TARGET_INTERFACE_SOURCES
        self.add_source()
        self.assertEqual(self.prepare(), [str(self.core)])
        self.assertEqual(TARGET_INTERFACE_SOURCES["raisin_ros2_messages"]["kind"], "source")
        self.assertIn("source_data", (self.target.generated_dir() / "include/std_msgs/msg/string.hpp").read_text())
        self.assertTrue((self.target.generated_dir() / "include/std_msgs/helper.hpp").is_file())
        self.assertEqual((self.target.install_dir() / "messages/std_msgs/msg/String.msg").read_text(),
                         "string source_data\n")

    def test_source_takes_precedence_without_stale_release_files(self):
        self.add_source()
        self.add_release()
        self.prepare()
        self.assertIn("source_data", (self.target.generated_dir() / "include/std_msgs/msg/string.hpp").read_text())
        self.assertFalse((self.target.install_dir() / "messages/std_msgs/msg/Stale.msg").exists())

    def test_ignored_message_source_uses_release(self):
        from commands.setup import TARGET_INTERFACE_SOURCES
        self.add_source()
        self.add_release()
        self.prepare(ignored_repos=("raisin_ros2_messages",))
        self.assertEqual(TARGET_INTERFACE_SOURCES["raisin_ros2_messages"]["kind"], "release")
        self.assertEqual((self.target.generated_dir() / "include/std_msgs/msg/string.hpp").read_text(),
                         "// release header\n")

    def test_missing_dependencies_preserve_existing_sdk_and_headers(self):
        sdk_marker = self.target.install_dir() / "raisin_sdk.json"
        generated_marker = self.target.generated_dir() / "include/keep.hpp"
        for path in (sdk_marker, generated_marker):
            path.parent.mkdir(parents=True)
            path.write_text("keep\n")
        with self.assertRaisesRegex(tc.TargetConfigError, "raisin_ros2_messages"):
            self.prepare()
        self.add_release()
        for name in self.target.source_repositories:
            with self.subTest(repository=name):
                source = self.root / "src" / name
                held = self.root / name
                source.rename(held)
                try:
                    with self.assertRaisesRegex(tc.TargetConfigError, name):
                        self.prepare()
                finally:
                    held.rename(source)
        for path in (sdk_marker, generated_marker):
            self.assertEqual(path.read_text(), "keep\n")

    def test_ignored_required_source_is_rejected(self):
        self.add_release()
        with self.assertRaisesRegex(tc.TargetConfigError, "requires active source"):
            self.prepare(ignored_repos=("raisin",))

    def test_incomplete_message_source_is_rejected_before_deployment(self):
        (self.root / "src/raisin_ros2_messages").mkdir()
        with self.assertRaisesRegex(tc.TargetConfigError, "std_msgs"):
            self.prepare()


class CMakeTemplateIsolationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.templates = Path(__file__).parent / "templates"
        g.init_globals(script_directory=str(self.root))

    def test_sdk_generation_needs_no_host_cmake_template(self):
        from commands.build_sdk import generate_sdk_cmake

        shutil.copytree(self.templates / "sdk/android", self.root / "templates/sdk/android")
        host_root = self.root / "CMakeLists.txt"
        host_root.write_text("host root sentinel\n")
        target = tc.TargetConfig(platform="android", profile="fixture")
        output = generate_sdk_cmake(target, [])
        content = output.read_text()
        self.assertEqual(host_root.read_text(), "host root sentinel\n")
        self.assertIn("project(raisin_android_sdk", content)
        self.assertIn(str(target.generated_dir() / "include"), content)
        self.assertNotIn("update_build_dir_in_yaml", content)
        self.assertNotIn("@", content)

    def test_host_generation_needs_no_sdk_templates(self):
        from commands.setup import update_cmake_file

        (self.root / "templates").mkdir()
        shutil.copy2(self.templates / "CMakeLists.txt", self.root / "templates/CMakeLists.txt")
        update_cmake_file([], "", False)
        content = (self.root / "CMakeLists.txt").read_text()
        self.assertIn(f'{self.root}/generated/include', content)
        self.assertIn("update_build_dir_in_yaml", content)
        self.assertNotIn("raisin_android_sdk", content)
        self.assertNotIn("@", content)


class TargetSelectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ndk = make_fake_ndk(Path(self.tmp.name))
        g.init_globals(script_directory=str(SCRIPT_DIR))

    def tearDown(self):
        self.tmp.cleanup()

    def resolve(self, **kwargs):
        kwargs.setdefault("ndk", str(self.ndk))
        return tc.resolve_android_target(**kwargs)

    def test_defaults_resolve(self):
        target = self.resolve()
        self.assertTrue(target.is_cross)
        self.assertEqual(target.platform, "android")
        self.assertEqual(target.abi, "arm64-v8a")
        self.assertEqual(target.api_level, 24)
        self.assertEqual(target.stl, "c++_shared")
        self.assertEqual(target.ndk_version, FAKE_NDK_VERSION)

    def test_march_is_a_conservative_baseline_not_the_host_default(self):
        # The host default is armv8.2-a+crypto+fp16+dotprod; shipping that to
        # every minSdk device would fault on older arm64 hardware.
        self.assertEqual(self.resolve().march, "armv8-a")
        self.assertEqual(self.resolve(abi="x86_64").march, "x86-64")
        self.assertEqual(self.resolve(march="armv8.4-a").march, "armv8.4-a")

    def test_host_target_is_not_cross(self):
        host = tc.TargetConfig.host()
        self.assertFalse(host.is_cross)
        self.assertEqual(host.cmake_args(), [])
        self.assertEqual(host.slug, "host")

    def test_rejects_unknown_abi(self):
        with self.assertRaises(tc.TargetConfigError) as ctx:
            self.resolve(abi="mips64")
        self.assertIn("mips64", str(ctx.exception))

    def test_rejects_unknown_stl(self):
        with self.assertRaises(tc.TargetConfigError):
            self.resolve(stl="gnustl_shared")

    def test_rejects_static_runtime_for_multiple_shared_libraries(self):
        with self.assertRaisesRegex(tc.TargetConfigError, "multiple shared"):
            self.resolve(stl="c++_static")

    def test_explicit_missing_ndk_never_falls_back_to_environment(self):
        with patch.dict(os.environ, {"ANDROID_NDK_HOME": str(self.ndk)}):
            with self.assertRaisesRegex(tc.TargetConfigError, "--ndk"):
                tc.discover_ndk(str(Path(self.tmp.name) / "missing"))

    def test_explicit_ndk_requires_revision_metadata(self):
        (self.ndk / "source.properties").unlink()
        with self.assertRaisesRegex(tc.TargetConfigError, "Pkg.Revision"):
            self.resolve()

    def test_explicit_ndk_is_resolved_before_cmake_changes_directory(self):
        relative = os.path.relpath(self.ndk)
        self.assertEqual(self.resolve(ndk=relative).ndk_dir, str(self.ndk.resolve()))

    def test_rejects_unknown_profile(self):
        with self.assertRaises(tc.TargetConfigError) as ctx:
            self.resolve(profile_name="does_not_exist")
        self.assertIn("android_comm", str(ctx.exception))

    def test_rejects_implausible_api_level(self):
        with self.assertRaises(tc.TargetConfigError):
            self.resolve(api_level=9)

    def test_rejects_non_android_profile(self):
        profiles = {"host_thing": {"platform": "host", "packages": ["x"]}}
        with self.assertRaises(tc.TargetConfigError):
            self.resolve(profile_name="host_thing", profiles=profiles)

    def test_missing_ndk_reports_how_to_fix(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(tc.TargetConfigError) as ctx:
                tc.resolve_android_target(ndk="")
        self.assertIn("ANDROID_NDK_HOME", str(ctx.exception))

    def test_ndk_discovered_from_android_home(self):
        with patch.dict(os.environ, {"ANDROID_HOME": self.tmp.name}, clear=True):
            ndk_dir, version = tc.discover_ndk("")
        self.assertEqual(Path(ndk_dir), self.ndk)
        self.assertEqual(version, FAKE_NDK_VERSION)

    def test_cmake_args_pin_the_toolchain(self):
        args = self.resolve().cmake_args()
        joined = " ".join(args)
        self.assertIn("android.toolchain.cmake", joined)
        self.assertIn("-DANDROID_ABI=arm64-v8a", args)
        self.assertIn("-DANDROID_PLATFORM=android-24", args)
        self.assertIn("-DANDROID_STL=c++_shared", args)


class ProfileValidationTest(unittest.TestCase):
    """The allowlist and the feature flags must not be able to drift apart."""

    def setUp(self):
        g.init_globals(script_directory=str(SCRIPT_DIR))
        self.profile = tc.load_profiles()["android_comm"]

    def test_shipped_profile_is_consistent(self):
        tc.validate_profile("android_comm", self.profile)

    def test_disabled_features_keep_their_packages_out(self):
        packages = set(self.profile["packages"])
        for excluded in (
            "raisin_data_logger",
            "raisin_parameter",
            "raisin_shared_memory",
            "websocketpp",
            "raisin_util",
        ):
            self.assertNotIn(excluded, packages)

    def test_package_with_no_enabled_feature_fails(self):
        profile = json.loads(json.dumps(self.profile))
        profile["packages"].append("raisin_shared_memory")
        with self.assertRaises(tc.TargetConfigError) as ctx:
            tc.validate_profile("bad", profile)
        self.assertIn("raisin_shared_memory", str(ctx.exception))

    def test_variant_must_be_explicit_and_known(self):
        profile = json.loads(json.dumps(self.profile))
        for value in (None, "minimal", "OFF"):
            profile["cmake_options"][tc.CORE_VARIANT_OPTION] = value
            with self.assertRaisesRegex(tc.TargetConfigError, "must explicitly select"):
                tc.validate_profile("bad", profile)

    def test_android_profile_requires_lite(self):
        profile = json.loads(json.dumps(self.profile))
        profile["cmake_options"][tc.CORE_VARIANT_OPTION] = "full"
        with self.assertRaisesRegex(tc.TargetConfigError, "Android SDK profiles currently require"):
            tc.validate_profile("bad", profile)

    def test_lite_profile_requires_compat_and_empty_encryption(self):
        for package in ("raisin_compat", "raisin_empty_encryption"):
            profile = json.loads(json.dumps(self.profile))
            profile["packages"].remove(package)
            with self.assertRaisesRegex(tc.TargetConfigError, package):
                tc.validate_profile("bad", profile)

    def test_empty_package_list_fails(self):
        with self.assertRaises(tc.TargetConfigError):
            tc.validate_profile("bad", {"packages": [], "cmake_options": {}})


class DependencyClosureTest(unittest.TestCase):
    """
    The regex scanner cannot evaluate CMake conditionals; the allowlist is what
    keeps disabled branches out of the generated root CMakeLists.txt.
    """

    def setUp(self):
        g.init_globals(script_directory=str(SCRIPT_DIR))
        from commands import setup as setup_module

        self.setup = setup_module
        self.network_cmake = (
            SCRIPT_DIR / "src" / "raisin" / "raisin_network" / "CMakeLists.txt"
        )
        if not self.network_cmake.is_file():
            self.skipTest("src/raisin is not checked out")

    def test_scanner_reports_disabled_branches(self):
        found = self.setup.find_dependencies(str(self.network_cmake))
        self.assertIn("raisin_data_logger", found)
        self.assertIn("raisin_parameter", found)
        self.assertIn("raisin_shared_memory", found)
        self.assertIn("websocketpp", found)

    def test_allowlist_prunes_them_from_discovery(self):
        allowed = {"raisin_network", "raisin_thread_pool", "raisin_compat"}
        with tempfile.TemporaryDirectory() as tmp:
            found = self.setup.find_project_directories(
                ["src"], tmp, packages_allowed=allowed
            )
        names = {Path(p).name for p in found}
        self.assertTrue(names <= allowed, f"unexpected packages: {names - allowed}")
        self.assertIn("raisin_network", names)

    def test_generated_graph_only_contains_allowlisted_packages(self):
        allowed = {
            "raisin_network",
            "raisin_thread_pool",
            "raisin_compat",
            "raisin_encryption",
            "raisin_empty_encryption",
        }
        with tempfile.TemporaryDirectory() as tmp:
            directories = self.setup.find_project_directories(
                ["src"], tmp, packages_allowed=allowed
            )
        graph = self.setup.build_dependency_graph(directories)
        for project, dependencies in graph.items():
            for dependency in dependencies:
                self.assertIn(dependency, allowed, f"{project} -> {dependency}")

    def test_generated_root_contains_only_the_profile_closure(self):
        """End to end: profile -> generated root CMakeLists.txt."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        ndk = make_fake_ndk(Path(tmp.name))
        target = tc.resolve_android_target(ndk=str(ndk))
        from commands.build_sdk import generate_sdk_cmake
        # Keep every generated path inside the temporary directory.
        with patch.object(type(target), "cmake_root_dir",
                          lambda self: Path(tmp.name) / "cmake_root"), \
             patch.object(type(target), "install_dir",
                          lambda self: Path(tmp.name) / "prefix"), \
             patch.object(type(target), "generated_dir",
                          lambda self: Path(tmp.name) / "generated"):
            g.generated_dir = str(Path(tmp.name) / "generated")
            allowed = set(target.packages) | set(target.message_packages)
            directories = self.setup.find_project_directories(
                ["src"], tmp.name, packages_allowed=allowed
            )
            path = generate_sdk_cmake(target, directories)
        g.generated_dir = str(SCRIPT_DIR / "generated")

        text = Path(path).read_text()
        self.assertNotEqual(Path(path), SCRIPT_DIR / "CMakeLists.txt")

        added = re.findall(r'^add_subdirectory\("([^"]+)"\s', text, re.MULTILINE)
        names = {Path(p).name for p in added}
        self.assertIn("raisin_network", names)
        self.assertIn("zstd", names)
        zstd_source = str(SCRIPT_DIR / "src/raisin_third_party_common/zstd")
        self.assertIn(zstd_source, added)
        self.assertLess(added.index(zstd_source), added.index(str(self.network_cmake.parent)))
        self.assertNotIn(str(SCRIPT_DIR / "third_party"), text)
        for excluded in ("raisin_data_logger", "raisin_parameter",
                         "raisin_shared_memory", "raisin_util"):
            self.assertNotIn(excluded, names)

        # Out-of-tree sources need an explicit binary directory.
        for line in text.splitlines():
            if line.startswith("add_subdirectory("):
                self.assertEqual(len(line.rstrip(")").split()), 2, line)

        # The variant is emitted ahead of the subprojects; only CMake expands it.
        flags_at = text.index('RAISIN_CORE_VARIANT lite CACHE STRING')
        self.assertNotIn("set(RAISIN_NETWORK_ENABLE_", text)
        self.assertNotIn("set(RAISIN_THREAD_POOL_ENABLE_", text)
        first_add = text.index("add_subdirectory(")
        self.assertLess(flags_at, first_add)
        self.assertNotIn("@@", text)


    def test_dependency_order_puts_providers_first(self):
        allowed = {
            "raisin_network",
            "raisin_thread_pool",
            "raisin_compat",
            "raisin_encryption",
            "raisin_empty_encryption",
        }
        with tempfile.TemporaryDirectory() as tmp:
            directories = self.setup.find_project_directories(
                ["src"], tmp, packages_allowed=allowed
            )
        graph = self.setup.build_dependency_graph(directories)
        order = self.setup.topological_sort(graph, list(graph.keys()))
        self.assertLess(order.index("raisin_thread_pool"), order.index("raisin_network"))
        self.assertLess(order.index("raisin_compat"), order.index("raisin_thread_pool"))


class OutputIsolationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ndk = make_fake_ndk(Path(self.tmp.name))
        g.init_globals(script_directory=str(SCRIPT_DIR))
        self.target = tc.resolve_android_target(ndk=str(self.ndk))
        self.host = tc.TargetConfig.host()

    def tearDown(self):
        self.tmp.cleanup()

    def test_host_paths_keep_their_historical_locations(self):
        self.assertEqual(self.host.generated_dir(), SCRIPT_DIR / "generated")
        self.assertEqual(self.host.install_dir(), SCRIPT_DIR / "install")
        self.assertEqual(self.host.cmake_root_dir(), SCRIPT_DIR)
        self.assertEqual(self.host.build_dir(), SCRIPT_DIR / "cmake-build-release")

    def test_no_target_path_collides_with_a_host_path(self):
        # cmake_root_dir() for the host is the workspace root, which of course
        # contains everything; the host *outputs* are what must stay untouched.
        host_paths = {
            self.host.build_dir(),
            self.host.generated_dir(),
            self.host.install_dir(),
            self.host.cmake_binary_dir(),
        }
        for path in (
            self.target.build_dir(),
            self.target.generated_dir(),
            self.target.install_dir(),
            self.target.cmake_root_dir(),
            self.target.cmake_binary_dir(),
        ):
            self.assertNotIn(path, host_paths)
            for host_path in host_paths:
                self.assertFalse(
                    str(path).startswith(str(host_path) + os.sep),
                    f"{path} lives inside host output {host_path}",
                )

    def test_target_outputs_stay_inside_gitignored_roots(self):
        # cmake-*/* and sdk/ are ignored by .gitignore.
        for path in (
            self.target.build_dir(),
            self.target.generated_dir(),
            self.target.cmake_root_dir(),
        ):
            self.assertTrue(path.name.startswith("cmake-build-android-")
                            or "cmake-build-android-" in str(path))
        self.assertEqual(self.target.install_dir().relative_to(SCRIPT_DIR).parts[:2], ("sdk", "android"))
        self.assertEqual(self.target.archive_dir(), SCRIPT_DIR / "sdk/android/archives")

    def test_sdk_does_not_become_an_ota_package_provider(self):
        from commands.repo_dependency_check import _discover_binary_packages

        with patch.object(g, "script_directory", self.tmp.name):
            package = self.target.install_dir() / "lib/cmake/raisin_network"
            package.mkdir(parents=True)
            (package / "raisin_networkConfig.cmake").write_text("")
            release = Path(self.tmp.name) / "release/install"
            host_package = release / "raisin/linux/24.04/x86_64/release/lib/cmake/raisin_network"
            host_package.mkdir(parents=True)
            providers = _discover_binary_packages(release)
            self.assertEqual(providers["raisin_network"][0], "raisin")
            self.assertEqual(set(providers), {"raisin_network"})

    def test_two_targets_do_not_share_outputs(self):
        other = tc.resolve_android_target(
            ndk=str(self.ndk), abi="x86_64", api_level=26
        )
        self.assertNotEqual(self.target.build_dir(), other.build_dir())
        self.assertNotEqual(self.target.install_dir(), other.install_dir())
        self.assertNotEqual(self.target.generated_dir(), other.generated_dir())

    def test_generated_root_is_not_the_host_cmakelists(self):
        self.assertNotEqual(
            self.target.cmake_root_dir() / "CMakeLists.txt",
            SCRIPT_DIR / "CMakeLists.txt",
        )

    def test_toolchain_and_profile_variants_do_not_reuse_any_outputs(self):
        variants = [
            replace(self.target, ndk_dir=str(Path(self.tmp.name) / "other-ndk")),
            replace(self.target, ndk_version="29.0.12345678"),
            # A legacy static build must not collide even though new builds reject it.
            replace(self.target, stl="c++_static"),
            replace(self.target, profile="another-profile"),
            replace(self.target, march="armv8.2-a"),
            replace(self.target, cmake_options={**self.target.cmake_options, "EXTRA": "OFF"}),
        ]
        paths = ("build_dir", "install_dir", "generated_dir", "cache_dir", "cmake_binary_dir")
        for other in variants:
            with self.subTest(target=other):
                for method in paths:
                    self.assertNotEqual(getattr(self.target, method)(), getattr(other, method)())

    def test_configuration_id_is_independent_of_dictionary_order(self):
        other = replace(self.target, cmake_options=dict(reversed(list(self.target.cmake_options.items()))))
        self.assertEqual(self.target.configuration_id, other.configuration_id)

    def test_archiving_another_ndk_does_not_overwrite_the_first_archive(self):
        from commands.build_sdk import archive_sdk
        g.init_globals(script_directory=self.tmp.name)
        self.addCleanup(g.init_globals, script_directory=str(SCRIPT_DIR))
        first = self.target
        second = replace(first, ndk_version="29.0.12345678")
        archives = []
        for target in (first, second):
            target.install_dir().mkdir(parents=True)
            (target.install_dir() / "marker").write_text(target.ndk_version)
            archives.append(archive_sdk(target))
        self.assertNotEqual(*archives)
        self.assertTrue(all(path.is_file() for path in archives))


class SdkMetadataTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ndk = make_fake_ndk(Path(self.tmp.name))
        g.init_globals(script_directory=str(SCRIPT_DIR))
        from commands import build_sdk as sdk_module

        self.android = sdk_module
        self.target = tc.resolve_android_target(ndk=str(self.ndk))

    def tearDown(self):
        self.tmp.cleanup()

    def test_protocol_version_is_read_from_source(self):
        source = SCRIPT_DIR / self.android.PROTOCOL_SOURCE
        if not source.is_file():
            self.skipTest("src/raisin is not checked out")
        version = self.android.read_protocol_version(str(SCRIPT_DIR))
        self.assertIsInstance(version, int)
        self.assertIn(f"version_ = {version}", source.read_text())

    def test_protocol_version_failure_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(Exception) as ctx:
                self.android.read_protocol_version(tmp)
            self.assertIn("protocol version", str(ctx.exception))

    def test_metadata_records_every_setting_that_affects_abi(self):
        metadata = self.target.metadata()
        for key in ("platform", "abi", "api_level", "ndk_version", "stl",
                    "build_type", "march", "cxx_standard"):
            self.assertIn(key, metadata)

    def test_hash_tree_covers_files_and_changes_with_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lib").mkdir()
            (root / "lib" / "a.so").write_bytes(b"one")
            first = self.android.hash_tree(root)
            self.assertEqual(list(first), ["lib/a.so"])
            (root / "lib" / "a.so").write_bytes(b"two")
            self.assertNotEqual(self.android.hash_tree(root)["lib/a.so"],
                                first["lib/a.so"])

    def test_config_template_renders_without_leftovers(self):
        values = {
            "SDK_NAME": "raisin_android_sdk",
            "SDK_VERSION": "1.2.3",
            "PROTOCOL_VERSION": 1104,
            "PROFILE": "android_comm",
            "ABI": "arm64-v8a",
            "API_LEVEL": 24,
            "STL": "c++_shared",
            "NDK_VERSION": FAKE_NDK_VERSION,
            "BUILD_TYPE": "RelWithDebInfo",
            "BUNDLED_PACKAGES": "raisin_network;raisin_thread_pool",
        }
        rendered = self.android._render_template(
            "android", "raisin_android_sdk-config.cmake.in", values
        )
        self.assertIn('set(RAISIN_ANDROID_SDK_ABI "arm64-v8a")', rendered)
        self.assertIn("set(RAISIN_ANDROID_SDK_PROTOCOL_VERSION 1104)", rendered)
        # The compatibility gates a consumer relies on.
        for guard in ("ANDROID_ABI", "ANDROID_STL",
                      "RAISIN_EXPECTED_PROTOCOL_VERSION", "API"):
            self.assertIn(guard, rendered)

    def test_render_template_rejects_missing_values(self):
        with self.assertRaises(Exception) as ctx:
            self.android._render_template(
                "android", "raisin_android_sdk-config.cmake.in", {"SDK_NAME": "x"}
            )
        self.assertIn("unresolved placeholders", str(ctx.exception))


class CMakeConsumerContractTest(unittest.TestCase):
    """Exercise real CMake cache semantics through the app's native entry point.

    Tiny imported libraries avoid needing an NDK or device: these tests configure
    but do not compile. The SDK config is rendered from the production template.
    """

    def setUp(self):
        self.native = SCRIPT_DIR.parent / "raisin_android/native"
        if not shutil.which("cmake") or not (self.native / "CMakeLists.txt").is_file():
            self.skipTest("requires CMake and the sibling raisin_android checkout")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ndk = make_fake_ndk(self.root)
        self.consumer = self.root / "consumer"
        self.consumer.mkdir()
        (self.consumer / "src").mkdir()
        for name in ("raisin_jni.cpp", "idl.cpp"):
            (self.consumer / "src" / name).touch()
        self.binary = self.root / "build"
        g.init_globals(script_directory=str(SCRIPT_DIR))
        (self.consumer / "CMakeLists.txt").write_text(f'''
cmake_minimum_required(VERSION 3.22)
project(sdk_contract LANGUAGES NONE)
set(ANDROID TRUE)
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-24)
set(ANDROID_STL c++_shared CACHE STRING "")
set(CMAKE_ANDROID_NDK "{self.ndk.as_posix()}")
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
include("{(self.native / 'CMakeLists.txt').as_posix()}")
get_target_property(_network raisin_network IMPORTED_LOCATION)
get_target_property(_pool raisin_thread_pool IMPORTED_LOCATION)
file(WRITE "${{CMAKE_BINARY_DIR}}/selected.txt" "${{_network}}\\n${{_pool}}\\n")
''')

    def sdk(self, name, protocol=1104, ndk_version=FAKE_NDK_VERSION, stl="c++_shared"):
        from commands.build_sdk import _render_template
        prefix = self.root / name
        (prefix / "lib").mkdir(parents=True)
        (prefix / "include").mkdir()
        for package in ("raisin_network", "raisin_thread_pool"):
            directory = prefix / "lib/cmake" / package
            directory.mkdir(parents=True)
            (prefix / "lib" / f"lib{package}.so").write_bytes(b"")
            dependencies = (
                "find_package(raisin_thread_pool REQUIRED CONFIG)\n"
                if package == "raisin_network" else ""
            )
            (directory / f"{package}Config.cmake").write_text(dependencies + f'''
get_filename_component(_prefix "${{CMAKE_CURRENT_LIST_DIR}}/../../.." ABSOLUTE)
add_library({package} SHARED IMPORTED)
set_target_properties({package} PROPERTIES
    IMPORTED_LOCATION "${{_prefix}}/lib/lib{package}.so"
    INTERFACE_INCLUDE_DIRECTORIES "${{_prefix}}/include")
''')
        directory = prefix / "lib/cmake/raisin_android_sdk"
        directory.mkdir()
        values = {
            "SDK_NAME": "raisin_android_sdk", "SDK_VERSION": "1.0.0",
            "PROTOCOL_VERSION": protocol, "PROFILE": "android_comm",
            "ABI": "arm64-v8a", "API_LEVEL": 24, "STL": stl,
            "NDK_VERSION": ndk_version, "BUILD_TYPE": "RelWithDebInfo",
            "BUNDLED_PACKAGES": "raisin_network;raisin_thread_pool",
        }
        (directory / "raisin_android_sdkConfig.cmake").write_text(
            _render_template("android", "raisin_android_sdk-config.cmake.in", values)
        )
        return prefix

    def configure(self, sdk, success=True, extra=()):
        result = subprocess.run(
            ["cmake", "-S", str(self.consumer), "-B", str(self.binary),
             f"-DRAISIN_ANDROID_SDK_DIR={sdk}", *extra],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result.stdout

    def test_switching_sdk_replaces_umbrella_and_transitive_cached_paths(self):
        first, second = self.sdk("sdk-a"), self.sdk("sdk-b")
        self.configure(first)
        self.configure(second)
        locations = (self.binary / "selected.txt").read_text().splitlines()
        self.assertEqual(locations, [
            str(second / "lib/libraisin_network.so"),
            str(second / "lib/libraisin_thread_pool.so"),
        ])

    def test_switching_to_incompatible_protocol_is_not_masked_by_cache(self):
        self.configure(self.sdk("sdk-a"))
        output = self.configure(self.sdk("sdk-b", protocol=9999), success=False)
        self.assertIn("speaks raisin protocol 9999", output)

    def test_missing_dependency_in_new_sdk_cannot_fall_back_to_old_sdk(self):
        self.configure(self.sdk("sdk-a"))
        second = self.sdk("sdk-b")
        (second / "lib/cmake/raisin_thread_pool/raisin_thread_poolConfig.cmake").unlink()
        output = self.configure(second, success=False)
        self.assertIn("Incomplete Raisin SDK", output)

    def test_ndk_revision_mismatch_is_rejected(self):
        output = self.configure(self.sdk("sdk", ndk_version="29.0.12345678"), success=False)
        self.assertIn("requires NDK 29.0.12345678", output)
        self.assertIn(FAKE_NDK_VERSION, output)

    def test_consumer_without_ndk_revision_is_rejected(self):
        (self.ndk / "source.properties").unlink()
        output = self.configure(self.sdk("sdk"), success=False)
        self.assertIn("cannot determine the consumer NDK revision", output)

    def test_static_consumer_is_rejected_after_shared_configure(self):
        sdk = self.sdk("sdk")
        self.configure(sdk)
        output = self.configure(sdk, success=False, extra=["-DANDROID_STL=c++_static"])
        self.assertIn("build uses 'c++_static'", output)

    def test_legacy_static_sdk_is_rejected(self):
        output = self.configure(self.sdk("sdk", stl="c++_static"), success=False)
        self.assertIn("multiple shared libraries", output)


class InstalledSdkTest(unittest.TestCase):
    """Checks against a real installed SDK, when one is present."""

    def setUp(self):
        g.init_globals(script_directory=str(SCRIPT_DIR))
        prefix = os.environ.get("RAISIN_ANDROID_SDK", "")
        if not prefix or not (Path(prefix) / "raisin_sdk.json").is_file():
            self.skipTest("no installed SDK (set RAISIN_ANDROID_SDK)")
        self.prefix = Path(prefix)
        self.metadata = json.loads((self.prefix / "raisin_sdk.json").read_text())

    def test_metadata_has_the_full_contract(self):
        for key in ("sdk", "protocol_version", "target", "features", "packages",
                    "message_packages", "sources", "files"):
            self.assertIn(key, self.metadata)
        for info in self.metadata["sources"].values():
            self.assertIn("commit", info)
            self.assertIn("dirty", info)

    def test_recorded_hashes_still_match(self):
        recorded = self.metadata["files"]
        actual = self.android_hashes()
        mismatched = [k for k, v in recorded.items() if actual.get(k) != v]
        self.assertEqual(mismatched, [], "SDK contents changed after packaging")

    def android_hashes(self):
        from commands import build_sdk as sdk_module

        return sdk_module.hash_tree(self.prefix)

    def test_metadata_does_not_hash_itself(self):
        self.assertNotIn("raisin_sdk.json", self.metadata["files"])

    def test_idl_layout_matches_what_the_app_mounts_as_assets(self):
        # RaisinClient.copyMessageDefinitions() walks assets/messages/...
        messages = self.prefix / "idl" / "messages"
        self.assertTrue(messages.is_dir())
        for package in self.metadata["message_packages"]:
            self.assertTrue((messages / package).is_dir(), package)

    def test_shipped_libraries_are_present_for_the_declared_abi(self):
        abi = self.metadata["target"]["abi"]
        jni = self.prefix / "jniLibs" / abi
        self.assertTrue(jni.is_dir())
        self.assertTrue(list(jni.glob("*.so")))
        for library in (self.prefix / "lib").glob("*.so"):
            self.assertTrue((jni / library.name).is_file(), library.name)

    def test_sdk_is_relocatable(self):
        # Nothing in the SDK may point back into the workspace that built it.
        offenders = []
        for path in self.prefix.rglob("*"):
            if not path.is_file() or path.suffix not in (".cmake", ".json", ".txt"):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if str(SCRIPT_DIR) in text and path.name != "raisin_sdk.json":
                offenders.append(str(path.relative_to(self.prefix)))
        self.assertEqual(offenders, [], "SDK references its build workspace")

    def test_profile_metadata_and_exported_features(self):
        profile = tc.load_profiles()[self.metadata["target"]["profile"]]
        expected = {
            k: (v if k == tc.CORE_VARIANT_OPTION else
                ("ON" if str(v).upper() in ("ON", "TRUE", "1") else "OFF"))
            for k, v in profile["cmake_options"].items()
        }
        self.assertEqual(self.metadata["features"], expected)
        # The exported targets supply macros to consumers without a separate feature file.
        definitions = {}
        for package in ("raisin_network", "raisin_thread_pool"):
            export = self.prefix / f"lib/cmake/{package}/{package}Targets.cmake"
            for key, value in re.findall(
                    r'(RAISIN_(?:NETWORK|THREAD_POOL)_ENABLE_[A-Z_]+)=\\?\$<BOOL:(ON|OFF)>',
                    export.read_text()):
                definitions[key] = value
        self.assertEqual(len(definitions), 10)
        self.assertEqual(set(definitions.values()), {"OFF"})



if __name__ == "__main__":
    unittest.main(verbosity=2)
