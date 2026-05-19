#!/usr/bin/env python3
"""
Tests for publish artifact pruning.
"""

import tempfile
import unittest
from pathlib import Path

from commands import globals as g
from commands.publish import (
    _discover_target_package_names,
    _get_missing_publish_dependencies,
    _get_publish_cmake_prefix_path,
    _prune_non_target_publish_artifacts,
)


class TestPublishArtifactPruning(unittest.TestCase):
    def test_discovers_target_cmake_and_interface_package_names(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = Path(tmpdir) / "src" / "target_repo"
            (target_dir / "library_pkg").mkdir(parents=True)
            (target_dir / "library_pkg" / "CMakeLists.txt").write_text(
                "project(library_pkg)\n",
                encoding="utf-8",
            )
            (target_dir / "interface_pkg" / "msg").mkdir(parents=True)
            (target_dir / "interface_pkg" / "msg" / "Thing.msg").write_text(
                "string data\n",
                encoding="utf-8",
            )

            package_names = _discover_target_package_names(target_dir)

        self.assertIn("library_pkg", package_names)
        self.assertIn("interface_pkg", package_names)
        self.assertNotIn("target_repo", package_names)

    def test_discovers_interfaces_below_repo_root_cmake(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = Path(tmpdir) / "src" / "target_repo"
            target_dir.mkdir(parents=True)
            (target_dir / "CMakeLists.txt").write_text(
                "project(target_repo)\n",
                encoding="utf-8",
            )
            (target_dir / "std_msgs" / "msg").mkdir(parents=True)
            (target_dir / "std_msgs" / "msg" / "Header.msg").write_text(
                "string frame_id\n",
                encoding="utf-8",
            )

            package_names = _discover_target_package_names(target_dir)

        self.assertIn("target_repo", package_names)
        self.assertIn("std_msgs", package_names)

    def test_prunes_known_non_target_artifacts_from_publish_install(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target_dir = root / "src" / "target_repo"
            (target_dir / "my_pkg" / "msg").mkdir(parents=True)
            (target_dir / "my_pkg" / "msg" / "Thing.msg").write_text(
                "string data\n",
                encoding="utf-8",
            )
            (target_dir / "my_lib").mkdir(parents=True)
            (target_dir / "my_lib" / "CMakeLists.txt").write_text(
                "project(my_lib)\n",
                encoding="utf-8",
            )
            other_repo = root / "src" / "other_repo"
            (other_repo / "dependency_lib").mkdir(parents=True)
            (other_repo / "dependency_lib" / "CMakeLists.txt").write_text(
                "project(dependency_lib)\n",
                encoding="utf-8",
            )

            install_dir = root / "release" / "install" / "target_repo"
            for rel_root in ("messages", "generated/include", "include"):
                (install_dir / rel_root / "my_pkg").mkdir(parents=True)
                (install_dir / rel_root / "std_msgs").mkdir(parents=True)
            (install_dir / "include" / "my_lib").mkdir(parents=True)
            (install_dir / "include" / "dependency_lib").mkdir(parents=True)
            (install_dir / "include" / "external_runtime_headers").mkdir(parents=True)
            (install_dir / "include" / "raisin_serialization_base.hpp").write_text(
                "// keep root files\n",
                encoding="utf-8",
            )

            _prune_non_target_publish_artifacts(target_dir, install_dir)

            self.assertTrue((install_dir / "messages" / "my_pkg").is_dir())
            self.assertTrue((install_dir / "generated" / "include" / "my_pkg").is_dir())
            self.assertTrue((install_dir / "include" / "my_pkg").is_dir())
            self.assertTrue((install_dir / "include" / "my_lib").is_dir())
            self.assertTrue(
                (install_dir / "include" / "external_runtime_headers").is_dir()
            )
            self.assertTrue(
                (install_dir / "include" / "raisin_serialization_base.hpp").is_file()
            )
            self.assertFalse((install_dir / "messages" / "std_msgs").exists())
            self.assertFalse(
                (install_dir / "generated" / "include" / "std_msgs").exists()
            )
            self.assertFalse((install_dir / "include" / "std_msgs").exists())
            self.assertFalse((install_dir / "include" / "dependency_lib").exists())

    def test_publish_cmake_prefix_path_includes_installed_dependencies(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            old_values = (
                g.script_directory,
                g.os_type,
                g.os_version,
                g.architecture,
            )
            g.script_directory = str(root)
            g.os_type = "ubuntu"
            g.os_version = "24.04"
            g.architecture = "x86_64"
            try:
                target_install = (
                    root
                    / "release"
                    / "install"
                    / "target_repo"
                    / "ubuntu"
                    / "24.04"
                    / "x86_64"
                    / "release"
                )
                dependency_install = (
                    root
                    / "release"
                    / "install"
                    / "dependency_repo"
                    / "ubuntu"
                    / "24.04"
                    / "x86_64"
                    / "release"
                )
                stale_target_install = (
                    root
                    / "release"
                    / "install"
                    / "target_repo"
                    / "ubuntu"
                    / "24.04"
                    / "x86_64"
                    / "debug"
                )
                dependency_install.mkdir(parents=True)
                stale_target_install.mkdir(parents=True)

                prefix_path = _get_publish_cmake_prefix_path(
                    "target_repo",
                    "release",
                    target_install,
                ).split(";")

            finally:
                (
                    g.script_directory,
                    g.os_type,
                    g.os_version,
                    g.architecture,
                ) = old_values

        self.assertEqual(str(root / "install"), prefix_path[0])
        self.assertEqual(str(target_install), prefix_path[1])
        self.assertIn(str(dependency_install), prefix_path)
        self.assertNotIn(str(stale_target_install), prefix_path)

    def test_missing_publish_dependencies_require_release_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            old_values = (
                g.script_directory,
                g.os_type,
                g.os_version,
                g.architecture,
            )
            g.script_directory = str(root)
            g.os_type = "ubuntu"
            g.os_version = "24.04"
            g.architecture = "x86_64"
            try:
                dependency_install = (
                    root
                    / "release"
                    / "install"
                    / "dependency_repo"
                    / "ubuntu"
                    / "24.04"
                    / "x86_64"
                    / "release"
                )
                dependency_install.mkdir(parents=True)

                missing_before = _get_missing_publish_dependencies(
                    {"dependencies": ["dependency_repo>=1.0.0"]},
                    "release",
                )
                (dependency_install / "release.yaml").write_text(
                    "version: 1.0.0\n",
                    encoding="utf-8",
                )
                missing_after = _get_missing_publish_dependencies(
                    {"dependencies": ["dependency_repo>=1.0.0"]},
                    "release",
                )

            finally:
                (
                    g.script_directory,
                    g.os_type,
                    g.os_version,
                    g.architecture,
                ) = old_values

        self.assertEqual(1, len(missing_before))
        self.assertEqual("dependency_repo>=1.0.0", missing_before[0][0])
        self.assertEqual([], missing_after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
