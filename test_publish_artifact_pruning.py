#!/usr/bin/env python3
"""
Tests for publish artifact pruning.
"""

import tempfile
import unittest
from pathlib import Path

from commands.publish import (
    _discover_target_package_names,
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
