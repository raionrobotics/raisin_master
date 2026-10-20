"""Tests for symlinking each package's config/ into install/ instead of copying it."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

from commands import globals as g  # noqa: E402
from commands import setup as raisin_setup  # noqa: E402
from commands import build as build_module  # noqa: E402


class SymlinkConfigTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        g.init_globals(script_directory=str(self.root))
        self.addCleanup(g.init_globals, script_directory=str(SCRIPT_DIR))

        self.pkg = self.root / "src" / "repo" / "pkg"
        (self.pkg / "config").mkdir(parents=True)
        (self.pkg / "config" / "params.yaml").write_text("gain: 1\n", encoding="utf-8")
        (self.pkg / "resource").mkdir()
        (self.pkg / "resource" / "model.urdf").write_text("<robot/>\n", encoding="utf-8")
        (self.pkg / "scripts").mkdir()
        (self.pkg / "scripts" / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (self.pkg / "CMakeLists.txt").write_text("project(pkg)\n", encoding="utf-8")

        self.installed = self.root / "install" / "config" / "pkg" / "config"

    def _find(self, symlink_config):
        return raisin_setup.find_project_directories(
            ["src"], "install", symlink_config=symlink_config
        )


class TestFindProjectDirectories(SymlinkConfigTestCase):
    def test_config_is_a_relative_link_to_the_source(self):
        self._find(symlink_config=True)

        self.assertTrue(self.installed.is_symlink())
        self.assertFalse(os.path.isabs(os.readlink(self.installed)))
        self.assertEqual(self.installed.resolve(), (self.pkg / "config").resolve())

    def test_a_source_edit_is_visible_through_install(self):
        self._find(symlink_config=True)

        (self.pkg / "config" / "params.yaml").write_text("gain: 2\n", encoding="utf-8")
        (self.pkg / "config" / "new.yaml").write_text("x: 1\n", encoding="utf-8")

        self.assertEqual((self.installed / "params.yaml").read_text(encoding="utf-8"), "gain: 2\n")
        self.assertTrue((self.installed / "new.yaml").is_file())

    def test_copy_mode_keeps_a_real_directory(self):
        self._find(symlink_config=False)

        self.assertFalse(self.installed.is_symlink())
        self.assertTrue((self.installed / "params.yaml").is_file())

    def test_resource_and_scripts_are_still_copied(self):
        self._find(symlink_config=True)

        for kind in ("resource", "scripts"):
            installed = self.root / "install" / kind / "pkg" / kind
            self.assertFalse(installed.is_symlink(), kind)
            self.assertTrue(installed.is_dir(), kind)

    def test_an_existing_directory_is_merged_into_not_replaced(self):
        self.installed.mkdir(parents=True)
        (self.installed / "deployed.yaml").write_text("a: 1\n", encoding="utf-8")

        self._find(symlink_config=True)

        self.assertFalse(self.installed.is_symlink())
        self.assertTrue((self.installed / "deployed.yaml").is_file())
        self.assertTrue((self.installed / "params.yaml").is_file())

    def test_same_named_packages_never_write_into_each_others_source(self):
        twin = self.root / "src" / "other_repo" / "pkg"
        (twin / "config").mkdir(parents=True)
        (twin / "config" / "params.yaml").write_text("gain: 9\n", encoding="utf-8")
        (twin / "CMakeLists.txt").write_text("project(pkg)\n", encoding="utf-8")

        self._find(symlink_config=True)

        self.assertFalse(self.installed.is_symlink())
        self.assertEqual((self.pkg / "config" / "params.yaml").read_text(encoding="utf-8"), "gain: 1\n")
        self.assertEqual((twin / "config" / "params.yaml").read_text(encoding="utf-8"), "gain: 9\n")
        self.assertEqual(sorted(os.listdir(self.pkg / "config")), ["params.yaml"])
        self.assertEqual(sorted(os.listdir(twin / "config")), ["params.yaml"])

    def test_a_refused_symlink_falls_back_to_a_copy(self):
        with patch.object(raisin_setup.os, "symlink", side_effect=OSError("not permitted")):
            self._find(symlink_config=True)

        self.assertFalse(self.installed.is_symlink())
        self.assertTrue((self.installed / "params.yaml").is_file())

    def test_wiping_install_leaves_the_source_config(self):
        self._find(symlink_config=True)

        raisin_setup.delete_directory(self.root / "install")

        self.assertTrue((self.pkg / "config" / "params.yaml").is_file())


class _StopSetup(Exception):
    pass


class TestSetupScope(SymlinkConfigTestCase):
    def _symlink_config_passed(self, **kwargs):
        seen = {}

        def fake_find(*args, **find_kwargs):
            seen.update(find_kwargs)
            raise _StopSetup

        stubs = [
            "check_supported_architecture",
            "get_packages_to_ignore",
            "get_repos_to_ignore",
            "guard_src_repo_lfs_assets",
            "setup_source_repositories",
            "deploy_install_packages",
            "guard_src_repo_release_yaml_dependencies",
            "build_pure_cmake_projects",
            "_print_ignore_lists",
        ]
        patches = [patch.object(raisin_setup, name, return_value=[]) for name in stubs]
        patches.append(patch.object(raisin_setup, "find_interface_files", return_value=[[]]))
        patches.append(patch.object(raisin_setup, "find_project_directories", side_effect=fake_find))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

        with self.assertRaises(_StopSetup):
            raisin_setup.setup(raisin_march="x86-64-v2", **kwargs)
        return seen["symlink_config"]

    def test_workspace_install_links(self):
        self.assertTrue(self._symlink_config_passed(symlink_config=True))

    def test_default_copies(self):
        self.assertFalse(self._symlink_config_passed())

    def test_package_install_copies(self):
        self.assertFalse(
            self._symlink_config_passed(symlink_config=True, package_name="pkg", build_type="release")
        )


class TestCommandLine(unittest.TestCase):
    def _symlink_config_from(self, command, args):
        with patch.object(raisin_setup, "setup") as setup, \
                patch.object(raisin_setup, "process_build_targets"), \
                patch.object(build_module, "build_command"):
            result = CliRunner().invoke(command, args)
        self.assertEqual(result.exit_code, 0, result.output)
        return setup.call_args.kwargs["symlink_config"]

    def test_build_links_by_default(self):
        self.assertTrue(self._symlink_config_from(build_module.build_cli_command, ["-t", "debug", "-i"]))

    def test_build_copy_config_copies(self):
        self.assertFalse(
            self._symlink_config_from(build_module.build_cli_command, ["-t", "debug", "--copy-config"])
        )

    def test_setup_links_by_default(self):
        self.assertTrue(self._symlink_config_from(raisin_setup.setup_command, []))

    def test_setup_copy_config_copies(self):
        self.assertFalse(self._symlink_config_from(raisin_setup.setup_command, ["--copy-config"]))


if __name__ == "__main__":
    unittest.main()
