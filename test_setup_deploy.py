"""What `raisin setup` still decides itself when it deploys installed packages.

The copy moved to `raisin_ota.runtime_prefix`. What a source build needs stays
in setup: a package with a checkout in src/ is built rather than deployed, and
each deployed package's generated headers are collected for that build.
"""

import sys
import tempfile
import unittest
import zipfile
from contextlib import chdir
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from commands import globals as g  # noqa: E402
from commands import setup as cli_setup  # noqa: E402


class TestSetupDeploy(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        for name, value in (
            ("vcpkg_dependencies", set()),
            ("os_type", "ubuntu"),
            ("os_version", "24.04"),
            ("architecture", "x86_64"),
            ("script_directory", str(self.root)),
            ("generated_dir", str(self.root / "generated")),
        ):
            self.addCleanup(setattr, g, name, getattr(g, name))
            setattr(g, name, value)
        self.ignored = set()
        patcher = patch.object(
            cli_setup, "get_repos_to_ignore", side_effect=lambda: self.ignored
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def an_installed_package(self, name, files):
        d = (
            self.root / "release" / "install" / name
            / g.os_type / g.os_version / g.architecture / "release"
        )
        for relative, content in files.items():
            path = d / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def a_src_checkout(self, name):
        (self.root / "src" / name).mkdir(parents=True)

    def test_a_package_with_a_src_checkout_is_not_deployed(self):
        self.an_installed_package("raisin", {"lib/libraisin.so": "binary"})
        self.an_installed_package("raisin_gui", {"lib/libgui.so": "binary"})
        self.a_src_checkout("raisin_gui")

        cli_setup.deploy_install_packages()

        self.assertTrue((self.root / "install" / "lib" / "libraisin.so").exists())
        self.assertFalse((self.root / "install" / "lib" / "libgui.so").exists())

    def test_a_src_checkout_of_an_ignored_repo_does_not_stop_the_deploy(self):
        self.an_installed_package("raisin_gui", {"lib/libgui.so": "binary"})
        self.a_src_checkout("raisin_gui")
        self.ignored = {"raisin_gui"}

        cli_setup.deploy_install_packages()

        self.assertTrue((self.root / "install" / "lib" / "libgui.so").exists())

    def test_generated_headers_of_a_deployed_package_are_collected(self):
        self.an_installed_package(
            "raisin", {"generated/include/raisin/msg/pose.hpp": "header"}
        )

        cli_setup.deploy_install_packages()

        self.assertEqual(
            (self.root / "generated" / "include" / "raisin" / "msg" / "pose.hpp")
            .read_text(encoding="utf-8"),
            "header",
        )

    def test_a_copy_that_fails_stops_setup(self):
        # It used to print the error and carry on, leaving install/ without the
        # rest of the packages and setup reporting success.
        self.an_installed_package("raisin", {"lib/libraisin.so": "binary"})
        (self.root / "install").mkdir()
        (self.root / "install" / "lib").write_text("a file", encoding="utf-8")

        with self.assertRaises(OSError):
            cli_setup.deploy_install_packages()

    def test_package_publish_includes_interfaces_from_its_ignored_source_repo(self):
        source_repo = self.root / "src" / "raisin_ros2_messages"
        imu = source_repo / "messages" / "sensor_msgs" / "msg" / "Imu.msg"
        imu.parent.mkdir(parents=True)
        imu.write_text("float32 angular_velocity_x\n", encoding="utf-8")
        action = source_repo / "messages" / "sensor_msgs" / "action" / "Inspect.action"
        action.parent.mkdir(parents=True)
        action.write_text(
            "string frame\n---\nbool success\n---\nfloat32 progress\n",
            encoding="utf-8",
        )
        unrelated_repo = self.root / "src" / "ignored_dependency"
        unrelated = unrelated_repo / "messages" / "other_msgs" / "msg" / "MustNotShip.msg"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text("int32 value\n", encoding="utf-8")
        stale_temp = self.root / "temp" / "stale_action_package" / "msg" / "Stale.msg"
        stale_temp.parent.mkdir(parents=True)
        stale_temp.write_text("uint8 value\n", encoding="utf-8")

        templates = Path(__file__).parent / "templates"
        (self.root / "templates").mkdir()
        for name in (
            "ActionTemplate.hpp", "MessageTemplate.hpp", "ServiceTemplate.hpp",
            "raisin_serialization_base.hpp",
        ):
            (self.root / "templates" / name).write_bytes((templates / name).read_bytes())
        # The unrelated repo is active: package publishing must still scope
        # interfaces to the selected package's own source repository.
        self.ignored = {"raisin_ros2_messages"}
        (self.root / "configuration_setting.yaml").write_text(
            "user_type: devel\npackages_to_ignore: []\nrepos_to_ignore: []\n",
            encoding="utf-8",
        )

        with patch.object(cli_setup, "check_supported_architecture"), \
                patch.object(cli_setup, "guard_src_repo_lfs_assets"), \
                patch.object(cli_setup, "deploy_install_packages"), \
                patch.object(cli_setup, "guard_src_repo_release_yaml_dependencies"), \
                patch.object(cli_setup, "build_pure_cmake_projects", return_value=[]), \
                patch.object(cli_setup, "update_cmake_file"), \
                patch.object(cli_setup, "get_commit_hash", return_value=None), \
                patch.object(cli_setup, "collect_src_vcpkg_dependencies"), \
                patch.object(cli_setup, "generate_vcpkg_json"):
            with chdir(self.root):
                projects = cli_setup.setup(
                    package_name="raisin_ros2_messages", build_type="release"
                )

        packaged = (
            self.root / "release" / "install" / "raisin_ros2_messages" / "ubuntu"
            / "24.04" / "x86_64" / "release" / "messages" / "sensor_msgs" / "msg" / "Imu.msg"
        )
        self.assertEqual(packaged.read_text(encoding="utf-8"), "float32 angular_velocity_x\n")
        generated_action_msg = packaged.parents[0] / "InspectGoal.msg"
        self.assertEqual(
            generated_action_msg.read_text(encoding="utf-8"),
            "string frame",
        )
        self.assertEqual(projects, [])
        unrelated_output = packaged.parents[2] / "other_msgs" / "msg" / "MustNotShip.msg"
        self.assertFalse(unrelated_output.exists())

        from commands.publish import _create_archive

        archive = _create_archive(
            "raisin_ros2_messages", "0.1.2", "release",
            {
                "install_dir": packaged.parents[3],
                "release_dir": self.root / "archives",
            },
        )
        with zipfile.ZipFile(archive) as published:
            self.assertIn("messages/sensor_msgs/msg/Imu.msg", published.namelist())
            self.assertIn("messages/sensor_msgs/msg/InspectGoal.msg", published.namelist())
            self.assertNotIn(
                "messages/other_msgs/msg/MustNotShip.msg", published.namelist()
            )
            self.assertNotIn(
                "messages/stale_action_package/msg/Stale.msg", published.namelist()
            )


if __name__ == "__main__":
    unittest.main()
