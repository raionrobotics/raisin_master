"""Tests for assembling the runtime prefix out of delivered packages.

    release/install/<pkg>/<os>/<os_version>/<arch>/<build_type>/   delivered
    install/                                                       what runs

The OTA agent calls `assemble`; `raisin setup` calls the pieces. The case that
motivated the module is `test_a_leftover_src_changes_nothing`: a robot with a
`src/` checkout failed its OTA install inside setup's source guard.
"""

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from raisin_ota import runtime_prefix  # noqa: E402
from raisin_ota.client import OtaContext  # noqa: E402


class RuntimePrefixTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workspace = Path(self._tmp.name) / "raisin_ws"
        self.home = Path(self._tmp.name) / "home"
        self.workspace.mkdir()
        self.home.mkdir()
        self.context = OtaContext(
            workspace=self.workspace,
            os_type="ubuntu",
            os_version="24.04",
            architecture="arm64",
        )
        self.prefix = self.workspace / "install"

    def a_delivered_package(self, name, files, build_type="release", platform=None):
        os_type, os_version, arch = platform or ("ubuntu", "24.04", "arm64")
        root = (
            self.workspace / "release" / "install" / name
            / os_type / os_version / arch / build_type
        )
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return root

    def a_device_resource(self, name, files):
        root = self.home / ".raisin" / name / "resource"
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def read(self, relative):
        return (self.prefix / relative).read_text(encoding="utf-8")


class TestDeployPackages(RuntimePrefixTestCase):
    def test_every_package_for_this_platform_is_merged_into_the_prefix(self):
        self.a_delivered_package("raisin", {"lib/libraisin.so": "raisin"})
        self.a_delivered_package(
            "raisin_third_party_common", {"lib/libimgui.so": "imgui"}
        )

        runtime_prefix.deploy_packages(self.context, self.prefix)

        self.assertEqual(self.read("lib/libraisin.so"), "raisin")
        self.assertEqual(self.read("lib/libimgui.so"), "imgui")

    def test_build_types_of_one_package_are_merged(self):
        self.a_delivered_package("raisin", {"lib/a.so": "r"}, build_type="release")
        self.a_delivered_package("raisin", {"lib/b.so": "d"}, build_type="debug")

        runtime_prefix.deploy_packages(self.context, self.prefix)

        self.assertEqual(self.read("lib/a.so"), "r")
        self.assertEqual(self.read("lib/b.so"), "d")

    def test_a_package_for_another_platform_is_left_out(self):
        self.a_delivered_package(
            "raisin", {"lib/x86.so": "x"}, platform=("ubuntu", "24.04", "x86_64")
        )

        deployed = runtime_prefix.deploy_packages(self.context, self.prefix)

        self.assertEqual(deployed, [])
        self.assertFalse((self.prefix / "lib" / "x86.so").exists())

    def test_a_skipped_package_is_left_out(self):
        self.a_delivered_package("raisin", {"lib/libraisin.so": "raisin"})
        self.a_delivered_package("raisin_gui", {"lib/libgui.so": "gui"})

        runtime_prefix.deploy_packages(self.context, self.prefix, skip={"raisin_gui"})

        self.assertTrue((self.prefix / "lib" / "libraisin.so").exists())
        self.assertFalse((self.prefix / "lib" / "libgui.so").exists())

    def test_the_copied_package_directories_are_returned(self):
        root = self.a_delivered_package("raisin", {"lib/libraisin.so": "raisin"})

        deployed = runtime_prefix.deploy_packages(self.context, self.prefix)

        self.assertEqual(deployed, [root])

    def test_everything_under_bin_is_made_executable(self):
        self.a_delivered_package("raisin", {"bin/raisin_node": "#!/bin/sh\n"})

        runtime_prefix.deploy_packages(self.context, self.prefix)

        mode = (self.prefix / "bin" / "raisin_node").stat().st_mode
        self.assertTrue(mode & stat.S_IXUSR)

    def test_a_copy_that_fails_raises_instead_of_reporting_a_partial_prefix(self):
        # `lib` as a file where the package has a directory: the copy cannot
        # proceed, and a prefix without the package must not look deployed.
        self.a_delivered_package("raisin", {"lib/libraisin.so": "raisin"})
        self.prefix.mkdir()
        (self.prefix / "lib").write_text("not a directory", encoding="utf-8")

        with self.assertRaises(OSError):
            runtime_prefix.deploy_packages(self.context, self.prefix)


class TestMakeScriptsExecutable(RuntimePrefixTestCase):
    def test_shell_scripts_under_scripts_are_made_executable(self):
        script = self.prefix / "scripts" / "raisin" / "scripts" / "start.sh"
        script.parent.mkdir(parents=True)
        script.write_text("#!/bin/sh\n", encoding="utf-8")
        script.chmod(0o644)

        runtime_prefix.make_scripts_executable(self.prefix)

        self.assertTrue(script.stat().st_mode & stat.S_IXUSR)

    def test_a_prefix_without_scripts_is_fine(self):
        self.prefix.mkdir()

        runtime_prefix.make_scripts_executable(self.prefix)


class TestCopyDeviceResources(RuntimePrefixTestCase):
    def test_the_device_resource_replaces_the_package_default(self):
        self.prefix.mkdir()
        default = self.prefix / "resource" / "raibo2" / "resource" / "params.yaml"
        default.parent.mkdir(parents=True)
        default.write_text("from the package", encoding="utf-8")
        self.a_device_resource("raibo2", {"params.yaml": "for this device"})

        runtime_prefix.copy_device_resources(self.prefix, self.home)

        self.assertEqual(default.read_text(encoding="utf-8"), "for this device")

    def test_resources_are_read_from_the_home_passed_in(self):
        # The agent's HOME is not the workspace owner's; the caller decides.
        self.a_device_resource("raibo2", {"calibration/imu.yaml": "imu"})

        runtime_prefix.copy_device_resources(self.prefix, self.home)

        self.assertEqual(
            self.read("resource/raibo2/resource/calibration/imu.yaml"), "imu"
        )


class TestAssemble(RuntimePrefixTestCase):
    def test_a_leftover_src_changes_nothing(self):
        # A controller with a leftover src/: a checkout of a repository the
        # archive also delivers, with a package that has moved elsewhere since.
        self.a_delivered_package(
            "raisin_third_party_common", {"lib/libimgui.so": "delivered"}
        )
        self.a_delivered_package("raisin", {"lib/libraisin.so": "delivered"})
        src = self.workspace / "src"
        (src / "raisin_third_party_gui" / "imgui").mkdir(parents=True)
        (src / "raisin_third_party_gui" / "imgui" / "CMakeLists.txt").write_text(
            "project(imgui)\n", encoding="utf-8"
        )
        (src / "raisin" / "resource").mkdir(parents=True)
        (src / "raisin" / "resource" / "from_src.yaml").write_text(
            "src", encoding="utf-8"
        )

        runtime_prefix.assemble(self.context, self.home)

        self.assertEqual(self.read("lib/libimgui.so"), "delivered")
        self.assertEqual(self.read("lib/libraisin.so"), "delivered")
        self.assertEqual(
            [p for p in self.prefix.rglob("*") if "from_src" in p.name], []
        )

    def test_the_prefix_starts_empty(self):
        self.a_delivered_package("raisin", {"lib/libraisin.so": "new"})
        stale = self.prefix / "lib" / "libremoved.so"
        stale.parent.mkdir(parents=True)
        stale.write_text("from the previous version", encoding="utf-8")

        runtime_prefix.assemble(self.context, self.home)

        self.assertFalse(stale.exists())
        self.assertEqual(self.read("lib/libraisin.so"), "new")

    def test_scripts_and_device_resources_are_in_place(self):
        self.a_delivered_package(
            "raisin",
            {
                "scripts/raisin/scripts/start.sh": "#!/bin/sh\n",
                "resource/raibo2/resource/params.yaml": "default",
            },
        )
        self.a_device_resource("raibo2", {"params.yaml": "device"})

        runtime_prefix.assemble(self.context, self.home)

        script = self.prefix / "scripts" / "raisin" / "scripts" / "start.sh"
        self.assertTrue(script.stat().st_mode & stat.S_IXUSR)
        self.assertEqual(self.read("resource/raibo2/resource/params.yaml"), "device")

    def test_the_workspace_generated_tree_is_not_touched(self):
        # Generated headers are a compiler's concern; a robot runs without them.
        generated = self.workspace / "generated" / "include" / "kept.hpp"
        generated.parent.mkdir(parents=True)
        generated.write_text("kept", encoding="utf-8")

        runtime_prefix.assemble(self.context, self.home)

        self.assertEqual(generated.read_text(encoding="utf-8"), "kept")

    def test_nothing_delivered_leaves_an_empty_prefix(self):
        deployed = runtime_prefix.assemble(self.context, self.home)

        self.assertEqual(deployed, [])
        self.assertEqual(os.listdir(self.prefix), [])


if __name__ == "__main__":
    unittest.main()
