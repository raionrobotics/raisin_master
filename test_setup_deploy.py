"""What `raisin setup` still decides itself when it deploys installed packages.

The copy moved to `raisin_ota.runtime_prefix`. What a source build needs stays
in setup: a package with a checkout in src/ is built rather than deployed, and
each deployed package's generated headers are collected for that build.
"""

import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
