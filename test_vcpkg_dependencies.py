"""What a package declares as a vcpkg dependency has to reach vcpkg.json."""

import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import yaml  # noqa: E402

from commands import globals as g  # noqa: E402
from commands import setup as cli_setup  # noqa: E402


class TestDeclaredVcpkgDependenciesAreRead(unittest.TestCase):
    """The key in the file is `vcpkg_dependencies`; the code asked for another.

    `release_data.get("g.vcpkg_dependencies")` — the `g.` prefix belongs to the
    Python variable the value is merged into, not to the YAML key. Nothing ever
    matched, so every declaration was silently dropped and the generated
    `vcpkg.json` was always `"dependencies": []`.

    Not hypothetical: the packages in this repo declare, between them,
    `[asio, yasm, curl, zstd]`, `[geographiclib, nlohmann-json]`,
    `[sdl2, boost-system, pcl]` and more. Whatever satisfies those libraries on
    a working machine today, it is not this mechanism.
    """

    def setUp(self):
        self._previous = set(g.vcpkg_dependencies)
        g.vcpkg_dependencies = set()
        self.addCleanup(setattr, g, "vcpkg_dependencies", self._previous)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.src = Path(self._tmp.name) / "src"
        self.src.mkdir(parents=True)

    def a_package_declaring(self, name, dependencies):
        project = self.src / name
        project.mkdir()
        (project / "release.yaml").write_text(
            yaml.safe_dump({"vcpkg_dependencies": list(dependencies)}),
            encoding="utf-8",
        )

    def collect(self):
        previous = g.script_directory
        g.script_directory = str(self._tmp.name)
        try:
            cli_setup.collect_src_vcpkg_dependencies()
        finally:
            g.script_directory = previous
        return g.vcpkg_dependencies

    def test_what_a_package_declares_is_collected(self):
        self.a_package_declaring("raisin", ["asio", "curl"])

        self.assertEqual(self.collect(), {"asio", "curl"})

    def test_declarations_from_several_packages_are_merged(self):
        self.a_package_declaring("raisin", ["asio"])
        self.a_package_declaring("raisin_gui", ["sdl2", "pcl"])

        self.assertEqual(self.collect(), {"asio", "sdl2", "pcl"})

    def test_a_package_declaring_nothing_contributes_nothing(self):
        self.a_package_declaring("raisin", [])

        self.assertEqual(self.collect(), set())


class TestDeployAlsoReadsThem(unittest.TestCase):
    """The other call site, and the one nearer a robot.

    `collect_src_vcpkg_dependencies` walks `src/`, which is empty on a machine
    that installs from archives. `deploy_install_packages` walks
    `release/install`, which is where an archive's packages land — so this is
    the reader that matters where there are no sources.

    It had the same wrong key, and a mutation run found it uncovered: reverting
    just this one left every test green. The fix was made in both places at
    once, which is exactly the situation where a single test lets half a fix
    look whole.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        # Set rather than inherited: the platform decides the directory this
        # walks, and a test that reads it from whatever the process happens to
        # hold builds its fixture somewhere the code will not look.
        for name, value in (
            ("vcpkg_dependencies", set()),
            ("os_type", "ubuntu"),
            ("os_version", "24.04"),
            ("architecture", "x86_64"),
        ):
            self.addCleanup(setattr, g, name, getattr(g, name))
            setattr(g, name, value)

        # `get_repos_to_ignore` reads `configuration_setting.yaml` and exits the
        # process when `user_type` is missing. Nothing about which packages to
        # skip is what these tests are asking, and a test that needs a config
        # file in the working directory answers a question about the working
        # directory instead.
        patcher = patch.object(cli_setup, "get_repos_to_ignore", return_value=set())
        patcher.start()
        self.addCleanup(patcher.stop)

    def an_installed_package_declaring(self, name, dependencies):
        """Where an archive puts a package: install/<pkg>/<os>/<ver>/<arch>/<build>."""
        d = (
            self.root
            / "release"
            / "install"
            / name
            / g.os_type
            / g.os_version
            / g.architecture
            / "release"
        )
        d.mkdir(parents=True)
        (d / "release.yaml").write_text(
            yaml.safe_dump({"vcpkg_dependencies": list(dependencies)}),
            encoding="utf-8",
        )

    def deploy(self):
        previous = g.script_directory
        g.script_directory = str(self.root)
        try:
            cli_setup.deploy_install_packages()
        finally:
            g.script_directory = previous
        return g.vcpkg_dependencies

    def test_what_a_deployed_package_declares_is_collected(self):
        self.an_installed_package_declaring("raisin_raibo2", ["eigen3", "opencv"])

        self.assertEqual(self.deploy(), {"eigen3", "opencv"})

    def test_several_deployed_packages_are_merged(self):
        self.an_installed_package_declaring("raisin_raibo2", ["eigen3"])
        self.an_installed_package_declaring("raisin_gui", ["sdl2"])

        self.assertEqual(self.deploy(), {"eigen3", "sdl2"})


if __name__ == "__main__":
    unittest.main()
