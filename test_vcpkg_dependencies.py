"""What a package declares as a vcpkg dependency has to reach vcpkg.json."""

import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
