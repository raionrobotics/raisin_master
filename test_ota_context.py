"""The OTA core must be usable without the CLI's process globals.

`commands.globals` is populated by `init_environment` at CLI startup. An agent
has no CLI, needs different values per deployment, and must not import a module
whose contract is "the CLI filled this in". These tests pin the boundary.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import commands.ota_client as ota  # noqa: E402


class TestOtaContext(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self._saved = ota._context
        ota.configure(
            ota.OtaContext(
                workspace=self.workspace,
                os_type="ubuntu",
                os_version="24.04",
                architecture="arm64",
            )
        )

    def tearDown(self):
        ota._context = self._saved
        self._tmp.cleanup()

    def test_platform_string_is_derived_from_the_context(self):
        self.assertEqual(ota._ctx().platform, "ubuntu-24.04-arm64")

    def test_package_dir_lays_out_the_platform_segments(self):
        base = Path("/release/install")

        result = ota._ctx().package_dir(base, "raisin", "release")

        self.assertEqual(
            result, base / "raisin" / "ubuntu" / "24.04" / "arm64" / "release"
        )

    def test_workspace_paths_come_from_the_context(self):
        self.assertEqual(ota._install_session_path().parent, self.workspace / "install")
        self.assertEqual(
            ota._install_event_queue_path().parent, self.workspace / "install"
        )

    def test_an_unconfigured_core_fails_loudly(self):
        """Silently defaulting would reintroduce the coupling this removes."""
        ota._context = None

        with self.assertRaises(RuntimeError) as caught:
            ota._ctx()

        self.assertIn("configure", str(caught.exception).lower())

    def test_two_contexts_do_not_bleed_into_each_other(self):
        other = Path(self._tmp.name) / "other"
        ota.configure(
            ota.OtaContext(
                workspace=other,
                os_type="ubuntu",
                os_version="22.04",
                architecture="x86_64",
            )
        )

        self.assertEqual(ota._ctx().platform, "ubuntu-22.04-x86_64")
        self.assertEqual(ota._install_session_path().parent, other / "install")


class TestCoreDoesNotImportCliGlobals(unittest.TestCase):
    """The dependency that blocks extracting the core into its own package."""

    CORE_MODULES = ("commands/ota_client.py", "commands/install_tree.py")

    def test_core_modules_do_not_import_commands_globals(self):
        offenders = []
        for module in self.CORE_MODULES:
            source = Path(module).read_text(encoding="utf-8")
            for line_no, line in enumerate(source.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith(("import ", "from ")) and "globals" in stripped:
                    offenders.append(f"{module}:{line_no} {stripped}")

        self.assertEqual(offenders, [])

    def test_core_modules_do_not_import_commands_utils(self):
        """`commands.utils` imports the globals module at import time."""
        offenders = []
        for module in self.CORE_MODULES:
            source = Path(module).read_text(encoding="utf-8")
            for line_no, line in enumerate(source.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith(("import ", "from ")) and (
                    "commands.utils" in stripped
                    or "from commands import utils" in stripped
                ):
                    offenders.append(f"{module}:{line_no} {stripped}")

        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
