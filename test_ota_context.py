"""The OTA core must be usable without the CLI's process globals.

`commands.globals` is populated by `init_environment` at CLI startup. An agent
has no CLI, needs different values per deployment, and must not import a module
whose contract is "the CLI filled this in". These tests pin the boundary.
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import raisin_ota.client as ota  # noqa: E402


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
        # `release/`, not `install/`: a full build deletes the latter.
        self.assertEqual(ota._install_session_path().parent, self.workspace / "release")
        self.assertEqual(
            ota._install_event_queue_path().parent, self.workspace / "release"
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
        self.assertEqual(ota._install_session_path().parent, other / "release")


class TestRobotIdentityIsInjected(unittest.TestCase):
    """The core is told who it is; it does not go looking.

    Resolving a credential means knowing about env vars, config files and a
    developer's HOME. A robot on a service account and a developer at a shell
    answer those differently, and the core should not have to care — nor should
    a human running the tool on a robot be silently attributed to the robot
    because a key file happened to be on disk.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._saved = ota._context

    def tearDown(self):
        ota._context = self._saved
        self._tmp.cleanup()

    def _configure(self, robot=None):
        ota.configure(
            ota.OtaContext(
                workspace=Path(self._tmp.name),
                os_type="ubuntu",
                os_version="24.04",
                architecture="arm64",
                robot=robot,
            )
        )

    def test_headers_come_from_the_injected_identity(self):
        self._configure(
            ota.RobotIdentity(
                api_key="rk_test",  # pragma: allowlist secret
                node_key="jetson",
                client_version="agent/1.2",
            )
        )

        headers = ota._robot_auth_headers("session-1")

        self.assertEqual(headers["Authorization"], "Robot rk_test")
        self.assertEqual(headers["X-Robot-Node"], "jetson")
        self.assertEqual(headers["X-Client-Version"], "agent/1.2")
        self.assertEqual(headers["X-Install-Session-Id"], "session-1")

    def test_no_identity_means_no_robot_requests(self):
        self._configure(robot=None)

        self.assertIsNone(ota._robot_auth_headers("session-1"))
        self.assertFalse(ota.robot_reporting_enabled())

    def test_environment_alone_does_not_grant_a_robot_identity(self):
        """The caller decides who it is — not whatever is lying on the machine."""
        self._configure(robot=None)

        with patch.dict(
            os.environ,
            {
                "RAISIN_ROBOT_API_KEY": "rk_from_env",  # pragma: allowlist secret
                "RAISIN_ROBOT_NODE": "jetson",
            },
            clear=True,
        ):
            self.assertIsNone(ota._robot_auth_headers("session-1"))
            self.assertFalse(ota.robot_reporting_enabled())

    def test_credential_resolution_is_not_the_core_s_job(self):
        removed = [
            "get_robot_api_key",
            "get_robot_node_key",
            "get_robot_api_key_path",
            "save_robot_api_key",
            "_load_local_config",
        ]
        still_here = [n for n in removed if hasattr(ota, n)]

        self.assertEqual(still_here, [])


class TestCoreDoesNotImportTheCli(unittest.TestCase):
    """The package must not reach back into the CLI it was extracted from.

    Two named modules were the original coupling, but the property that matters
    is broader and easier to state: nothing under `raisin_ota/` imports
    `commands` at all. An agent, a commissioning tool and a telemetry program
    each install this package without the CLI present, so a single import here
    is an ImportError on a robot rather than a lint failure here.
    """

    CORE_MODULES = (
        "raisin_ota/__init__.py",
        "raisin_ota/client.py",
        "raisin_ota/install_tree.py",
        "raisin_ota/ssh.py",
    )

    def _import_lines(self, module):
        source = Path(module).read_text(encoding="utf-8")
        for line_no, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                yield line_no, stripped

    def test_no_core_module_imports_the_cli(self):
        offenders = [
            f"{module}:{line_no} {line}"
            for module in self.CORE_MODULES
            for line_no, line in self._import_lines(module)
            if line.startswith(("import commands", "from commands"))
        ]

        self.assertEqual(offenders, [])

    def test_the_guard_would_notice(self):
        """A guard nothing can fail is not a guard.

        Runs the same detection over a file with the coupling deliberately put
        back, so a refactor that breaks the check fails here rather than going
        quiet and passing forever.
        """
        with tempfile.TemporaryDirectory() as tmp:
            planted = Path(tmp) / "planted.py"
            planted.write_text(
                "import os\nfrom commands import globals as g\n", encoding="utf-8"
            )

            caught = [
                line
                for _, line in self._import_lines(str(planted))
                if line.startswith(("import commands", "from commands"))
            ]

        self.assertEqual(caught, ["from commands import globals as g"])


if __name__ == "__main__":
    unittest.main()
