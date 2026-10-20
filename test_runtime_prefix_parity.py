"""`raisin setup` and `runtime_prefix.assemble` build the same runtime prefix.

Both put together the pieces in `raisin_ota.runtime_prefix`, each in its own
order: setup with its source overlay between them, the OTA agent with nothing
else. A runtime step added to one caller only would leave the other building a
different prefix, and each caller's own tests would still pass. With no `src/`
there is no overlay, so the two `install/` trees must match file for file.
"""

import contextlib
import hashlib
import io
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

from commands import globals as g  # noqa: E402
from commands import setup as cli_setup  # noqa: E402
from raisin_ota import runtime_prefix  # noqa: E402
from raisin_ota.client import OtaContext  # noqa: E402

REPO = Path(__file__).parent

#: Files only setup puts in the prefix, and why that is not a runtime step.
SETUP_ONLY = {
    # Copied from the workspace checkout's templates/ for a source build; the
    # delivered packages carry their own copy, and only a compiler reads it.
    "generated/include/raisin_serialization_base.hpp",
}


def snapshot(prefix):
    """Every path under `prefix` with its content hash and mode."""
    entries = {}
    for path in sorted(prefix.rglob("*")):
        relative = path.relative_to(prefix).as_posix()
        mode = stat.S_IMODE(path.stat().st_mode)
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entries[relative] = ("file", digest, oct(mode))
        else:
            entries[relative] = ("dir", oct(mode))
    return entries


class TestSetupAndAssembleBuildTheSamePrefix(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        for name in (
            "vcpkg_dependencies",
            "os_type",
            "os_version",
            "architecture",
            "script_directory",
            "generated_dir",
        ):
            self.addCleanup(setattr, g, name, getattr(g, name))

    def a_workspace(self, name):
        """Two delivered packages, a device override, and no `src/`."""
        workspace = self.root / name / "raisin_ws"
        home = self.root / name / "home"
        packages = {
            "raisin": {
                "bin/raisin_node": "#!/bin/sh\n",
                "lib/libraisin.so": "raisin",
                "scripts/raisin/scripts/start.sh": "#!/bin/sh\n",
                "resource/raibo2/resource/params.yaml": "from the package",
                "generated/include/raisin/msg/pose.hpp": "header",
                "release.txt": "raisin 1111111\n",
            },
            "raisin_gui": {
                "lib/libgui.so": "gui",
                "release.txt": "raisin_gui 2222222\n",
            },
        }
        for package, files in packages.items():
            root = (
                workspace / "release" / "install" / package
                / "ubuntu" / "24.04" / "x86_64" / "release"
            )
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                path.chmod(0o644)
        override = home / ".raisin" / "raibo2" / "resource" / "params.yaml"
        override.parent.mkdir(parents=True)
        override.write_text("for this device", encoding="utf-8")
        (workspace / "templates").mkdir()
        shutil.copy(
            REPO / "templates" / "raisin_serialization_base.hpp",
            workspace / "templates",
        )
        return workspace, home

    def setup_prefix(self):
        workspace, home = self.a_workspace("setup")
        g.vcpkg_dependencies = set()
        g.os_type, g.os_version, g.architecture = "ubuntu", "24.04", "x86_64"
        g.script_directory = str(workspace)
        # The ignore lists come from the workspace's configuration file, and
        # CMakeLists.txt and vcpkg.json are written beside install/, not in it.
        with patch.object(cli_setup, "get_repos_to_ignore", return_value=[]), \
                patch.object(cli_setup, "get_packages_to_ignore", return_value=[]), \
                patch.object(cli_setup, "update_cmake_file"), \
                patch.object(cli_setup, "generate_vcpkg_json"), \
                patch.dict(os.environ, {"HOME": str(home)}), \
                contextlib.redirect_stdout(io.StringIO()):
            cli_setup.setup()
        return workspace / "install"

    def assemble_prefix(self):
        workspace, home = self.a_workspace("assemble")
        context = OtaContext(
            workspace=workspace,
            os_type="ubuntu",
            os_version="24.04",
            architecture="x86_64",
        )
        runtime_prefix.assemble(context, home)
        return workspace / "install"

    def test_without_src_both_build_the_same_prefix(self):
        from_setup = snapshot(self.setup_prefix())
        from_assemble = snapshot(self.assemble_prefix())

        for relative in SETUP_ONLY:
            self.assertIn(relative, from_setup)
            del from_setup[relative]
        differences = {
            relative: (from_setup.get(relative), from_assemble.get(relative))
            for relative in from_setup.keys() | from_assemble.keys()
            if from_setup.get(relative) != from_assemble.get(relative)
        }
        self.assertEqual(differences, {})


if __name__ == "__main__":
    unittest.main()
