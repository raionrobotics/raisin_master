"""Generic CLI cache definitions remain argv values and reach build/publish equally."""
import subprocess
import platform
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
from commands import globals as g
from commands.build import build_command, build_cli_command
from commands.publish import _build_package, publish_command
from commands.cmake_definitions import cmake_definition_args


class CmakeDefinitionsTest(unittest.TestCase):
    def test_definitions_preserve_values_without_shell_interpretation(self):
        values = ("ENABLE_DEMO=ON", "LABEL=a b;c=d", "EMPTY=", "TEXT=$(not-executed)")
        self.assertEqual(cmake_definition_args(values), ["-D" + v for v in values])
        self.assertEqual(cmake_definition_args(()), [])

    def test_malformed_duplicate_and_cli_owned_definitions_are_rejected(self):
        for values in (("MISSING",), ("=x",), ("-B=elsewhere",), ("BAD KEY=ON",),
                       ("KEY=x\ny",), ("KEY=x\x00y",), ("KEY=ON", "KEY=OFF"),
                       ("CMAKE_INSTALL_PREFIX=/tmp/elsewhere",), ("CMAKE_BUILD_TYPE=Debug",),
                       ("CMAKE_TOOLCHAIN_FILE=other",), ("CMAKE_GENERATOR=Make",)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                cmake_definition_args(values)

    def test_invalid_cli_input_is_rejected_before_setup_or_publish(self):
        for command, args in ((build_cli_command, []), (publish_command, ["example"])):
            with self.subTest(command=command.name):
                with (patch("commands.setup.setup") as setup,
                      patch("commands.publish.publish") as publish):
                    result = CliRunner().invoke(command, [*args, "-t", "release",
                        "--cmake-define", "CMAKE_INSTALL_PREFIX=/tmp/elsewhere"])
                self.assertNotEqual(result.exit_code, 0)
                setup.assert_not_called(); publish.assert_not_called()

    def test_cli_passes_repeated_definitions_and_keeps_default_empty(self):
        for values in ((), ("ENABLE_DEMO=ON", "LABEL=a b")):
            args = ["-t", "release"]
            for value in values:
                args += ["--cmake-define", value]
            with (patch("commands.setup.setup"), patch("commands.setup.process_build_targets"),
                  patch("commands.build.build_command") as build,
                  patch("commands.publish.publish", return_value=True) as publish):
                result = CliRunner().invoke(build_cli_command, args)
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertEqual(tuple(build.call_args.kwargs["cmake_defines"]), values)
                result = CliRunner().invoke(publish_command, ["example", *args])
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertEqual(tuple(publish.call_args.kwargs["cmake_defines"]), values)

    def test_build_passes_each_value_as_one_argv_element(self):
        with tempfile.TemporaryDirectory() as root:
            with (patch.object(g, "script_directory", root),
                  patch.object(g, "developer_env", {}), patch.object(g, "ninja_path", ""),
                  patch("commands.build.check_supported_architecture"),
                  patch("commands.build._resolve_default_python", return_value=None),
                  patch("commands.build.stash_pure_cmake_build_dir"),
                  patch("commands.build.restore_pure_cmake_build_dir"),
                  patch("commands.build.is_qemu_emulated", return_value=False),
                  patch("commands.build.get_build_jobs", return_value=1),
                  patch("commands.build.subprocess.run") as run):
                build_command(["release"], cmake_defines=("LABEL=a b;c=d",))
            self.assertIn("-DLABEL=a b;c=d", run.call_args_list[0].args[0])

    def test_publish_passes_definitions_without_writing_package_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root)/"example"; target.mkdir()
            (target/"release.yaml").write_text("version: 1.0.0\n")
            paths = {"target_dir": target, "build_dir": Path(root)/"build",
                     "install_dir": Path(root)/"install"}
            with (patch("commands.publish.setup"),
                  patch("commands.publish.platform.system", return_value="Linux"),
                  patch("commands.publish._build_linux") as build):
                self.assertTrue(_build_package("example", "Release", paths,
                                               cmake_defines=("ENABLE_DEMO=ON",)))
                self.assertIn("-DENABLE_DEMO=ON", build.call_args.args[-1])
            self.assertFalse((paths["install_dir"]/"share/raisin/build-profile.json").exists())
            sentinel = paths["install_dir"]/"preserve"; sentinel.write_text("existing")
            with self.assertRaises(ValueError):
                _build_package("example", "Release", paths, cmake_defines=("BAD",))
            self.assertEqual(sentinel.read_text(), "existing")

    @unittest.skipUnless(platform.system() == "Linux" and shutil.which("ninja"),
                         "requires native Linux CMake/Ninja")
    def test_real_build_returns_to_package_default_without_stale_cache(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root)
            (source/"CMakeLists.txt").write_text(
                'cmake_minimum_required(VERSION 3.15)\nproject(default_test NONE)\n'
                'option(ENABLE_DEMO "Demo" OFF)\n'
                'file(WRITE "${CMAKE_BINARY_DIR}/observed.txt" "${ENABLE_DEMO}")\n')
            with (patch.object(g, "script_directory", root),
                  patch.object(g, "developer_env", {}), patch.object(g, "ninja_path", ""),
                  patch("commands.build.check_supported_architecture"),
                  patch("commands.build._resolve_default_python", return_value=None),
                  patch("commands.build.is_qemu_emulated", return_value=False),
                  patch("commands.build.get_build_jobs", return_value=1)):
                build_command(["release"], cmake_defines=("ENABLE_DEMO=ON",))
                self.assertEqual((source/"cmake-build-release/observed.txt").read_text(), "ON")
                build_command(["release"])
                self.assertEqual((source/"cmake-build-release/observed.txt").read_text(), "OFF")

    def test_real_cmake_receives_literal_values(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root)
            (source/"CMakeLists.txt").write_text(
                'cmake_minimum_required(VERSION 3.15)\nproject(definition_test NONE)\n'
                'file(WRITE "${CMAKE_BINARY_DIR}/observed.txt" "${LABEL}\\n${EMPTY}")\n')
            subprocess.run(["cmake", "-S", root, "-B", str(source/"build"),
                *cmake_definition_args(("LABEL=a b;c=d", "EMPTY="))],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual((source/"build/observed.txt").read_text(), "a b;c=d\n")


if __name__ == "__main__":
    unittest.main()
