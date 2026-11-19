"""Explicit synthetic-profile selection through the public CLI and archive path."""
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
from commands import globals as g
from commands.build import build_cli_command, build_command
from commands.fms_build_profile import fms_runtime_cmake_args
from commands.publish import _build_package, _create_archive, publish_command

RUNTIME = "RAISIN_BUILD_FMS_RUNTIME"
DEVELOPMENT = "RAISIN_BUILD_FMS_DEVELOPMENT_PROFILES"
PACKAGE = "raisin_behavior_tree_plugin"


def source(root, development=True):
    package = Path(root) / "src/raisin_plugin" / PACKAGE
    package.mkdir(parents=True)
    options = [RUNTIME, DEVELOPMENT] if development else [RUNTIME]
    (package / "CMakeLists.txt").write_text("".join(
        f'option({name} "Opt in" OFF)\n' for name in options))
    (package / "release.yaml").write_text("version: 0.0.2\n")
    return package


class DevelopmentProfileTest(unittest.TestCase):
    def test_default_clears_both_cached_choices(self):
        with tempfile.TemporaryDirectory() as root:
            source(root)
            self.assertEqual(fms_runtime_cmake_args(root, False),
                             [f"-D{RUNTIME}=OFF", f"-D{DEVELOPMENT}=OFF"])

    def test_development_requires_both_explicit_choices_and_source_support(self):
        for runtime, development, supported, message in (
            (False, True, True, "requires --fms-runtime"),
            (True, False, True, "--fms-development-profiles"),
            (True, True, False, DEVELOPMENT),
        ):
            with self.subTest(runtime=runtime, development=development, supported=supported):
                with tempfile.TemporaryDirectory() as root:
                    source(root, supported)
                    with self.assertRaisesRegex(ValueError, message):
                        fms_runtime_cmake_args(root, runtime, development_profiles=development)

    def test_build_cli_propagates_development_choice(self):
        with tempfile.TemporaryDirectory() as root:
            source(root)
            with (patch.object(g, "script_directory", root),
                  patch("commands.setup.setup"), patch("commands.setup.process_build_targets"),
                  patch("commands.build.build_command") as build):
                result = CliRunner().invoke(build_cli_command, ["-t", "release",
                    "--fms-runtime", "--fms-development-profiles"])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertTrue(build.call_args.kwargs["fms_development_profiles"])

    def test_build_cli_rejects_runtime_only_on_development_source(self):
        with tempfile.TemporaryDirectory() as root:
            source(root)
            with (patch.object(g, "script_directory", root),
                  patch("commands.setup.setup"), patch("commands.setup.process_build_targets"),
                  patch("commands.build.build_command") as build):
                result = CliRunner().invoke(build_cli_command, ["-t", "release", "--fms-runtime"])
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("--fms-development-profiles", result.output)
            build.assert_not_called()

    def test_build_passes_both_flags_to_cmake(self):
        with tempfile.TemporaryDirectory() as root:
            source(root)
            with (patch.object(g, "script_directory", root),
                  patch.object(g, "developer_env", {}), patch.object(g, "ninja_path", ""),
                  patch("commands.build.check_supported_architecture"),
                  patch("commands.build._resolve_default_python", return_value=None),
                  patch("commands.build.stash_pure_cmake_build_dir"),
                  patch("commands.build.delete_directory"),
                  patch("commands.build.restore_pure_cmake_build_dir"),
                  patch("commands.build.is_qemu_emulated", return_value=False),
                  patch("commands.build.get_build_jobs", return_value=1),
                  patch("commands.build.subprocess.run") as run):
                build_command(["release"], fms_runtime=True, fms_development_profiles=True)
            self.assertIn(f"-D{RUNTIME}=ON", run.call_args_list[0].args[0])
            self.assertIn(f"-D{DEVELOPMENT}=ON", run.call_args_list[0].args[0])

    def test_publish_cli_propagates_development_choice(self):
        with tempfile.TemporaryDirectory() as root:
            source(root)
            with (patch.object(g, "script_directory", root),
                  patch("commands.publish.publish", return_value=True) as publish):
                result = CliRunner().invoke(publish_command, [PACKAGE, "-t", "release",
                    "--fms-runtime", "--fms-development-profiles"])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertTrue(publish.call_args.kwargs["fms_development_profiles"])

    def test_publish_rejects_development_choice_for_other_packages(self):
        with patch("commands.publish.publish") as publish:
            result = CliRunner().invoke(publish_command,
                ["raisin_network", "-t", "release", "--fms-runtime", "--fms-development-profiles"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("only valid for", result.output)
        publish.assert_not_called()

    def test_cli_rejects_development_only_before_setup_or_source_lookup(self):
        for command, arguments in ((build_cli_command, []), (publish_command, [PACKAGE])):
            with self.subTest(command=command.name):
                with (patch("commands.setup.setup") as setup,
                      patch("commands.publish._resolve_target_dir") as resolve):
                    result = CliRunner().invoke(command,
                        [*arguments, "-t", "release", "--fms-development-profiles"])
                self.assertNotEqual(result.exit_code, 0)
                self.assertIn("requires --fms-runtime", result.output)
                setup.assert_not_called()
                resolve.assert_not_called()

    def test_invalid_publish_selection_preserves_existing_artifacts(self):
        with tempfile.TemporaryDirectory() as root:
            package = source(root)
            install = Path(root)/"install"
            install.mkdir()
            sentinel = install/"existing-artifact"
            sentinel.write_text("preserve")
            paths = {"target_dir": package, "build_dir": Path(root)/"build",
                     "install_dir": install}
            for runtime, development in ((True, False), (False, True)):
                with self.subTest(runtime=runtime, development=development):
                    with self.assertRaises(ValueError):
                        _build_package(PACKAGE, "Release", paths,
                            fms_runtime=runtime, fms_development_profiles=development)
                    self.assertEqual(sentinel.read_text(), "preserve")

    def test_archive_records_the_development_choice(self):
        with tempfile.TemporaryDirectory() as root:
            package = source(root)
            paths = {"target_dir": package, "build_dir": Path(root)/"build",
                     "install_dir": Path(root)/"install", "release_dir": Path(root)/"release"}
            with (patch.object(g, "script_directory", root),
                  patch("commands.publish.setup"),
                  patch("commands.publish.platform.system", return_value="Linux"),
                  patch("commands.publish._build_linux") as build,
                  patch.object(g, "os_type", "ubuntu"),
                  patch.object(g, "os_version", "24.04"),
                  patch.object(g, "architecture", "x86_64")):
                self.assertTrue(_build_package(PACKAGE, "Release", paths,
                    fms_runtime=True, fms_development_profiles=True))
                self.assertIn(f"-D{DEVELOPMENT}=ON", build.call_args.args[-1])
                archive = _create_archive(PACKAGE, "0.0.2", "release", paths)
            with zipfile.ZipFile(archive) as zipped:
                profile = json.loads(zipped.read("share/raisin/build-profile.json"))
            self.assertEqual(profile["features"],
                             {"fms_runtime": True, "fms_development_profiles": True})


if __name__ == "__main__":
    unittest.main()
