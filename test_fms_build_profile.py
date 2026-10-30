import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
from commands import globals as g
from commands.fms_build_profile import (
    FMS_RUNTIME_OPTION,
    fms_runtime_cmake_args,
    write_fms_build_profile,
)
from commands.publish import _build_package, _create_archive, _get_paths
from commands.build import build_cli_command, build_command
from commands.publish import publish_command


class FmsBuildProfileTest(unittest.TestCase):
    def _write_plugin_option(self, script_directory):
        package = (
            Path(script_directory)
            / "src"
            / "raisin_plugin"
            / "raisin_behavior_tree_plugin"
        )
        package.mkdir(parents=True, exist_ok=True)
        (package / "CMakeLists.txt").write_text(
            f'option({FMS_RUNTIME_OPTION} "Build FMS runtime" OFF)\n'
        )

    def test_publish_resolves_package_nested_in_plugin_repository(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package = (
                Path(temp_dir)
                / "src"
                / "raisin_plugin"
                / "raisin_behavior_tree_plugin"
            )
            package.mkdir(parents=True)
            (package / "release.yaml").write_text("version: 0.0.2\n")
            with patch.object(g, "script_directory", temp_dir):
                self.assertEqual(
                    _get_paths("raisin_behavior_tree_plugin", "release")["target_dir"],
                    package,
                )

    def test_publish_prefers_direct_package_and_refuses_ambiguous_nested_names(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "src"
            direct = source / "raisin_behavior_tree_plugin"
            direct.mkdir(parents=True)
            (direct / "release.yaml").write_text("version: 1.0.0\n")
            (source / "raisin_plugin" / direct.name).mkdir(parents=True)
            (source / "raisin_plugin" / direct.name / "release.yaml").write_text(
                "version: 0.0.2\n"
            )
            with patch.object(g, "script_directory", temp_dir):
                self.assertEqual(
                    _get_paths(direct.name, "release")["target_dir"], direct
                )

            (direct / "release.yaml").unlink()
            direct.rmdir()
            (source / "raisin_plugin" / direct.name / "release.yaml").unlink()
            (source / "raisin_plugin" / direct.name).rmdir()
            (source / "raisin_plugin").rmdir()
            for repository, version in (
                ("raisin_plugin", "0.0.2"),
                ("other_plugin", "0.0.3"),
            ):
                package = source / repository / direct.name
                package.mkdir(parents=True)
                (package / "release.yaml").write_text(f"version: {version}\n")
            with patch.object(g, "script_directory", temp_dir):
                with self.assertRaisesRegex(ValueError, "Ambiguous package target"):
                    _get_paths(direct.name, "release")

    def test_publish_rejects_package_target_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(g, "script_directory", temp_dir):
                with self.assertRaisesRegex(ValueError, "Invalid package target"):
                    _get_paths("../outside", "release")

    def test_disabled_does_not_require_fms_source_or_add_cmake_option(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertEqual(fms_runtime_cmake_args(temp_dir, enabled=False), [])

    def test_enabled_fails_closed_when_selected_plugin_lacks_option(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package = (
                Path(temp_dir)
                / "src"
                / "raisin_plugin"
                / "raisin_behavior_tree_plugin"
            )
            package.mkdir(parents=True)
            (package / "CMakeLists.txt").write_text("project(raisin_behavior_tree_plugin)\n")
            with self.assertRaisesRegex(ValueError, FMS_RUNTIME_OPTION):
                fms_runtime_cmake_args(temp_dir, enabled=True)

    def test_enabled_requires_declared_option_and_returns_only_opt_in(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package = (
                Path(temp_dir)
                / "src"
                / "raisin_plugin"
                / "raisin_behavior_tree_plugin"
            )
            package.mkdir(parents=True)
            (package / "CMakeLists.txt").write_text(
                f'option({FMS_RUNTIME_OPTION} "Build FMS runtime" OFF)\n'
            )
            self.assertEqual(
                fms_runtime_cmake_args(temp_dir, enabled=True),
                [f"-D{FMS_RUNTIME_OPTION}=ON"],
            )

    def test_publish_checks_option_in_the_selected_package_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_plugin_option(temp_dir)
            target_dir = (
                Path(temp_dir)
                / "src"
                / "alternate_plugin_repo"
                / "raisin_behavior_tree_plugin"
            )
            target_dir.mkdir(parents=True)
            (target_dir / "CMakeLists.txt").write_text(
                "project(raisin_behavior_tree_plugin)\n"
            )
            (target_dir / "release.yaml").write_text("version: 0.1.0\n")
            paths = {
                "build_dir": Path(temp_dir) / "build",
                "install_dir": Path(temp_dir) / "install",
                "target_dir": target_dir,
            }
            with (
                patch.object(g, "script_directory", temp_dir),
                patch("commands.publish.delete_directory") as delete_directory,
                patch("commands.publish.setup"),
                patch("commands.publish.platform.system", return_value="Linux"),
                patch("commands.publish._build_linux"),
            ):
                with self.assertRaisesRegex(ValueError, FMS_RUNTIME_OPTION):
                    _build_package(
                        "raisin_behavior_tree_plugin",
                        "Release",
                        paths,
                        fms_runtime=True,
                    )
            delete_directory.assert_not_called()

    def test_non_fms_package_does_not_receive_fms_cmake_override(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_plugin_option(temp_dir)
            target_dir = Path(temp_dir) / "src" / "raisin_network"
            target_dir.mkdir(parents=True)
            (target_dir / "CMakeLists.txt").write_text("project(raisin_network)\n")
            (target_dir / "release.yaml").write_text("version: 1.0.0\n")
            paths = {
                "build_dir": Path(temp_dir) / "build",
                "install_dir": Path(temp_dir) / "install",
                "target_dir": target_dir,
            }
            with (
                patch.object(g, "script_directory", temp_dir),
                patch("commands.publish.delete_directory"),
                patch("commands.publish.setup"),
                patch("commands.publish.platform.system", return_value="Linux"),
                patch("commands.publish._build_linux") as build_linux,
            ):
                self.assertTrue(
                    _build_package("raisin_network", "Release", paths)
                )
            self.assertNotIn(
                f"-D{FMS_RUNTIME_OPTION}=OFF",
                build_linux.call_args.args[-1],
            )
            self.assertFalse(
                (Path(temp_dir) / "install/share/raisin/build-profile.json").exists()
            )

    def test_disabled_plugin_archive_does_not_add_fms_profile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_plugin_option(temp_dir)
            target_dir = (
                Path(temp_dir)
                / "src"
                / "raisin_plugin"
                / "raisin_behavior_tree_plugin"
            )
            (target_dir / "release.yaml").write_text("version: 0.0.2\n")
            paths = {
                "build_dir": Path(temp_dir) / "build",
                "install_dir": Path(temp_dir) / "install",
                "target_dir": target_dir,
            }
            with (
                patch.object(g, "script_directory", temp_dir),
                patch("commands.publish.delete_directory"),
                patch("commands.publish.setup"),
                patch("commands.publish.platform.system", return_value="Linux"),
                patch("commands.publish._build_linux"),
            ):
                self.assertTrue(
                    _build_package("raisin_behavior_tree_plugin", "Release", paths)
                )
            self.assertFalse(
                (Path(temp_dir) / "install/share/raisin/build-profile.json").exists()
            )

    def test_build_command_passes_on_and_off_to_cmake(self):
        for enabled, expected in ((False, "OFF"), (True, "ON")):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as temp_dir:
                self._write_plugin_option(temp_dir)
                with (
                    patch.object(g, "script_directory", temp_dir),
                    patch.object(g, "developer_env", {}),
                    patch.object(g, "ninja_path", ""),
                    patch("commands.build.check_supported_architecture"),
                    patch("commands.build._resolve_default_python", return_value=None),
                    patch("commands.build.stash_pure_cmake_build_dir"),
                    patch("commands.build.delete_directory"),
                    patch("commands.build.restore_pure_cmake_build_dir"),
                    patch("commands.build.is_qemu_emulated", return_value=False),
                    patch("commands.build.get_build_jobs", return_value=1),
                    patch("commands.build.subprocess.run") as run,
                ):
                    build_command(["release"], fms_runtime=enabled)
                cmake_args = run.call_args_list[0].args[0]
                self.assertIn(f"-D{FMS_RUNTIME_OPTION}={expected}", cmake_args)

    def test_disabled_explicitly_overrides_declared_option_to_off(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_plugin_option(temp_dir)
            self.assertEqual(
                fms_runtime_cmake_args(temp_dir, enabled=False),
                [f"-D{FMS_RUNTIME_OPTION}=OFF"],
            )

    def test_comment_does_not_count_as_declared_option(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package = (
                Path(temp_dir)
                / "src"
                / "raisin_plugin"
                / "raisin_behavior_tree_plugin"
            )
            package.mkdir(parents=True)
            (package / "CMakeLists.txt").write_text(
                f"# option({FMS_RUNTIME_OPTION} disabled)\n"
            )
            with self.assertRaisesRegex(ValueError, FMS_RUNTIME_OPTION):
                fms_runtime_cmake_args(temp_dir, enabled=True)

    def test_bracket_comments_and_string_arguments_do_not_count_as_options(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package = (
                Path(temp_dir)
                / "src"
                / "raisin_plugin"
                / "raisin_behavior_tree_plugin"
            )
            package.mkdir(parents=True)
            (package / "CMakeLists.txt").write_text(
                "#[=[\n"
                f'option({FMS_RUNTIME_OPTION} "comment only" OFF)\n'
                "]=]\n"
                f'message(\n  "option({FMS_RUNTIME_OPTION} string only)"\n)\n'
            )
            with self.assertRaisesRegex(ValueError, FMS_RUNTIME_OPTION):
                fms_runtime_cmake_args(temp_dir, enabled=True)

    def test_actual_option_after_multiline_command_is_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package = (
                Path(temp_dir)
                / "src"
                / "raisin_plugin"
                / "raisin_behavior_tree_plugin"
            )
            package.mkdir(parents=True)
            (package / "CMakeLists.txt").write_text(
                'message("not an option")\n'
                f'OPTION("{FMS_RUNTIME_OPTION}" "Build FMS runtime" OFF)\n'
            )
            self.assertEqual(
                fms_runtime_cmake_args(temp_dir, enabled=True),
                [f"-D{FMS_RUNTIME_OPTION}=ON"],
            )

    def test_cmake_command_name_is_case_insensitive_but_variable_is_exact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package = (
                Path(temp_dir)
                / "src"
                / "raisin_plugin"
                / "raisin_behavior_tree_plugin"
            )
            package.mkdir(parents=True)
            cmake_file = package / "CMakeLists.txt"
            cmake_file.write_text(
                f'OPTION({FMS_RUNTIME_OPTION} "Build FMS runtime" OFF)\n'
            )
            self.assertEqual(
                fms_runtime_cmake_args(temp_dir, enabled=True),
                [f"-D{FMS_RUNTIME_OPTION}=ON"],
            )

            cmake_file.write_text(
                'option(raisin_build_fms_runtime "Build FMS runtime" OFF)\n'
            )
            with self.assertRaisesRegex(ValueError, FMS_RUNTIME_OPTION):
                fms_runtime_cmake_args(temp_dir, enabled=True)

    def test_archive_profile_records_exact_boolean_choice(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = write_fms_build_profile(temp_dir, enabled=True)
            self.assertEqual(
                json.loads(profile_path.read_text()),
                {
                    "schema_version": 1,
                    "package": "raisin_behavior_tree_plugin",
                    "features": {"fms_runtime": True},
                },
            )

    def test_plugin_archive_contains_build_profile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            install_dir = Path(temp_dir) / "install"
            release_dir = Path(temp_dir) / "release"
            install_dir.mkdir()
            (install_dir / "release.yaml").write_text("version: 0.1.0\n")
            write_fms_build_profile(str(install_dir), enabled=True)
            with (
                patch.object(g, "os_type", "ubuntu"),
                patch.object(g, "os_version", "24.04"),
                patch.object(g, "architecture", "x86_64"),
            ):
                archive = _create_archive(
                    "raisin_behavior_tree_plugin",
                    "0.1.0",
                    "release",
                    {"install_dir": install_dir, "release_dir": release_dir},
                )
            with zipfile.ZipFile(archive) as zipped:
                data = json.loads(
                    zipped.read("share/raisin/build-profile.json").decode()
                )
            self.assertTrue(data["features"]["fms_runtime"])

    @patch("commands.build.build_command")
    @patch("commands.setup.process_build_targets")
    @patch("commands.setup.setup")
    def test_build_cli_passes_explicit_opt_in(self, _setup, _targets, mock_build):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_plugin_option(temp_dir)
            with patch.object(g, "script_directory", temp_dir):
                result = CliRunner().invoke(
                    build_cli_command, ["--type", "release", "--fms-runtime"]
                )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(mock_build.call_args.kwargs["fms_runtime"])

    @patch("commands.build.build_command")
    @patch("commands.setup.process_build_targets")
    @patch("commands.setup.setup")
    def test_build_cli_resolves_plugin_source_during_setup_before_validation(
        self, mock_setup, _targets, mock_build
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            package = (
                Path(temp_dir)
                / "src"
                / "raisin_plugin"
                / "raisin_behavior_tree_plugin"
            )

            def resolve_plugin_source(**_kwargs):
                package.mkdir(parents=True, exist_ok=True)
                (package / "CMakeLists.txt").write_text(
                    f'option({FMS_RUNTIME_OPTION} "Build FMS runtime" OFF)\n'
                )

            mock_setup.side_effect = resolve_plugin_source
            with patch.object(g, "script_directory", temp_dir):
                result = CliRunner().invoke(
                    build_cli_command, ["--type", "release", "--fms-runtime"]
                )

        self.assertEqual(result.exit_code, 0, result.output)
        mock_setup.assert_called_once()
        self.assertTrue(mock_build.call_args.kwargs["fms_runtime"])

    @patch("commands.build.build_command")
    @patch("commands.setup.process_build_targets")
    @patch("commands.setup.setup")
    def test_build_cli_keeps_opt_in_disabled_by_default(
        self, _setup, _targets, mock_build
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(g, "script_directory", temp_dir):
                result = CliRunner().invoke(
                    build_cli_command, ["--type", "release"]
                )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(mock_build.call_args.kwargs["fms_runtime"])

    @patch("commands.publish.publish", return_value=True)
    def test_publish_cli_passes_opt_in_for_plugin_archive(self, mock_publish):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_plugin_option(temp_dir)
            (
                Path(temp_dir)
                / "src"
                / "raisin_plugin"
                / "raisin_behavior_tree_plugin"
                / "release.yaml"
            ).write_text("version: 0.1.0\n")
            with patch.object(g, "script_directory", temp_dir):
                result = CliRunner().invoke(
                    publish_command,
                    [
                        "raisin_behavior_tree_plugin",
                        "--type",
                        "release",
                        "--fms-runtime",
                    ],
                )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(mock_publish.call_args.kwargs["fms_runtime"])

    def test_publish_cli_refuses_runtime_on_another_package(self):
        result = CliRunner().invoke(
            publish_command,
            ["raisin_network", "--type", "release", "--fms-runtime"],
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("only valid for raisin_behavior_tree_plugin", result.output)

    def test_publish_package_passes_nested_source_opt_in_and_writes_profile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_plugin_option(temp_dir)
            target_dir = (
                Path(temp_dir)
                / "src"
                / "raisin_plugin"
                / "raisin_behavior_tree_plugin"
            )
            paths = {
                "build_dir": Path(temp_dir) / "build",
                "install_dir": Path(temp_dir) / "install",
                "target_dir": target_dir,
            }
            (target_dir / "release.yaml").write_text("version: 0.1.0\n")
            with (
                patch.object(g, "script_directory", temp_dir),
                patch("commands.publish.delete_directory"),
                patch("commands.publish.setup") as mock_setup,
                patch("commands.publish.platform.system", return_value="Linux"),
                patch("commands.publish._build_linux") as build_linux,
            ):
                self.assertTrue(
                    _build_package(
                        "raisin_behavior_tree_plugin",
                        "Release",
                        paths,
                        fms_runtime=True,
                    )
                )
            self.assertIn(
                f"-D{FMS_RUNTIME_OPTION}=ON",
                build_linux.call_args.args[-1],
            )
            self.assertEqual(
                mock_setup.call_args.kwargs["package_source_dir"], target_dir
            )
            profile = json.loads(
                (
                    Path(temp_dir)
                    / "install/share/raisin/build-profile.json"
                ).read_text()
            )
            self.assertTrue(profile["features"]["fms_runtime"])


if __name__ == "__main__":
    unittest.main()
