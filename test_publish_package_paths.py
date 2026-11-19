import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from commands import globals as g
from commands.publish import _get_paths


class PublishPackagePathsTest(unittest.TestCase):
    def test_publish_resolves_package_nested_in_plugin_repository(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package = (
                Path(temp_dir)
                / "src"
                / "plugin_collection"
                / "example_package"
            )
            package.mkdir(parents=True)
            (package / "release.yaml").write_text("version: 0.0.2\n")
            with patch.object(g, "script_directory", temp_dir):
                self.assertEqual(
                    _get_paths("example_package", "release")["target_dir"],
                    package,
                )

    def test_publish_prefers_direct_package_and_refuses_ambiguous_nested_names(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "src"
            direct = source / "example_package"
            direct.mkdir(parents=True)
            (direct / "release.yaml").write_text("version: 1.0.0\n")
            (source / "plugin_collection" / direct.name).mkdir(parents=True)
            (source / "plugin_collection" / direct.name / "release.yaml").write_text(
                "version: 0.0.2\n"
            )
            with patch.object(g, "script_directory", temp_dir):
                self.assertEqual(
                    _get_paths(direct.name, "release")["target_dir"], direct
                )

            (direct / "release.yaml").unlink()
            direct.rmdir()
            (source / "plugin_collection" / direct.name / "release.yaml").unlink()
            (source / "plugin_collection" / direct.name).rmdir()
            (source / "plugin_collection").rmdir()
            for repository, version in (
                ("plugin_collection", "0.0.2"),
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
