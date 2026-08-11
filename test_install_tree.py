"""Tests for the versioned install tree and its atomic commit point.

Layout:

    release/versions/<version>/   complete package tree for one archive version
    release/install -> versions/<version>    the only thing that goes live

`release/install` keeps its path so existing consumers (repo_dependency_check,
index) are unaffected; only its type changes, from directory to symlink.
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from commands import install_tree as it  # noqa: E402


class InstallTreeTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.release = Path(self._tmp.name)
        self.release = self.release / "release"
        self.release.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _write_pkg(self, base: Path, name: str, marker: str = "x"):
        """Install a package the way extraction does: replace the directory.

        Editing in place would mutate the hardlink-shared previous version.
        """
        relative = Path(name) / "linux" / "22.04" / "x86_64" / "release"
        d = it.replace_package_dir(base, relative)
        (d / "release.yaml").write_text(f"version: {marker}\n", encoding="utf-8")
        return d


class TestLegacyMigration(InstallTreeTestCase):
    """Robots in the field have release/install as a real directory."""

    def test_existing_directory_becomes_a_version_plus_symlink(self):
        legacy = self.release / "install"
        self._write_pkg(legacy, "pkg1", "old")

        it.migrate_legacy_tree(self.release)

        link = self.release / "install"
        self.assertTrue(link.is_symlink())
        self.assertTrue(
            (link / "pkg1" / "linux" / "22.04" / "x86_64" / "release" / "release.yaml")
            .read_text()
            .strip()
            .endswith("old")
        )

    def test_migration_is_idempotent(self):
        self._write_pkg(self.release / "install", "pkg1")
        it.migrate_legacy_tree(self.release)
        first = os.readlink(self.release / "install")

        it.migrate_legacy_tree(self.release)

        self.assertEqual(os.readlink(self.release / "install"), first)

    def test_nothing_to_migrate_when_there_is_no_tree(self):
        it.migrate_legacy_tree(self.release)

        self.assertFalse((self.release / "install").exists())

    def test_migrated_packages_are_not_copied_twice(self):
        """A large install tree must be moved, not duplicated."""
        legacy = self.release / "install"
        pkg = self._write_pkg(legacy, "pkg1")
        inode = (pkg / "release.yaml").stat().st_ino

        it.migrate_legacy_tree(self.release)

        moved = (
            self.release
            / "install"
            / "pkg1"
            / "linux"
            / "22.04"
            / "x86_64"
            / "release"
            / "release.yaml"
        )
        self.assertEqual(moved.stat().st_ino, inode)


class TestStageAndCommit(InstallTreeTestCase):
    def test_staging_does_not_disturb_the_live_tree(self):
        it.migrate_legacy_tree(self.release)
        staging = it.stage_version(self.release, "2026.2.0")
        self._write_pkg(staging, "pkg_new")

        self.assertFalse((self.release / "install").exists())
        self.assertTrue(staging.is_dir())

    def test_commit_points_the_symlink_at_the_new_version(self):
        staging = it.stage_version(self.release, "2026.2.0")
        self._write_pkg(staging, "pkg1", "new")

        it.commit_version(self.release, "2026.2.0")

        self.assertEqual(it.current_version(self.release), "2026.2.0")
        self.assertTrue(
            (
                self.release
                / "install"
                / "pkg1"
                / "linux"
                / "22.04"
                / "x86_64"
                / "release"
                / "release.yaml"
            ).is_file()
        )

    def test_commit_replaces_a_previous_version_atomically(self):
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1", "old")
        it.commit_version(self.release, "1.0.0")

        self._write_pkg(it.stage_version(self.release, "2.0.0"), "pkg1", "new")
        it.commit_version(self.release, "2.0.0")

        self.assertEqual(it.current_version(self.release), "2.0.0")
        content = (
            self.release
            / "install"
            / "pkg1"
            / "linux"
            / "22.04"
            / "x86_64"
            / "release"
            / "release.yaml"
        ).read_text()
        self.assertIn("new", content)

    def test_previous_version_survives_a_commit(self):
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1", "old")
        it.commit_version(self.release, "1.0.0")
        self._write_pkg(it.stage_version(self.release, "2.0.0"), "pkg1", "new")
        it.commit_version(self.release, "2.0.0")

        self.assertEqual(it.previous_version(self.release), "1.0.0")

    def test_abandoned_staging_leaves_the_live_tree_alone(self):
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1", "old")
        it.commit_version(self.release, "1.0.0")

        it.stage_version(self.release, "2.0.0")  # never committed

        self.assertEqual(it.current_version(self.release), "1.0.0")

    def test_staging_clones_the_current_version_for_partial_installs(self):
        """`raisin install pkg1` must not drop the packages it did not touch."""
        staging = it.stage_version(self.release, "1.0.0")
        self._write_pkg(staging, "pkg1", "old")
        self._write_pkg(staging, "pkg2", "old")
        it.commit_version(self.release, "1.0.0")

        new_staging = it.stage_version(self.release, "2.0.0")

        self.assertTrue((new_staging / "pkg2").is_dir())

    def test_clone_shares_storage_with_the_current_version(self):
        """Cloning a full install tree must not double the disk footprint."""
        staging = it.stage_version(self.release, "1.0.0")
        pkg = self._write_pkg(staging, "pkg1")
        it.commit_version(self.release, "1.0.0")
        inode = (
            (
                self.release
                / "install"
                / "pkg1"
                / "linux"
                / "22.04"
                / "x86_64"
                / "release"
                / "release.yaml"
            )
            .stat()
            .st_ino
        )

        new_staging = it.stage_version(self.release, "2.0.0")

        cloned = (
            new_staging
            / "pkg1"
            / "linux"
            / "22.04"
            / "x86_64"
            / "release"
            / "release.yaml"
        )
        self.assertEqual(cloned.stat().st_ino, inode)
        self.assertNotEqual(pkg, cloned)


class TestTamperRecovery(InstallTreeTestCase):
    """The symlink is one `rm` away from being wrong. Detect it, do not trust it."""

    def _commit(self, version):
        self._write_pkg(it.stage_version(self.release, version), "pkg1", version)
        it.commit_version(self.release, version)

    def test_dangling_symlink_is_not_reported_as_installed(self):
        """Trusting it would report a version that is not on disk to the server."""
        self._commit("1.0.0")
        self._commit("2.0.0")
        shutil.rmtree(self.release / "versions" / "0002-2.0.0")

        self.assertIsNone(it.current_version(self.release))

    def test_dangling_symlink_heals_to_a_surviving_version(self):
        self._commit("1.0.0")
        self._commit("2.0.0")
        shutil.rmtree(self.release / "versions" / "0002-2.0.0")

        it.ensure_tree(self.release)

        self.assertEqual(it.current_version(self.release), "1.0.0")
        self.assertIn(
            "1.0.0",
            (
                self.release
                / "install"
                / "pkg1"
                / "linux"
                / "22.04"
                / "x86_64"
                / "release"
                / "release.yaml"
            ).read_text(),
        )

    def test_deleted_symlink_is_relinked_to_the_newest_version(self):
        """`rm -rf release/install` removes the link; the packages survive."""
        self._commit("1.0.0")
        self._commit("2.0.0")
        (self.release / "install").unlink()

        it.ensure_tree(self.release)

        self.assertEqual(it.current_version(self.release), "2.0.0")

    def test_recovery_is_a_noop_when_nothing_was_touched(self):
        self._commit("1.0.0")
        self._commit("2.0.0")

        it.ensure_tree(self.release)

        self.assertEqual(it.current_version(self.release), "2.0.0")
        self.assertEqual(it.previous_version(self.release), "1.0.0")

    def test_symlink_replaced_by_a_real_directory_is_absorbed(self):
        self._commit("1.0.0")
        (self.release / "install").unlink()
        restored = self.release / "install"
        self._write_pkg(restored, "pkg1", "restored")

        it.ensure_tree(self.release)

        self.assertTrue((self.release / "install").is_symlink())
        self.assertIn(
            "restored",
            (
                self.release
                / "install"
                / "pkg1"
                / "linux"
                / "22.04"
                / "x86_64"
                / "release"
                / "release.yaml"
            ).read_text(),
        )

    def test_no_versions_and_no_link_is_left_alone(self):
        it.ensure_tree(self.release)

        self.assertFalse((self.release / "install").exists())

    def test_stale_previous_pointer_is_ignored(self):
        """Deleting the rollback target must not leave rollback claiming to work."""
        self._commit("1.0.0")
        self._commit("2.0.0")
        shutil.rmtree(self.release / "versions" / "0001-1.0.0")

        self.assertIsNone(it.previous_version(self.release))
        self.assertIsNone(it.rollback(self.release))
        self.assertEqual(it.current_version(self.release), "2.0.0")


class TestRollback(InstallTreeTestCase):
    def test_rollback_restores_the_previous_version(self):
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1", "old")
        it.commit_version(self.release, "1.0.0")
        self._write_pkg(it.stage_version(self.release, "2.0.0"), "pkg1", "new")
        it.commit_version(self.release, "2.0.0")

        restored = it.rollback(self.release)

        self.assertEqual(restored, "1.0.0")
        self.assertEqual(it.current_version(self.release), "1.0.0")
        content = (
            self.release
            / "install"
            / "pkg1"
            / "linux"
            / "22.04"
            / "x86_64"
            / "release"
            / "release.yaml"
        ).read_text()
        self.assertIn("old", content)

    def test_rollback_without_a_previous_version_reports_it(self):
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1")
        it.commit_version(self.release, "1.0.0")

        self.assertIsNone(it.rollback(self.release))
        self.assertEqual(it.current_version(self.release), "1.0.0")


class TestRetention(InstallTreeTestCase):
    def _commit(self, version):
        self._write_pkg(it.stage_version(self.release, version), "pkg1", version)
        it.commit_version(self.release, version)

    def test_old_versions_are_pruned_to_the_keep_count(self):
        for v in ("1.0.0", "2.0.0", "3.0.0", "4.0.0"):
            self._commit(v)

        it.prune_versions(self.release, keep=2)

        kept = sorted(
            p.name.split("-", 1)[1] for p in (self.release / "versions").iterdir()
        )
        self.assertEqual(kept, ["3.0.0", "4.0.0"])

    def test_pruning_never_removes_the_live_or_previous_version(self):
        self._commit("1.0.0")
        self._commit("2.0.0")

        it.prune_versions(self.release, keep=1)

        kept = sorted(
            p.name.split("-", 1)[1] for p in (self.release / "versions").iterdir()
        )
        self.assertIn("2.0.0", kept)  # live
        self.assertIn("1.0.0", kept)  # rollback target


if __name__ == "__main__":
    unittest.main()
