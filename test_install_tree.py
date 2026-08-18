"""Tests for the versioned install tree and its atomic commit point.

Layout:

    release/versions/<version>/   complete package tree for one archive version
    release/install -> versions/<version>    the only thing that goes live

`release/install` keeps its path so existing consumers (repo_dependency_check,
index) are unaffected; only its type changes, from directory to symlink.
"""

import errno
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from raisin_ota import install_tree as it  # noqa: E402


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


class TestUnusableTreeIsReported(InstallTreeTestCase):
    """Giving a robot a bigger package partition is a normal thing to do.

    Mounting one at `release/install` puts it on a different filesystem from
    `release/versions`, and neither `rename` nor `os.link` crosses that
    boundary. The module docstring promises operations fail gracefully; they
    escaped as a traceback instead.
    """

    def test_a_cross_device_migration_names_the_cause(self):
        legacy = it.current_link(self.release)
        legacy.mkdir()
        (legacy / "raisin").mkdir()

        def cross_device(self_, target):
            raise OSError(errno.EXDEV, "Invalid cross-device link")

        with patch.object(Path, "rename", cross_device):
            with self.assertRaises(it.InstallTreeUnusable) as caught:
                it.ensure_tree(self.release)

        self.assertIn("filesystem", str(caught.exception))

    def test_a_clone_that_cannot_hardlink_is_reported(self):
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1", "1.0.0")
        it.commit_version(self.release, "1.0.0")

        with patch(
            "raisin_ota.install_tree.shutil.copytree",
            side_effect=OSError(errno.EXDEV, "Invalid cross-device link"),
        ):
            with self.assertRaises(it.InstallTreeUnusable):
                it.stage_version(self.release, "2.0.0")


class TestForeignSymlinks(InstallTreeTestCase):
    """A robot's package tree is often deliberately put on another disk.

    `release/install -> /mnt/data/raisin-install` is how an operator moves
    1.1GB off a small root filesystem. Recovery must not read that as its own
    broken link, because "fixing" it puts the next install back on the disk
    they moved it off — and says it repaired something while doing it.
    """

    def _operator_link(self):
        external = Path(self._tmp.name) / "data" / "install"
        external.mkdir(parents=True)
        (external / "raisin").mkdir()
        os.symlink(external, it.current_link(self.release))
        return external

    def test_a_link_to_another_disk_is_left_alone(self):
        external = self._operator_link()

        said = it.ensure_tree(self.release)

        self.assertIsNone(said)
        self.assertTrue(it.current_link(self.release).is_symlink())
        self.assertEqual(
            os.path.realpath(it.current_link(self.release)),
            os.path.realpath(external),
        )

    def test_a_link_to_another_disk_is_not_repointed_at_a_local_version(self):
        """With versions on disk the old code silently relocated the install."""
        external = self._operator_link()
        stale = it.versions_dir(self.release) / "0001-old"
        stale.mkdir(parents=True)

        it.ensure_tree(self.release)

        self.assertEqual(
            os.path.realpath(it.current_link(self.release)),
            os.path.realpath(external),
        )

    def test_our_own_dangling_link_is_still_recovered(self):
        """The recovery this replaces must keep working for links we made."""
        versions = it.versions_dir(self.release)
        (versions / "0001-1.0.0").mkdir(parents=True)
        os.symlink("versions/0002-2.0.0", it.current_link(self.release))

        it.ensure_tree(self.release)

        self.assertEqual(it.current_version(self.release), "1.0.0")


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


class TestMultiCommitAttempt(InstallTreeTestCase):
    """`raisin install --install-all` commits once per build type.

    Both commits belong to one attempt, so the rollback target must stay the
    state that existed before the attempt began — not the intermediate state
    the attempt itself produced.
    """

    def _commit(self, version, session=None, marker=None):
        self._write_pkg(
            it.stage_version(self.release, version), "pkg1", marker or version
        )
        return it.commit_version(self.release, version, session=session)

    def test_second_commit_of_one_attempt_keeps_the_original_rollback_target(self):
        self._commit("1.0.0", marker="good")  # the state to return to
        self._commit("2.0.0-debug", session="s1", marker="debug")
        self._commit("2.0.0", session="s1", marker="release")

        self.assertEqual(it.current_version(self.release), "2.0.0")
        self.assertEqual(it.previous_version(self.release), "1.0.0")

    def test_rollback_after_a_two_stage_attempt_restores_the_pre_attempt_tree(self):
        self._commit("1.0.0", marker="good")
        self._commit("2.0.0-debug", session="s1", marker="debug")
        self._commit("2.0.0", session="s1", marker="release")

        it.rollback(self.release)

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
        self.assertIn("good", content)

    def test_a_later_attempt_moves_the_rollback_target_forward(self):
        self._commit("1.0.0", session="s1", marker="first")
        self._commit("2.0.0", session="s2", marker="second")

        self.assertEqual(it.previous_version(self.release), "1.0.0")

    def test_commits_without_a_session_behave_as_before(self):
        self._commit("1.0.0")
        self._commit("2.0.0")

        self.assertEqual(it.previous_version(self.release), "1.0.0")


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

    def test_abandoned_staging_does_not_consume_retention_slots(self):
        """A crash between stage and commit leaves a tree nothing points at.

        Counting it toward `keep` makes the retention setting mean something
        other than what it says, and the orphans are the newest generations so
        they take the slots real versions should hold.
        """
        for v in ("1.0.0", "2.0.0", "3.0.0"):
            self._commit(v)
        for i in range(3):
            it.stage_version(self.release, f"9.9.{i}")  # never committed

        it.prune_versions(self.release, keep=2)

        kept = sorted(
            p.name.split("-", 1)[1] for p in (self.release / "versions").iterdir()
        )
        self.assertEqual(kept, ["2.0.0", "3.0.0"])

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
