"""Tests for the versioned install tree and its atomic commit point.

Layout:

    release/versions/<version>/   complete package tree for one archive version
    release/install -> versions/<version>    the only thing that goes live

`release/install` keeps its path so existing consumers (repo_dependency_check,
index) are unaffected; only its type changes, from directory to symlink.
"""

import errno
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from raisin_ota import install_tree as it  # noqa: E402
from raisin_ota import durable  # noqa: E402


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

    def test_recovery_ignores_a_newer_abandoned_staging_tree(self):
        self._commit("1.0.0")
        self._write_pkg(it.stage_version(self.release, "2.0.0"), "pkg1", "partial")
        (self.release / "install").unlink()

        it.ensure_tree(self.release)

        self.assertEqual(it.current_version(self.release), "1.0.0")

    def test_first_interrupted_install_is_not_activated_by_recovery(self):
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1", "partial")

        it.ensure_tree(self.release)

        self.assertFalse((self.release / "install").is_symlink())
        self.assertIsNone(it.current_version(self.release))

    def test_failed_staging_marker_preserves_the_previous_tree_and_recovery(self):
        self._commit("1.0.0")
        previous = (self.release / "install").resolve()
        write = Path.write_text

        def fail_marker(path, *args, **kwargs):
            if path.name == it._STAGING_MARKER:
                raise OSError(errno.ENOSPC, "cannot record staging marker")
            return write(path, *args, **kwargs)

        with patch.object(Path, "write_text", fail_marker):
            with self.assertRaises(OSError):
                it.stage_version(self.release, "2.0.0")
        self.assertEqual((self.release / "install").resolve(), previous)
        self.assertEqual(list(it.versions_dir(self.release).iterdir()), [previous])
        (self.release / "install").unlink()
        it.ensure_tree(self.release)
        self.assertEqual((self.release / "install").resolve(), previous)

    def test_first_install_marker_failure_cannot_leave_a_recoverable_tree(self):
        with patch.object(Path, "write_text", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                it.stage_version(self.release, "1.0.0")
        it.ensure_tree(self.release)
        self.assertIsNone(it.current_version(self.release))
        self.assertFalse((self.release / "install").exists())
        self.assertEqual(list(it.versions_dir(self.release).iterdir()), [])

    def test_failed_switch_keeps_the_staging_marker_until_cleanup(self):
        self._commit("1.0.0")
        staged = it.stage_version(self.release, "2.0.0")
        self._write_pkg(staged, "pkg1", "new")
        with patch.object(
            it, "_point_current_at", side_effect=OSError("cannot switch")
        ):
            with self.assertRaises(OSError):
                it.commit_version(self.release, "2.0.0")
        self.assertTrue((staged / ".staging").is_file())
        (self.release / "install").unlink()

        it.ensure_tree(self.release)

        self.assertEqual(it.current_version(self.release), "1.0.0")

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

    def test_rollback_without_a_previous_version_goes_back_to_nothing(self):
        """A first install: before it there was no version, so none is live.

        Replaces `test_rollback_without_a_previous_version_reports_it`
        (raisin_master#123), which asserted the version stayed live -- the
        pointer left on a failed first install that this PR fixes.
        """
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1")
        it.commit_version(self.release, "1.0.0")

        self.assertIsNone(it.rollback(self.release))
        self.assertIsNone(it.current_version(self.release))
        self.assertFalse((self.release / "install").is_symlink())

    def test_the_next_repair_does_not_relink_a_first_install_rolled_back(self):
        """Left committed, `ensure_tree` would put the link back a poll later."""
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1")
        it.commit_version(self.release, "1.0.0")
        it.rollback(self.release)

        it.ensure_tree(self.release)

        self.assertIsNone(it.current_version(self.release))

    def test_a_first_install_rolled_back_is_pruned(self):
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1")
        it.commit_version(self.release, "1.0.0")
        it.rollback(self.release)

        it.prune_versions(self.release)

        self.assertEqual(list((self.release / "versions").iterdir()), [])

    def test_the_next_install_after_it_starts_from_nothing(self):
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1")
        it.commit_version(self.release, "1.0.0")
        it.rollback(self.release)

        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1")
        it.commit_version(self.release, "1.0.0")

        self.assertEqual(it.current_version(self.release), "1.0.0")
        self.assertIsNone(it.previous_version(self.release))

    def test_a_rollback_record_that_is_not_text_is_not_read_as_none(self):
        """Corrupted bytes are not "no version before": the live one stays.

        The earlier release's `.previous-version` is read only when this
        release's record is absent -- a robot that last committed before it.
        """
        self._write_pkg(it.stage_version(self.release, "1.0.0"), "pkg1")
        it.commit_version(self.release, "1.0.0")
        (self.release / ".rollback").unlink()
        (self.release / ".previous-version").write_bytes(b"\xff\xfe\x00")

        self.assertIsNone(it.rollback(self.release))
        self.assertEqual(it.current_version(self.release), "1.0.0")

    def test_rollback_with_nothing_live_changes_nothing(self):
        self.assertIsNone(it.rollback(self.release))
        self.assertFalse((self.release / "install").exists())

    def test_rollback_leaves_someone_elses_link_alone(self):
        elsewhere = self.release.parent / "elsewhere"
        elsewhere.mkdir()
        (self.release / "install").symlink_to(elsewhere)

        self.assertIsNone(it.rollback(self.release))
        self.assertTrue((self.release / "install").is_symlink())


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

    def test_second_commit_under_one_session_is_undone_on_its_own(self):
        """Changed from "keeps the original rollback target" (raisin_master#123).

        `--install-all` was removed in 46a940c, and it was the only caller that
        committed twice for one install. `session` is now accepted and ignored:
        a failed install keeps its session so the retry can resume it, and the
        retry's commit was taken for the same install committing twice -- see
        `TestRollbackUndoesTheLastCommitOnce`.
        """
        self._commit("1.0.0", marker="good")
        self._commit("2.0.0-debug", session="s1", marker="debug")
        self._commit("2.0.0", session="s1", marker="release")

        self.assertEqual(it.current_version(self.release), "2.0.0")
        self.assertEqual(it.previous_version(self.release), "2.0.0-debug")

    def test_rollback_after_two_commits_under_one_session_undoes_the_last(self):
        """Changed from "restores the pre-attempt tree" (raisin_master#123).

        Same reason as the test above: `--install-all` was removed in 46a940c,
        and `session` is accepted and ignored.
        """
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
        self.assertIn("debug", content)

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


class TestAVersionCannotLeaveTheTree(InstallTreeTestCase):
    """The version naming a directory comes from the server.

    `stage_version` built `versions/<gen>-<version>` straight from it. Measured
    before writing this, on a throwaway tree:

        '1.0.0'                        -> release/versions/0001-1.0.0        inside
        '../ESCAPED'                   -> release/versions/0002-../ESCAPED   inside
        '1.0/../../../OUTSIDE/pwned'   -> OUTSIDE/pwned                      OUTSIDE

    The generation prefix quietly defeats a bare `..` — `0002-..` is a literal
    directory name, not the parent — which is why this needs a separator to
    work and why it is easy to look at and conclude it is safe. With one, the
    path leaves `versions/` entirely, and the process writing it is root on a
    robot.

    Refused rather than sanitised. A version with a separator in it is not a
    version this tool can install, and rewriting it into something acceptable
    would put a tree on disk under a name the server does not know.
    """

    def staged_names(self):
        base = it.versions_dir(self.release)
        return sorted(p.name for p in base.iterdir()) if base.is_dir() else []

    def test_an_ordinary_version_still_stages(self):
        staged = it.stage_version(self.release, "1.0.0")

        self.assertTrue(staged.is_dir())
        self.assertEqual(self.staged_names(), ["0001-1.0.0"])

    def test_a_version_with_a_separator_is_refused(self):
        with self.assertRaises(ValueError):
            it.stage_version(self.release, "1.0/../../../OUTSIDE/pwned")

    def test_refusing_leaves_nothing_behind(self):
        """Not even the parent. `mkdir(parents=True)` ran before the path was used."""
        with self.assertRaises(ValueError):
            it.stage_version(self.release, "1.0/../../../OUTSIDE/pwned")

        self.assertEqual(self.staged_names(), [])
        self.assertFalse((self.release.parent / "OUTSIDE").exists())

    def test_a_backslash_is_refused_too(self):
        """Not the separator here, but the metadata travels between machines."""
        with self.assertRaises(ValueError):
            it.stage_version(self.release, "1.0\\..\\..\\x")

    def test_a_bare_parent_reference_is_refused_even_though_the_prefix_defeats_it(self):
        """The prefix is not a guard — it is a coincidence of the naming scheme.

        Left accepted, a later change to the prefix turns it into an escape
        with no test failing.
        """
        with self.assertRaises(ValueError):
            it.stage_version(self.release, "..")

    def test_an_empty_version_is_refused(self):
        with self.assertRaises(ValueError):
            it.stage_version(self.release, "")

    def test_a_null_byte_is_refused_with_something_an_operator_can_read(self):
        """Python raises `ValueError: embedded null byte` here on its own.

        So asserting only the exception type proved nothing — the check could be
        deleted and the test would still pass, which is what a mutation run
        showed. What this guard adds is the *message*: which field, and what was
        in it. `embedded null byte` names neither, and arrives from somewhere
        under `pathlib` rather than from the value the server sent.
        """
        # No separator in it, deliberately. `"1.0\\x00/etc"` was caught by the
        # separator clause instead, so the null check could still be deleted
        # with everything green — the second time this one test passed for a
        # reason that was not the thing it names.
        with self.assertRaises(ValueError) as caught:
            it.stage_version(self.release, "1.0\x00etc")

        self.assertIn("version", str(caught.exception))

    def test_the_refusal_names_the_value(self):
        """An operator reading `systemctl status` has to see what was rejected."""
        with self.assertRaises(ValueError) as caught:
            it.stage_version(self.release, "1.0/../x")

        self.assertIn("1.0/../x", str(caught.exception))


class TestRollbackUndoesTheLastCommitOnce(InstallTreeTestCase):
    """A rollback undoes the commit before it, and only that one, once.

    It used to be inferred: `.previous-version` moved on every commit and
    rollback, a commit under the session that committed last skipped it, and a
    missing file was read as a first install. A failed install keeps its
    session so the retry can resume it, so the retry's commit recorded nothing
    -- and the rollback after it took a robot with a version back to none.

    Now each commit writes `release/.rollback` before the link moves, and a
    rollback consumes it.
    """

    def _commit(self, version, marker=None, session=None):
        self._write_pkg(
            it.stage_version(self.release, version), "pkg1", marker or version
        )
        return it.commit_version(self.release, version, session=session)

    def _live_marker(self):
        return (
            self.release
            / "install"
            / "pkg1"
            / "linux"
            / "22.04"
            / "x86_64"
            / "release"
            / "release.yaml"
        ).read_text()

    def test_every_retry_under_the_same_session_goes_back_to_the_version_before(
        self,
    ):
        """Found in review: the second retry went to none, the third to the failure."""
        self._commit("1.0.0", marker="good")
        for _ in range(3):
            it.ensure_tree(self.release)
            self._commit("2.0.0", marker="bad", session="S")

            self.assertEqual(it.rollback(self.release), "1.0.0")
            self.assertEqual(it.current_version(self.release), "1.0.0")
        self.assertIn("good", self._live_marker())

    def test_a_session_is_accepted_and_ignored(self):
        """`session` stays in the signature for the callers that pass it, and
        nothing reads it.

        It marked commits of one install, so that a second kept the first's
        rollback target. A failed install keeps its session so the retry can
        resume it, so the retry's commit was taken for the same install
        committing twice and recorded nothing to go back to -- the defect above.
        Telling one install from the next is not something a session can do,
        and the only caller that committed twice for one install, `--all`, was
        removed in 46a940c. So each commit is undone on its own, whatever
        session it carries. `TestMultiCommitAttempt` above was changed to say
        the same.
        """
        self._commit("1.0.0")
        self._commit("2.0.0-debug", session="s1")
        self._commit("2.0.0", session="s1")

        self.assertEqual(it.previous_version(self.release), "2.0.0-debug")
        self.assertEqual(it.rollback(self.release), "2.0.0-debug")
        self.assertIsNone(it.rollback(self.release))

    def test_a_second_rollback_with_no_commit_between_changes_nothing(self):
        """Found in review: it took the restored version away, and pruning deleted it."""
        self._commit("1.0.0")
        self._commit("2.0.0")
        it.rollback(self.release)

        self.assertIsNone(it.rollback(self.release))
        it.ensure_tree(self.release)
        it.prune_versions(self.release, keep=1)

        self.assertEqual(it.current_version(self.release), "1.0.0")

    def test_the_version_rolled_back_from_is_never_relinked(self):
        self._commit("1.0.0")
        self._commit("2.0.0")
        it.rollback(self.release)
        (self.release / "install").unlink()

        it.ensure_tree(self.release)

        self.assertEqual(it.current_version(self.release), "1.0.0")

    def test_the_version_rolled_back_from_is_pruned(self):
        self._commit("1.0.0")
        self._commit("2.0.0")
        it.rollback(self.release)

        it.prune_versions(self.release)

        kept = [p.name for p in (self.release / "versions").iterdir()]
        self.assertEqual(kept, ["0001-1.0.0"])

    def test_a_rollback_stopped_part_way_finishes_when_repeated(self):
        """Killed after the link moved and before the record went."""
        self._commit("1.0.0")
        self._commit("2.0.0")
        with patch.object(it, "_clear_rollback", side_effect=OSError("killed")):
            with self.assertRaises(OSError):
                it.rollback(self.release)
        self.assertEqual(it.current_version(self.release), "1.0.0")

        self.assertEqual(it.rollback(self.release), "1.0.0")
        self.assertIsNone(it.rollback(self.release))
        self.assertEqual(it.current_version(self.release), "1.0.0")

    def test_a_first_install_rollback_stopped_part_way_finishes_when_repeated(self):
        self._commit("1.0.0")
        with patch.object(it, "_clear_rollback", side_effect=OSError("killed")):
            with self.assertRaises(OSError):
                it.rollback(self.release)
        self.assertIsNone(it.current_version(self.release))

        self.assertIsNone(it.rollback(self.release))
        it.ensure_tree(self.release)
        self.assertIsNone(it.current_version(self.release))
        self.assertFalse((self.release / ".rollback").exists())

    def test_a_commit_whose_switch_failed_is_undone_without_moving_anything(self):
        """The record is written before the link moves, so it may name a switch
        that never happened."""
        self._commit("1.0.0")
        it.stage_version(self.release, "2.0.0")
        with patch.object(it, "_point_current_at", side_effect=OSError("refused")):
            with self.assertRaises(OSError):
                it.commit_version(self.release, "2.0.0")

        self.assertEqual(it.rollback(self.release), "1.0.0")
        self.assertEqual(it.current_version(self.release), "1.0.0")

    def test_a_commit_that_cannot_be_recorded_does_not_switch(self):
        """A link moved with nothing to undo it is the failure this record ends."""
        self._commit("1.0.0")
        it.stage_version(self.release, "2.0.0")
        with patch.object(it, "_write_rollback", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                it.commit_version(self.release, "2.0.0")

        self.assertEqual(it.current_version(self.release), "1.0.0")

    def test_a_record_that_cannot_be_read_changes_nothing(self):
        """Not knowing where to go is not "no version before": the live one stays."""
        self._commit("1.0.0")
        (self.release / ".rollback").write_bytes(b"\xff\xfe\x00")

        self.assertIsNone(it.rollback(self.release))
        self.assertEqual(it.current_version(self.release), "1.0.0")

    def test_a_link_moved_by_someone_else_is_left_where_they_put_it(self):
        self._commit("1.0.0")
        self._commit("2.0.0")
        self._commit("3.0.0")
        os.remove(self.release / "install")
        (self.release / "install").symlink_to(Path("versions") / "0001-1.0.0")

        self.assertIsNone(it.rollback(self.release))
        self.assertEqual(it.current_version(self.release), "1.0.0")

    def test_no_record_at_all_is_not_read_as_a_first_install(self):
        self._commit("1.0.0")
        (self.release / ".rollback").unlink()

        self.assertIsNone(it.rollback(self.release))
        self.assertEqual(it.current_version(self.release), "1.0.0")

    def test_a_robot_that_committed_before_this_record_still_rolls_back(self):
        """What an earlier release left: `.previous-version` and no record."""
        self._commit("1.0.0")
        self._commit("2.0.0")
        (self.release / ".rollback").unlink()
        (self.release / ".previous-version").write_text("0001-1.0.0")

        self.assertEqual(it.rollback(self.release), "1.0.0")
        self.assertFalse((self.release / ".previous-version").exists())

    def test_a_record_left_behind_by_a_downgrade_changes_nothing(self):
        """An earlier release committed after this record and left it stale.

        Its `.previous-version` is not taken to outrank the record -- that
        would be guessing which file is newer. The record no longer names the
        live version, so the rollback does nothing.
        """
        self._commit("1.0.0")
        self._commit("2.0.0")
        (self.release / ".previous-version").write_text("0002-2.0.0")
        os.remove(self.release / "install")
        self._write_pkg(it.stage_version(self.release, "3.0.0"), "pkg1", "3.0.0")
        (self.release / "versions" / "0003-3.0.0" / ".staging").unlink()
        (self.release / "install").symlink_to(Path("versions") / "0003-3.0.0")

        self.assertIsNone(it.rollback(self.release))
        self.assertEqual(it.current_version(self.release), "3.0.0")

    def test_a_rollback_with_the_link_removed_goes_back_to_the_version_before(self):
        """Found in review: with no link the rollback did nothing, and the next
        `ensure_tree` relinked the version it was asked to undo."""
        self._commit("1.0.0", marker="good")
        self._commit("2.0.0", marker="bad")
        os.remove(self.release / "install")

        self.assertEqual(it.rollback(self.release), "1.0.0")
        it.ensure_tree(self.release)
        self.assertEqual(it.current_version(self.release), "1.0.0")
        self.assertIn("good", self._live_marker())

    def test_a_commit_clears_what_an_earlier_release_recorded(self):
        (self.release / ".previous-version").write_text("0009-gone")
        (self.release / ".current-session").write_text("s1")

        self._commit("1.0.0")

        self.assertFalse((self.release / ".previous-version").exists())
        self.assertFalse((self.release / ".current-session").exists())

    def test_it_says_beforehand_when_a_rollback_goes_back_to_none(self):
        self._commit("1.0.0")
        self.assertTrue(it.rolls_back_to_none(self.release))

        self._commit("2.0.0")
        self.assertFalse(it.rolls_back_to_none(self.release))

        it.rollback(self.release)
        self.assertFalse(it.rolls_back_to_none(self.release))

    def test_it_does_not_say_none_for_a_rollback_it_would_refuse(self):
        """Found in review: with the link moved to another disk after a first
        install, it said none while `rollback` refused the foreign link -- and
        the agent removed the runtime tree on its word."""
        self._commit("1.0.0")
        elsewhere = Path(self._tmp.name) / "other-disk" / "0001-1.0.0"
        elsewhere.mkdir(parents=True)
        os.remove(self.release / "install")
        (self.release / "install").symlink_to(elsewhere)

        self.assertFalse(it.rolls_back_to_none(self.release))
        self.assertIsNone(it.rollback(self.release))
        self.assertEqual(os.readlink(self.release / "install"), str(elsewhere))

    def test_it_says_what_a_rollback_did_when_no_version_comes_back(self):
        """Found in review: None from `rollback` was a first install taken back
        to none, nothing to undo, and a refusal alike."""
        self._commit("1.0.0")
        self.assertEqual(
            it.undo_last_commit(self.release), (it.RollbackOutcome.TO_NONE, None)
        )
        self.assertEqual(
            it.undo_last_commit(self.release),
            (it.RollbackOutcome.NOTHING_TO_UNDO, None),
        )

        self._commit("1.0.0")
        self._commit("2.0.0")
        live = self.release / "install"
        moved_to = live.resolve()
        os.remove(live)
        live.symlink_to(moved_to)
        self.assertEqual(
            it.undo_last_commit(self.release), (it.RollbackOutcome.REFUSED, None)
        )

        os.remove(live)
        live.symlink_to(Path("versions") / moved_to.name)
        self.assertEqual(
            it.undo_last_commit(self.release), (it.RollbackOutcome.RESTORED, "1.0.0")
        )

    def test_a_directory_where_the_link_was_is_refused(self):
        """Found in review: read as no link, the rollback went ahead and raised
        IsADirectoryError -- after the agent, told it went back to none, had
        removed the runtime tree."""
        for versions in (["1.0.0"], ["1.0.0", "2.0.0"]):
            with self.subTest(versions=versions):
                shutil.rmtree(self.release)
                self.release.mkdir()
                for version in versions:
                    self._commit(version)
                live = self.release / "install"
                os.remove(live)
                live.mkdir()
                (live / "restored-by-hand").write_text("x", encoding="utf-8")

                self.assertFalse(it.rolls_back_to_none(self.release))
                self.assertEqual(
                    it.undo_last_commit(self.release),
                    (it.RollbackOutcome.REFUSED, None),
                )
                self.assertTrue((live / "restored-by-hand").is_file())

    def test_a_record_that_cannot_be_read_is_not_nothing_to_undo(self):
        """Found in review: a record torn by a power cut was "no record", and
        the health check said there was no previous version while 1.0.0 was
        there and the failed one stayed live."""
        self._commit("1.0.0")
        self._commit("2.0.0")
        for torn in (b"", b"\xff\xfe\x00", b'{"from": ""}', b"[]"):
            with self.subTest(torn=torn):
                (self.release / ".rollback").write_bytes(torn)

                self.assertEqual(
                    it.undo_last_commit(self.release),
                    (it.RollbackOutcome.UNUSABLE, None),
                )
                self.assertFalse(it.rolls_back_to_none(self.release))
                self.assertEqual(it.current_version(self.release), "2.0.0")

    def test_a_record_naming_something_outside_versions_is_unreadable(self):
        """From review: `..` or a separator in either end became a path -- the
        link pointed at `release` itself, or a marker was written outside
        `versions/`."""
        self._commit("1.0.0")
        self._commit("2.0.0")
        outside = Path(self._tmp.name) / "x"
        outside.mkdir()
        for name in ("..", "../../x", "0001-a/b", str(outside), "x"):
            for record in (
                {"from": name, "to": "0001-1.0.0"},
                {"from": "0002-2.0.0", "to": name},
            ):
                with self.subTest(record=record):
                    (self.release / ".rollback").write_text(
                        json.dumps(record), encoding="utf-8"
                    )

                    self.assertEqual(
                        it.undo_last_commit(self.release),
                        (it.RollbackOutcome.UNUSABLE, None),
                    )
                    self.assertEqual(it.current_version(self.release), "2.0.0")
                    self.assertEqual(list(outside.iterdir()), [])
                    self.assertFalse((self.release / ".staging").exists())

    def test_a_record_that_cannot_be_written_keeps_an_earlier_releases_file(self):
        """From review: the earlier release's `.previous-version` was removed
        before the record was written, so a write that failed left nothing to
        go back with."""
        self._commit("1.0.0")
        self._commit("2.0.0")
        (self.release / ".rollback").unlink()
        (self.release / ".previous-version").write_text("0001-1.0.0", encoding="utf-8")
        self._write_pkg(it.stage_version(self.release, "3.0.0"), "pkg1", "3.0.0")

        with patch.object(durable, "write_durably", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                it.commit_version(self.release, "3.0.0")

        self.assertEqual(it.current_version(self.release), "2.0.0")
        self.assertTrue((self.release / ".previous-version").exists())
        self.assertEqual(it.rollback(self.release), "1.0.0")

    def test_a_record_naming_one_version_on_both_ends_is_unusable(self):
        """Never written by a commit, which records nothing for the live
        version; carried out, it marked the live version abandoned and said it
        was restored."""
        self._commit("1.0.0")
        self._commit("2.0.0")
        (self.release / ".rollback").write_text(
            json.dumps({"from": "0002-2.0.0", "to": "0002-2.0.0"}), encoding="utf-8"
        )

        self.assertEqual(
            it.undo_last_commit(self.release), (it.RollbackOutcome.UNUSABLE, None)
        )
        self.assertFalse(
            (self.release / "versions" / "0002-2.0.0" / ".staging").exists()
        )
        self.assertEqual(it.current_version(self.release), "2.0.0")

    def test_committing_the_live_version_keeps_the_last_commits_record(self):
        self._commit("1.0.0")
        self._commit("2.0.0")

        it.commit_version(self.release, "2.0.0")

        self.assertEqual(it.rollback(self.release), "1.0.0")

    def test_an_earlier_release_file_naming_something_outside_is_ignored(self):
        self._commit("1.0.0")
        self._commit("2.0.0")
        (self.release / ".rollback").unlink()
        (self.release / ".previous-version").write_text("..", encoding="utf-8")

        self.assertEqual(
            it.undo_last_commit(self.release),
            (it.RollbackOutcome.NOTHING_TO_UNDO, None),
        )
        self.assertEqual(it.current_version(self.release), "2.0.0")

    def _steps(self):
        """Record, in order, the flushes and the moves of the link."""
        steps = []
        write_durably, mark_staging = durable.write_durably, it._mark_staging
        point_current_at = it._point_current_at

        def durably(path, text):
            write_durably(path, text)
            steps.append(("durable", path.name))

        def marked(version_dir):
            mark_staging(version_dir)
            steps.append(("marked", version_dir.name))

        def pointed(release, dir_name):
            steps.append(("link", dir_name))
            point_current_at(release, dir_name)

        for module, name, fake in (
            (durable, "write_durably", durably),
            (it, "_mark_staging", marked),
            (it, "_point_current_at", pointed),
        ):
            patcher = patch.object(module, name, fake)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(it.os, "sync", lambda: steps.append(("sync",)))
        patcher.start()
        self.addCleanup(patcher.stop)
        return steps

    def test_a_commit_is_on_disk_before_the_link_names_it(self):
        """From review: a rename is atomic, not durable. A power cut after the
        switch could leave the record empty, or the link on a tree whose files
        never reached the disk."""
        self._commit("1.0.0")
        self._write_pkg(it.stage_version(self.release, "2.0.0"), "pkg1", "2.0.0")
        steps = self._steps()

        it.commit_version(self.release, "2.0.0")

        self.assertEqual(
            steps,
            [("sync",), ("durable", ".rollback"), ("link", "0002-2.0.0")],
        )

    def test_a_rollback_marks_what_it_undid_on_disk_before_moving_the_link(self):
        self._commit("1.0.0")
        self._commit("2.0.0")
        steps = self._steps()

        it.rollback(self.release)

        self.assertEqual(steps, [("marked", "0002-2.0.0"), ("link", "0001-1.0.0")])


class TestDurableWrites(unittest.TestCase):
    """`durable` is public for the OTA agent, so what it promises is tested
    here and not only through the tree."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)

    def test_it_replaces_the_file_whole_and_leaves_nothing_beside_it(self):
        path = self.directory / "state.json"
        path.write_text("old", encoding="utf-8")

        durable.write_durably(path, "new")

        self.assertEqual(path.read_text(encoding="utf-8"), "new")
        self.assertEqual([p.name for p in self.directory.iterdir()], ["state.json"])

    def test_it_flushes_the_file_and_then_its_directory(self):
        synced = []
        real_fsync = os.fsync

        def fsync(descriptor):
            synced.append(os.path.isdir(f"/proc/self/fd/{descriptor}"))
            real_fsync(descriptor)

        with patch.object(durable.os, "fsync", fsync):
            durable.write_durably(self.directory / "state.json", "x")

        self.assertEqual(synced, [False, True])

    def test_a_directory_that_cannot_be_flushed_is_not_an_error(self):
        durable.fsync_directory(self.directory / "missing")

    def test_a_failed_write_raises_and_leaves_the_file_and_nothing_else(self):
        """From review: the temporary file stayed behind after a failure, and
        its fixed name was safe only for a caller holding a lock."""
        path = self.directory / "state.json"
        path.write_text("old", encoding="utf-8")

        with patch.object(durable.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                durable.write_durably(path, "new")

        self.assertEqual(path.read_text(encoding="utf-8"), "old")
        self.assertEqual([p.name for p in self.directory.iterdir()], ["state.json"])

    def test_each_write_has_a_temporary_file_of_its_own(self):
        names = []
        real_replace = os.replace

        def replace(source, destination):
            names.append(Path(source).name)
            real_replace(source, destination)

        with patch.object(durable.os, "replace", replace):
            durable.write_durably(self.directory / "state.json", "1")
            durable.write_durably(self.directory / "state.json", "2")

        self.assertEqual(len(set(names)), 2)
        self.assertTrue(all(name.startswith(".state.json.") for name in names))


if __name__ == "__main__":
    unittest.main()
