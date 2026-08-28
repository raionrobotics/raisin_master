"""Cross-process contract for the install tree, queue and session lock."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from raisin_ota import InstallStateBusy, install_state_lock


class InstallStateLockTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workspace = Path(self._tmp.name)

    def protected_snapshot(self):
        protected = [
            self.workspace / "release" / "install" / "live.txt",
            self.workspace / "release" / "download.part",
            self.workspace / ".ota" / "session" / "current",
            self.workspace / ".ota" / "events" / "event.json",
        ]
        return {
            str(path.relative_to(self.workspace)): (
                path.read_bytes() if path.is_file() else None
            )
            for path in protected
        }

    def seed_protected_state(self):
        values = {
            self.workspace / "release" / "install" / "live.txt": b"live",
            self.workspace / "release" / "download.part": b"partial",
            self.workspace / ".ota" / "session" / "current": b"session-1",
            self.workspace / ".ota" / "events" / "event.json": b"event-1",
        }
        for path, value in values.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)

    def child_holding(self, name):
        code = """
import sys
from raisin_ota import install_state_lock

workspace, holder = sys.argv[1], sys.argv[2]
with install_state_lock(workspace, holder):
    print("READY", flush=True)
    sys.stdin.read(1)
"""
        process = subprocess.Popen(
            [sys.executable, "-c", code, str(self.workspace), name],
            cwd=Path(__file__).parent,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self.stop_child, process)
        self.assertEqual(process.stdout.readline().strip(), "READY")
        return process

    @staticmethod
    def stop_child(process):
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


class TestContention(InstallStateLockTestCase):
    def test_second_agent_fails_fast_and_names_the_holder(self):
        process = self.child_holding("raisin-ota-agent")

        with self.assertRaises(InstallStateBusy) as caught:
            with install_state_lock(self.workspace, "raisin-ota-agent"):
                self.fail("two agents entered the same install state")

        message = str(caught.exception)
        self.assertIn("raisin-ota-agent", message)
        self.assertIn(f"pid {process.pid}", message)

    def test_cli_loses_to_agent_without_changing_shared_state(self):
        self.seed_protected_state()
        before = self.protected_snapshot()
        self.child_holding("raisin-ota-agent")

        with self.assertRaises(InstallStateBusy):
            with install_state_lock(self.workspace, "raisin install"):
                self.fail("the CLI entered state held by the agent")

        self.assertEqual(self.protected_snapshot(), before)

    def test_unrelated_workspaces_do_not_block_each_other(self):
        other = self.workspace / "other"
        other.mkdir()

        with install_state_lock(self.workspace, "first"):
            with install_state_lock(other, "second"):
                pass


class TestRelease(InstallStateLockTestCase):
    def test_normal_exit_releases_the_lock(self):
        with install_state_lock(self.workspace, "first"):
            pass

        with install_state_lock(self.workspace, "second"):
            pass

    def test_killed_holder_releases_the_lock(self):
        process = self.child_holding("crashing agent")

        process.kill()
        process.wait(timeout=5)

        with install_state_lock(self.workspace, "replacement agent"):
            pass


class TestLockPathSafety(InstallStateLockTestCase):
    @unittest.skipUnless(hasattr(os, "symlink"), "symlink required")
    def test_a_symlink_is_not_followed_by_a_privileged_agent(self):
        victim = self.workspace / "victim"
        victim.write_text("do not overwrite", encoding="utf-8")
        (self.workspace / ".raisin-install.lock").symlink_to(victim)

        with self.assertRaises(RuntimeError):
            with install_state_lock(self.workspace, "agent"):
                pass

        self.assertEqual(victim.read_text(encoding="utf-8"), "do not overwrite")


if __name__ == "__main__":
    unittest.main()
