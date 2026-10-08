"""What setup hashes to decide whether a pure_cmake project changed.

raisin_third_party_common/raisim downloads its raisim2Lib release into
raisim/.download (hundreds of MB, git-ignored) next to its CMakeLists.txt.
Hidden directories hold no sources, so they stay out of the hash: reading the
download on every setup is slow, and it would change the hash the first time
the project is configured.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from commands import setup as cli_setup  # noqa: E402


class TestPureCmakeSourceHash(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.project = Path(self._tmp.name) / "raisim"
        self.project.mkdir()
        (self.project / "CMakeLists.txt").write_text("project(raisim)\n")
        (self.project / "src").mkdir()
        (self.project / "src" / "a.cpp").write_text("int a;\n")

    def hash(self):
        return cli_setup._compute_source_hash(self.project)

    def test_hidden_directories_are_not_hashed(self):
        before = self.hash()
        download = self.project / ".download" / "2.8.0" / "linux-x86"
        download.mkdir(parents=True)
        (download / "linux-x86-2.8.0.zip").write_bytes(b"zip")
        (download / "extracted").mkdir()
        (download / "extracted" / "raisimConfig.cmake").write_text("# config\n")
        (self.project / "src" / ".cache").mkdir()
        (self.project / "src" / ".cache" / "b.cpp").write_text("int b;\n")
        self.assertEqual(before, self.hash())

    def test_hidden_files_are_not_hashed(self):
        before = self.hash()
        (self.project / ".gitignore").write_text("/.download/\n")
        self.assertEqual(before, self.hash())

    def test_broken_symlinks_are_skipped(self):
        before = self.hash()
        (self.project / "src" / "dangling.cpp").symlink_to(self.project / "missing.cpp")
        self.assertEqual(before, self.hash())

    def test_sources_are_hashed(self):
        before = self.hash()
        (self.project / "src" / "a.cpp").write_text("int a = 1;\n")
        changed = self.hash()
        self.assertNotEqual(before, changed)
        (self.project / "src" / "b.cpp").write_text("int b;\n")
        self.assertNotEqual(changed, self.hash())


if __name__ == "__main__":
    unittest.main()
