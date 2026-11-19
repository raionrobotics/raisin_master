#!/usr/bin/env python3
"""
Tests that a published package archive depends only on what was built.

The OTA server identifies a package build by the hash of its zip, and a version
tag may point at one build only. Two builds of the same sources must therefore
produce the same bytes, whatever time they ran and whichever executor workspace
they ran in.

Usage:
    python3 test_publish_archive.py
    python3 -m unittest test_publish_archive
"""

import os
import stat
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from commands import globals as g
from commands import publish
from commands import setup as cli_setup


def make_install_tree(root: Path) -> Path:
    install = root / "install"
    (install / "lib").mkdir(parents=True)
    (install / "include" / "pkg").mkdir(parents=True)
    (install / "bin").mkdir()
    (install / "lib" / "libpkg.so").write_bytes(b"\x7fELF" + b"\x00" * 64)
    (install / "include" / "pkg" / "pkg.hpp").write_text("#pragma once\n")
    tool = install / "bin" / "pkg-tool"
    tool.write_text("#!/bin/sh\necho ok\n")
    tool.chmod(0o755)
    (install / "release.yaml").write_text("version: 1.2.3\n")
    return install


def archive_of(root: Path) -> bytes:
    paths = {"install_dir": root / "install", "release_dir": root / "release"}
    paths["release_dir"].mkdir(exist_ok=True)
    return publish._create_archive("pkg", "1.2.3", "release", paths).read_bytes()


class ReproducibleArchiveTest(unittest.TestCase):
    def setUp(self):
        self._saved = (g.os_type, g.os_version, g.architecture)
        g.os_type, g.os_version, g.architecture = "ubuntu", "24.04", "x86_64"

    def tearDown(self):
        g.os_type, g.os_version, g.architecture = self._saved

    def test_same_files_built_at_different_times_give_identical_archives(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            make_install_tree(Path(first))
            make_install_tree(Path(second))
            # A later build writes the same files with a different mtime.
            later = time.time() + 86400
            for path in (Path(second) / "install").rglob("*"):
                os.utime(path, (later, later))
            self.assertEqual(archive_of(Path(first)), archive_of(Path(second)))

    def test_archive_keeps_layout_and_executable_bits(self):
        with tempfile.TemporaryDirectory() as root:
            make_install_tree(Path(root))
            path = Path(root) / "release" / "pkg-ubuntu-24.04-x86_64-release-v1.2.3.zip"
            archive_of(Path(root))
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                self.assertIn("bin/", names)
                self.assertIn("include/pkg/pkg.hpp", names)
                # Unix, whatever platform built it: unzip applies the stored modes only then.
                self.assertEqual({i.create_system for i in archive.infolist()}, {3})
                modes = {i.filename: stat.S_IMODE(i.external_attr >> 16) for i in archive.infolist()}
                self.assertEqual(modes["bin/pkg-tool"], 0o755)
                self.assertEqual(modes["include/pkg/pkg.hpp"], 0o644)
                self.assertEqual(archive.read("bin/pkg-tool"), b"#!/bin/sh\necho ok\n")

    def test_creation_order_does_not_change_the_archive(self):
        # Directory listing order follows the filesystem, which differs between executors.
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for root, names in ((first, ["a.txt", "m.txt", "z.txt"]), (second, ["z.txt", "m.txt", "a.txt"])):
                install = Path(root) / "install"
                for sub in (names if root == first else list(reversed(names))):
                    (install / sub.replace(".txt", "")).mkdir(parents=True, exist_ok=True)
                for name in names:
                    (install / name).write_text(name)
            self.assertEqual(archive_of(Path(first)), archive_of(Path(second)))

    def test_files_are_streamed_not_read_whole(self):
        with tempfile.TemporaryDirectory() as root:
            make_install_tree(Path(root))
            original = Path.read_bytes
            def refuse(path):
                raise AssertionError(f"read whole: {path}")
            Path.read_bytes = refuse
            try:
                paths = {"install_dir": Path(root) / "install", "release_dir": Path(root) / "release"}
                paths["release_dir"].mkdir()
                archive = publish._create_archive("pkg", "1.2.3", "release", paths)
            finally:
                Path.read_bytes = original
            with zipfile.ZipFile(archive) as opened:
                self.assertEqual(opened.read("lib/libpkg.so"), b"\x7fELF" + b"\x00" * 64)

    def test_content_change_changes_the_archive(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            make_install_tree(Path(first))
            make_install_tree(Path(second))
            (Path(second) / "install" / "include" / "pkg" / "pkg.hpp").write_text("#pragma once\n// v2\n")
            self.assertNotEqual(archive_of(Path(first)), archive_of(Path(second)))


class ReleaseRecordTest(unittest.TestCase):
    def test_workspace_root_is_named_by_repository_not_by_folder(self):
        # Jenkins checks the workspace out as raisin_integration, raisin_integration@2,
        # test@2 ...; the folder name must not reach the release record.
        for folder in ("raisin_integration@2", "test@2", "raisin_master"):
            self.assertEqual(cli_setup.release_record_name(f"/ci/{folder}", f"/ci/{folder}"), "raisin_master")
        self.assertEqual(cli_setup.release_record_name("/ci/test@2/src/raisin_gui", "/ci/test@2"), "raisin_gui")

    def test_record_lines_do_not_depend_on_discovery_order(self):
        # Repositories are found in filesystem order, which differs between executors.
        with tempfile.TemporaryDirectory() as root:
            first, second = Path(root) / "a.txt", Path(root) / "b.txt"
            cli_setup.write_data(first, {"raisin_gui": "2" * 40, "raisin": "1" * 40})
            cli_setup.write_data(second, {"raisin": "1" * 40, "raisin_gui": "2" * 40})
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first.read_text(), f"raisin {'1' * 40}\nraisin_gui {'2' * 40}\n")


if __name__ == "__main__":
    unittest.main()
