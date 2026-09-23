#!/usr/bin/env python3
"""Unit tests for the build machine's fetch path (raisin_ota/build_machine.py).

These run against a real HTTP server on a loopback port rather than a mocked
`requests`. The difference matters: what is being tested is that this module
sends the credential in the header the server reads, walks the two paths the
server actually serves, and verifies the body it is given -- and a mock of
`requests.get` asserts only that the code called the mock the way the test
already assumed.

Usage:
    python test_build_machine.py
    python -m pytest test_build_machine.py -v
"""

import hashlib
import io
import json
import os
import shutil
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from raisin_ota import build_machine as bm


ARCHIVE_ID = "11111111-1111-4111-8111-111111111111"
SDK_ID = "22222222-2222-4222-8222-222222222222"
THIRD_PARTY_ID = "33333333-3333-4333-8333-333333333333"
GOOD_KEY = "pk_" + "a" * 40


def a_package(*files: tuple) -> bytes:
    """A package archive: a zip rooted at the prefix, as the publisher builds it."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files:
            archive.writestr(name, content)
    return buffer.getvalue()


SDK_ZIP = a_package(("include/raisin/version.hpp", "#define RAISIN 1\n"),
                    ("lib/libraisin.so", "not really an elf"))
THIRD_PARTY_ZIP = a_package(("include/vendor/json.hpp", "// vendored\n"),
                            ("lib/libvendor.so", "also not an elf"))
ESCAPING_ZIP = a_package(("../escaped.txt", "should never be written"))


class FakeOta(BaseHTTPRequestHandler):
    """The two hops the `pk_` surface serves, and nothing else."""

    archives = []          # what the listing answers with
    blobs = {}             # packageId -> zip bytes
    seen_keys = []         # every credential the server was shown
    ignore_filters = False # reproduce the server ignoring name/platform

    def log_message(self, *args):  # keep the test output clean
        pass

    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        FakeOta.seen_keys.append(self.headers.get(bm.PACKAGE_KEY_HEADER))
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]

        # Every path this serves is under the read surface. A request to any
        # other prefix is a 404 here, as it is on the server.
        if len(parts) < 2 or parts[0] != "api" or parts[1] != bm.READ_SURFACE:
            self._json(404, {"message": "no such route"})
            return

        if self.headers.get(bm.PACKAGE_KEY_HEADER) != GOOD_KEY:
            self._json(401, {"message": "unknown credential"})
            return

        rest = parts[2:]
        if rest == ["archives"]:
            query = parse_qs(url.query)
            found = FakeOta.archives
            if not FakeOta.ignore_filters:
                found = [
                    a
                    for a in found
                    if a["name"] == query.get("name", [None])[0]
                    and a["platform"] == query.get("platform", [None])[0]
                    and (
                        "version" not in query
                        or a["version"] == query["version"][0]
                    )
                ]
            self._json(200, {"data": {"archives": found, "total": len(found)}})
            return

        if len(rest) == 5 and rest[0] == "archives" and rest[4] == "download":
            blob = FakeOta.blobs.get(rest[3])
            if blob is None:
                self._json(404, {"message": "no such package here"})
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(blob)))
            self.send_header("X-Content-Hash", hashlib.sha256(blob).hexdigest())
            self.end_headers()
            self.wfile.write(blob)
            return

        self._json(404, {"message": "no such route"})


class BuildMachineFetch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FakeOta)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address
        cls.endpoint = f"http://{host}:{port}/api"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.into = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.into, ignore_errors=True)
        FakeOta.seen_keys = []
        FakeOta.ignore_filters = False
        FakeOta.blobs = {SDK_ID: SDK_ZIP, THIRD_PARTY_ID: THIRD_PARTY_ZIP}
        FakeOta.archives = [
            {
                "id": ARCHIVE_ID,
                "name": "raisin-robot",
                "version": "1.0.188",
                "platform": "ubuntu-24.04-x86_64",
                "packages": [
                    {"packageId": SDK_ID, "packageName": "raisin",
                     "tagName": "1.0.188"},
                    {"packageId": THIRD_PARTY_ID,
                     "packageName": "raisin_third_party_common",
                     "tagName": "1.0.188"},
                ],
            }
        ]

    def fetch(self, **kwargs):
        kwargs.setdefault("key", GOOD_KEY)
        kwargs.setdefault("endpoint", self.endpoint)
        return bm.fetch_archive(
            "raisin-robot", "ubuntu-24.04-x86_64", self.into / "sdk", **kwargs
        )

    # -- the credential ----------------------------------------------------

    def test_reads_the_key_from_the_environment(self):
        self.assertEqual(bm.package_key({bm.PACKAGE_KEY_ENV: GOOD_KEY}), GOOD_KEY)

    def test_refuses_a_missing_key_by_name(self):
        with self.assertRaises(bm.FetchRefused) as refused:
            bm.package_key({})
        self.assertIn(bm.PACKAGE_KEY_ENV, str(refused.exception))

    def test_refuses_a_credential_of_another_kind(self):
        # The paste an operator actually makes. Caught here rather than sent and
        # answered 401, which sends them reading about permissions instead.
        for wrong in ("rk_" + "b" * 40, "ik_" + "c" * 40, "et_" + "d" * 40):
            with self.assertRaises(bm.FetchRefused) as refused:
                bm.package_key({bm.PACKAGE_KEY_ENV: wrong})
            self.assertIn(wrong[:3], str(refused.exception))

    def test_sends_the_key_in_the_header_the_server_reads(self):
        self.fetch(packages=["raisin"])
        self.assertTrue(FakeOta.seen_keys)
        self.assertEqual(set(FakeOta.seen_keys), {GOOD_KEY})

    def test_a_refused_credential_says_so_rather_than_raising_for_status(self):
        with self.assertRaises(bm.FetchRefused) as refused:
            self.fetch(packages=["raisin"], key="pk_" + "z" * 40)
        self.assertIn("refused this credential", str(refused.exception))

    # -- the surface -------------------------------------------------------

    def test_reads_under_the_package_surface(self):
        # If this hung off the operator prefix instead, the fake would 404 --
        # which is what the real server does, because the operator routes are on
        # a tier a `pk_` key cannot reach at all.
        self.assertEqual(bm.read_base("https://example/api"),
                         "https://example/api/archive-read")
        self.fetch(packages=["raisin"])
        self.assertTrue((self.into / "sdk" / "include" / "raisin").is_dir())

    # -- what lands where --------------------------------------------------

    def test_unpacks_the_package_at_the_prefix_root(self):
        self.fetch(packages=["raisin"])
        # `-DRAISIN_SDK_PREFIX=` points at this directory, so these two paths
        # are the contract with the fixture build.
        self.assertTrue((self.into / "sdk" / "include" / "raisin" / "version.hpp").is_file())
        self.assertTrue((self.into / "sdk" / "lib" / "libraisin.so").is_file())

    def test_merges_two_packages_into_one_prefix(self):
        # The reason this tool exists rather than the robot's: one prefix, not a
        # directory per package.
        fetched = self.fetch(packages=["raisin", "raisin_third_party_common"])
        self.assertEqual(sorted(fetched), ["raisin", "raisin_third_party_common"])
        self.assertTrue((self.into / "sdk" / "include" / "raisin" / "version.hpp").is_file())
        self.assertTrue((self.into / "sdk" / "include" / "vendor" / "json.hpp").is_file())

    def test_takes_every_package_when_none_is_named(self):
        fetched = self.fetch()
        self.assertEqual(sorted(fetched), ["raisin", "raisin_third_party_common"])

    def test_leaves_no_download_file_behind(self):
        self.fetch(packages=["raisin"])
        self.assertEqual(list((self.into / "sdk").glob(".*.download")), [])

    def test_refuses_a_package_the_archive_does_not_carry(self):
        with self.assertRaises(bm.FetchRefused) as refused:
            self.fetch(packages=["raisin_gui"])
        # Names what is there, so the next attempt is informed.
        self.assertIn("raisin_third_party_common", str(refused.exception))

    # -- choosing the archive ---------------------------------------------

    def test_pins_a_version_exactly(self):
        FakeOta.archives.insert(0, dict(FakeOta.archives[0], version="1.0.999"))
        archive = bm.resolve_archive(
            "raisin-robot", "ubuntu-24.04-x86_64",
            key=GOOD_KEY, version="1.0.188", endpoint=self.endpoint,
        )
        self.assertEqual(archive["version"], "1.0.188")

    def test_accepts_either_spelling_of_a_pin(self):
        archive = bm.resolve_archive(
            "raisin-robot", "ubuntu-24.04-x86_64",
            key=GOOD_KEY, version="v1.0.188", endpoint=self.endpoint,
        )
        self.assertEqual(archive["version"], "1.0.188")

    def test_a_pin_that_is_not_there_refuses_rather_than_falls_back(self):
        """The `dso 1.0.3` defect: a pin that is absent must not become "newest".

        `ignore_filters` is the point of this test, not decoration. With the
        server filtering by version, asking for one that does not exist returns
        nothing and the empty-list refusal fires -- so the fallback this guards
        against is never reached and the test passes against code that has it.
        Measured: replacing the refusal below with `return matching[0]` kept the
        suite green until this line was added.

        What the server actually does is answer with the right name and platform
        and the *wrong version*, which is where a fallback silently hands a build
        machine a different SDK than its repository pinned.
        """
        FakeOta.ignore_filters = True
        with self.assertRaises(bm.FetchRefused) as refused:
            bm.resolve_archive(
                "raisin-robot", "ubuntu-24.04-x86_64",
                key=GOOD_KEY, version="2.0.0", endpoint=self.endpoint,
            )
        self.assertIn("no version 2.0.0", str(refused.exception))

    def test_takes_the_newest_when_no_version_is_pinned(self):
        FakeOta.archives.insert(0, dict(FakeOta.archives[0], version="1.0.999"))
        archive = bm.resolve_archive(
            "raisin-robot", "ubuntu-24.04-x86_64",
            key=GOOD_KEY, endpoint=self.endpoint,
        )
        self.assertEqual(archive["version"], "1.0.999")

    def test_filters_again_when_the_server_ignores_the_filters(self):
        # Observed behaviour, not a hypothetical: the listing has answered with
        # archives of another name *and* another architecture. An x86 build
        # machine handed an arm64 SDK links and then fails somewhere else.
        FakeOta.ignore_filters = True
        FakeOta.archives = [
            {"id": "other", "name": "raisin-warehouse", "version": "9",
             "platform": "ubuntu-24.04-arm64", "packages": []}
        ]
        with self.assertRaises(bm.FetchRefused) as refused:
            bm.resolve_archive(
                "raisin-robot", "ubuntu-24.04-x86_64",
                key=GOOD_KEY, endpoint=self.endpoint,
            )
        self.assertIn("No available archive", str(refused.exception))

    def test_says_so_when_there_is_no_such_archive(self):
        FakeOta.archives = []
        with self.assertRaises(bm.FetchRefused):
            self.fetch(packages=["raisin"])

    # -- the destination ---------------------------------------------------

    def test_refuses_a_destination_that_is_not_empty(self):
        # Two SDK versions unpacked over each other leave headers and libraries
        # that disagree, and the first symptom is a link error a long way away.
        target = self.into / "sdk"
        target.mkdir()
        (target / "leftover").write_text("from an earlier run")
        with self.assertRaises(bm.FetchRefused) as refused:
            self.fetch(packages=["raisin"])
        self.assertIn("--clean", str(refused.exception))

    def test_clean_replaces_what_was_there(self):
        target = self.into / "sdk"
        target.mkdir()
        (target / "leftover").write_text("from an earlier run")
        self.fetch(packages=["raisin"], clean=True)
        self.assertFalse((target / "leftover").exists())
        self.assertTrue((target / "include" / "raisin" / "version.hpp").is_file())

    def test_refuses_an_entry_that_would_escape_the_prefix(self):
        # `extractall` resolves `../` against the destination, so one entry is
        # enough to write outside it.
        FakeOta.blobs = {SDK_ID: ESCAPING_ZIP}
        with self.assertRaises(bm.FetchRefused) as refused:
            self.fetch(packages=["raisin"])
        self.assertIn("outside", str(refused.exception))
        self.assertFalse((self.into / "escaped.txt").exists())

    # -- the body ----------------------------------------------------------

    def test_refuses_a_body_that_does_not_match_the_advertised_digest(self):
        """A body that is not what the server said it was must not be unpacked.

        The server sends `X-Content-Hash` and the shared download primitive
        verifies against it. Asserted here because choosing that primitive is
        this module's decision: a plain `requests.get` would have written the
        bytes and unpacked them, and a build machine would compile against
        whatever arrived.
        """
        tampered = SDK_ZIP + b"tampered"
        honest_digest = hashlib.sha256(SDK_ZIP).hexdigest()

        class MisdeclaringOta(FakeOta):
            def do_GET(self):
                url = urlparse(self.path)
                parts = [p for p in url.path.split("/") if p]
                if parts and parts[-1] == "download":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(tampered)))
                    # The digest of the *untampered* zip, against a body that is
                    # not it.
                    self.send_header("X-Content-Hash", honest_digest)
                    self.end_headers()
                    self.wfile.write(tampered)
                    return
                FakeOta.do_GET(self)

        server = HTTPServer(("127.0.0.1", 0), MisdeclaringOta)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        host, port = server.server_address
        target = self.into / "tampered"
        with self.assertRaises(bm.FetchRefused) as refused:
            bm.fetch_archive(
                "raisin-robot", "ubuntu-24.04-x86_64", target,
                packages=["raisin"], key=GOOD_KEY,
                endpoint=f"http://{host}:{port}/api",
            )
        self.assertIn("Downloading 'raisin' failed", str(refused.exception))
        # Nothing unpacked, and no half-written download left to be resumed into
        # a future run.
        self.assertEqual(list(target.glob("**/*.hpp")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
