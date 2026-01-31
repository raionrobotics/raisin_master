#!/usr/bin/env python3
"""
Unit tests for the OTA client (commands/ota_client.py).

Exercises configuration, SSH auth, upload, download, and integration
with install.py / publish.py. All external dependencies (HTTP, subprocess,
filesystem) are mocked so the tests run offline.

Usage:
    python test_ota.py
    python -m pytest test_ota.py -v
"""

import base64
import hashlib
import json
import os
import struct
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import commands.ota_client as ota
from commands import globals as g


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(
    status_code=200, json_data=None, raise_for_status=None, iter_content=None
):
    """Build a MagicMock that behaves like a requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    if raise_for_status:
        resp.raise_for_status.side_effect = raise_for_status
    else:
        resp.raise_for_status.return_value = None
    if iter_content is not None:
        resp.iter_content.return_value = iter_content
    # Support usage as context manager (streaming downloads)
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _make_sshsig(raw_sig=None):
    """Build a minimal SSHSIG container and return (sshsig_bytes, sig_wire_blob).

    ``sig_wire_blob`` is the SSH wire-format signature that the OTA server
    expects (algorithm name + raw signature, both length-prefixed).
    """
    if raw_sig is None:
        raw_sig = b"X" * 64  # fake 64-byte ed25519 signature
    sig_wire = (
        struct.pack(">I", 11)
        + b"ssh-ed25519"
        + struct.pack(">I", len(raw_sig))
        + raw_sig
    )
    pubkey_blob = (
        struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"K" * 32
    )
    data = (
        b"SSHSIG"
        + struct.pack(">I", 1)  # version
        + struct.pack(">I", len(pubkey_blob))
        + pubkey_blob
        + struct.pack(">I", 4)
        + b"auth"
        + struct.pack(">I", 0)  # reserved (empty)
        + struct.pack(">I", 6)
        + b"sha512"
        + struct.pack(">I", len(sig_wire))
        + sig_wire
    )
    return data, sig_wire


def _make_sshsig_pem(raw_sig=None):
    """Build a PEM-wrapped SSHSIG string (as ssh-keygen -Y sign outputs)."""
    sshsig_bytes, sig_wire = _make_sshsig(raw_sig)
    b64 = base64.b64encode(sshsig_bytes).decode()
    # Wrap in PEM lines of 70 chars
    lines = [b64[i : i + 70] for i in range(0, len(b64), 70)]
    pem = "-----BEGIN SSH SIGNATURE-----\n"
    pem += "\n".join(lines) + "\n"
    pem += "-----END SSH SIGNATURE-----\n"
    return pem, sig_wire


# ============================================================================
# 1. Configuration Tests
# ============================================================================


class TestConfiguration(unittest.TestCase):
    """Verify env-var-based configuration helpers."""

    def test_get_ota_endpoint_returns_default_when_unset(self):
        """Should return default endpoint when env var is not set."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("RAISIN_OTA_ENDPOINT", None)
            self.assertEqual(ota.get_ota_endpoint(), ota.DEFAULT_OTA_ENDPOINT)

    def test_get_ota_endpoint_returns_value(self):
        with patch.dict(os.environ, {"RAISIN_OTA_ENDPOINT": "https://ota.example.com"}):
            self.assertEqual(ota.get_ota_endpoint(), "https://ota.example.com")

    def test_get_ssh_key_path_default(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("RAISIN_SSH_KEY", None)
            result = ota.get_ssh_key_path()
            self.assertEqual(result, Path("~/.ssh/id_ed25519").expanduser())

    def test_get_ssh_key_path_custom(self):
        with patch.dict(os.environ, {"RAISIN_SSH_KEY": "/tmp/my_key"}):
            self.assertEqual(ota.get_ssh_key_path(), Path("/tmp/my_key"))


# ============================================================================
# 1b. Token Persistence Tests
# ============================================================================


def _make_jwt(exp_offset_seconds=3600):
    """Build a minimal JWT with the given expiry offset from now."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(
        b"="
    )
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + exp_offset_seconds}).encode()
    ).rstrip(b"=")
    sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.{sig.decode()}"


class TestTokenPersistence(unittest.TestCase):
    """Verify JWT expiry checks, file caching, and cache clearing."""

    def setUp(self):
        ota._cached_token = None
        ota._auth_failed = False
        self._tmpdir = tempfile.mkdtemp()
        self._orig_script_directory = g.script_directory
        g.script_directory = self._tmpdir

    def tearDown(self):
        ota._cached_token = None
        ota._auth_failed = False
        g.script_directory = self._orig_script_directory
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_is_jwt_expired_false_for_valid_token(self):
        token = _make_jwt(exp_offset_seconds=3600)  # expires in 1 hour
        self.assertFalse(ota._is_jwt_expired(token))

    def test_is_jwt_expired_true_for_expired_token(self):
        token = _make_jwt(exp_offset_seconds=-60)  # expired 1 min ago
        self.assertTrue(ota._is_jwt_expired(token))

    def test_is_jwt_expired_true_within_buffer(self):
        token = _make_jwt(exp_offset_seconds=10)  # expires in 10s, within 30s buffer
        self.assertTrue(ota._is_jwt_expired(token))

    def test_is_jwt_expired_true_for_garbage(self):
        self.assertTrue(ota._is_jwt_expired("not-a-jwt"))

    def test_save_and_load_token(self):
        token = _make_jwt(3600)
        with patch.dict(os.environ, {"RAISIN_OTA_ENDPOINT": "https://ota.test"}):
            ota._save_token(token)
            loaded = ota._load_cached_token()
        self.assertEqual(loaded, token)

    def test_load_returns_none_for_wrong_endpoint(self):
        token = _make_jwt(3600)
        with patch.dict(os.environ, {"RAISIN_OTA_ENDPOINT": "https://ota.test"}):
            ota._save_token(token)
        with patch.dict(os.environ, {"RAISIN_OTA_ENDPOINT": "https://other.server"}):
            self.assertIsNone(ota._load_cached_token())

    def test_load_returns_none_for_expired_token(self):
        token = _make_jwt(-60)
        with patch.dict(os.environ, {"RAISIN_OTA_ENDPOINT": "https://ota.test"}):
            ota._save_token(token)
            self.assertIsNone(ota._load_cached_token())

    def test_load_returns_none_when_no_file(self):
        with patch.dict(os.environ, {"RAISIN_OTA_ENDPOINT": "https://ota.test"}):
            self.assertIsNone(ota._load_cached_token())

    def test_clear_cached_token_removes_both(self):
        token = _make_jwt(3600)
        ota._cached_token = token
        with patch.dict(os.environ, {"RAISIN_OTA_ENDPOINT": "https://ota.test"}):
            ota._save_token(token)
            ota._clear_cached_token()
        self.assertIsNone(ota._cached_token)
        cache_path = Path(self._tmpdir) / ".ota_token_cache.json"
        self.assertFalse(cache_path.exists())

    def test_authenticate_uses_file_cache(self):
        """authenticate() should return a file-cached token without SSH auth."""
        token = _make_jwt(3600)
        with patch.dict(os.environ, {"RAISIN_OTA_ENDPOINT": "https://ota.test"}):
            ota._save_token(token)
            result = ota.authenticate()
        self.assertEqual(result, token)
        self.assertEqual(ota._cached_token, token)

    @patch("commands.ota_client._get_ssh_fingerprint", return_value="aabb")
    @patch(
        "commands.ota_client.requests.post",
        side_effect=ota.requests.ConnectionError("refused"),
    )
    @patch("commands.ota_client.get_ssh_key_path")
    @patch("commands.ota_client.get_ota_endpoint", return_value="https://ota.test")
    def test_auth_failure_stops_retrying(self, _ep, mock_key_path, mock_post, _fp):
        """After one auth failure, subsequent calls return None immediately."""
        key_path = MagicMock()
        key_path.exists.return_value = True
        mock_key_path.return_value = key_path

        # First call fails
        self.assertIsNone(ota.authenticate())
        self.assertTrue(ota._auth_failed)
        self.assertEqual(mock_post.call_count, 1)

        # Second call should NOT hit the server again
        self.assertIsNone(ota.authenticate())
        self.assertEqual(mock_post.call_count, 1)  # still 1

    def test_clear_cached_token_resets_auth_failed(self):
        """_clear_cached_token() resets the failure flag for 401 retry."""
        ota._auth_failed = True
        ota._clear_cached_token()
        self.assertFalse(ota._auth_failed)


# ============================================================================
# 2. SSH Fingerprint & Signing Tests
# ============================================================================


class TestSSHHelpers(unittest.TestCase):
    """Verify SSH fingerprint extraction and nonce signing."""

    @patch("commands.ota_client.subprocess.run")
    def test_get_ssh_fingerprint_parses_output(self, mock_run):
        # "dGVzdGZpbmdlcnByaW50" is base64 for b"testfingerprint"
        mock_run.return_value = MagicMock(
            stdout="256 SHA256:dGVzdGZpbmdlcnByaW50 user@host (ED25519)\n"
        )
        fp = ota._get_ssh_fingerprint(Path("/tmp/key"))
        # Should return hex-encoded SHA256, without "SHA256:" prefix
        self.assertEqual(fp, b"testfingerprint".hex())
        mock_run.assert_called_once_with(
            ["ssh-keygen", "-lf", "/tmp/key.pub"],
            capture_output=True,
            text=True,
            check=True,
        )

    @patch("commands.ota_client.subprocess.run")
    def test_get_ssh_fingerprint_uses_pub_suffix(self, mock_run):
        """If the key already ends in .pub, don't double-suffix."""
        # "eHl6Nzg5" is base64 for b"xyz789"
        mock_run.return_value = MagicMock(
            stdout="256 SHA256:eHl6Nzg5 user@host (ED25519)\n"
        )
        fp = ota._get_ssh_fingerprint(Path("/tmp/key.pub"))
        self.assertEqual(fp, b"xyz789".hex())
        mock_run.assert_called_once_with(
            ["ssh-keygen", "-lf", "/tmp/key.pub"],
            capture_output=True,
            text=True,
            check=True,
        )

    def test_extract_sig_from_sshsig(self):
        """_extract_sig_from_sshsig returns the SSH wire-format signature blob."""
        sshsig_bytes, expected_wire = _make_sshsig()
        result = ota._extract_sig_from_sshsig(sshsig_bytes)
        self.assertEqual(result, expected_wire)

    def test_sign_nonce_produces_valid_signature(self):
        """_sign_nonce signs the hex-decoded nonce and returns SSH wire-format base64."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        private_key = Ed25519PrivateKey.generate()
        key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as f:
            f.write(key_bytes)
            key_path = Path(f.name)

        # Use a hex-encoded nonce (like the real server sends)
        test_nonce = "aabbccdd" * 8  # 32 bytes as hex = 64 hex chars

        try:
            sig_b64 = ota._sign_nonce(test_nonce, key_path)

            # Decode and parse wire format
            sig_wire = base64.b64decode(sig_b64)
            algo_len = struct.unpack(">I", sig_wire[:4])[0]
            algo = sig_wire[4 : 4 + algo_len]
            self.assertEqual(algo, b"ssh-ed25519")

            raw_sig_offset = 4 + algo_len
            sig_len = struct.unpack(
                ">I", sig_wire[raw_sig_offset : raw_sig_offset + 4]
            )[0]
            raw_sig = sig_wire[raw_sig_offset + 4 : raw_sig_offset + 4 + sig_len]
            self.assertEqual(len(raw_sig), 64)

            # Verify the signature over the hex-decoded nonce bytes
            public_key = private_key.public_key()
            public_key.verify(raw_sig, bytes.fromhex(test_nonce))  # raises on failure
        finally:
            key_path.unlink()


# ============================================================================
# 3. Authentication Tests
# ============================================================================


class TestAuthentication(unittest.TestCase):
    """Verify the SSH challenge-response authentication flow.

    Patches _load_cached_token, _save_token, and _is_jwt_expired so the
    persistent cache and JWT validation don't interfere with SSH auth tests.
    """

    def setUp(self):
        ota._cached_token = None
        ota._auth_failed = False
        self._p_load = patch(
            "commands.ota_client._load_cached_token", return_value=None
        )
        self._p_save = patch("commands.ota_client._save_token")
        self._p_load.start()
        self._p_save.start()

    def tearDown(self):
        ota._cached_token = None
        ota._auth_failed = False
        self._p_load.stop()
        self._p_save.stop()

    @patch("commands.ota_client._sign_nonce", return_value="SIG")
    @patch("commands.ota_client._get_ssh_fingerprint", return_value="SHA256:fp")
    @patch("commands.ota_client.requests.post")
    @patch("commands.ota_client.get_ssh_key_path")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    def test_authenticate_happy_path(self, _ep, mock_key_path, mock_post, _fp, _sign):
        key_path = MagicMock()
        key_path.exists.return_value = True
        mock_key_path.return_value = key_path

        # First POST returns nonce, second returns accessToken
        # Server wraps all responses in {"success": true, "data": {...}}
        mock_post.side_effect = [
            _mock_response(json_data={"data": {"nonce": "random-nonce"}}),
            _mock_response(json_data={"data": {"accessToken": "tok123"}}),
        ]

        token = ota.authenticate()
        self.assertEqual(token, "tok123")
        self.assertEqual(mock_post.call_count, 2)

    @patch("commands.ota_client._sign_nonce", return_value="SIG")
    @patch("commands.ota_client._get_ssh_fingerprint", return_value="SHA256:fp")
    @patch("commands.ota_client.requests.post")
    @patch("commands.ota_client.get_ssh_key_path")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    def test_authenticate_caches_token(self, _ep, mock_key_path, mock_post, _fp, _sign):
        key_path = MagicMock()
        key_path.exists.return_value = True
        mock_key_path.return_value = key_path

        mock_post.side_effect = [
            _mock_response(json_data={"data": {"nonce": "n"}}),
            _mock_response(json_data={"data": {"accessToken": "cached-tok"}}),
        ]

        tok1 = ota.authenticate()
        tok2 = ota.authenticate()  # should use cache, no extra HTTP
        self.assertEqual(tok1, "cached-tok")
        self.assertEqual(tok2, "cached-tok")
        self.assertEqual(mock_post.call_count, 2)  # only from the first call

    @patch("commands.ota_client.get_ssh_key_path")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    def test_authenticate_ssh_key_missing(self, _ep, mock_key_path):
        key_path = MagicMock()
        key_path.exists.return_value = False
        mock_key_path.return_value = key_path

        self.assertIsNone(ota.authenticate())

    @patch(
        "commands.ota_client._get_ssh_fingerprint",
        side_effect=FileNotFoundError("ssh-keygen"),
    )
    @patch("commands.ota_client.get_ssh_key_path")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    def test_authenticate_ssh_keygen_not_found(self, _ep, mock_key_path, _fp):
        key_path = MagicMock()
        key_path.exists.return_value = True
        mock_key_path.return_value = key_path

        self.assertIsNone(ota.authenticate())

    @patch("commands.ota_client._get_ssh_fingerprint", return_value="SHA256:fp")
    @patch(
        "commands.ota_client.requests.post",
        side_effect=ota.requests.ConnectionError("refused"),
    )
    @patch("commands.ota_client.get_ssh_key_path")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    def test_authenticate_server_unreachable(self, _ep, mock_key_path, _post, _fp):
        key_path = MagicMock()
        key_path.exists.return_value = True
        mock_key_path.return_value = key_path

        self.assertIsNone(ota.authenticate())


# ============================================================================
# 4. Upload Tests
# ============================================================================


class TestUpload(unittest.TestCase):
    """Verify upload_package and _compute_sha256."""

    def setUp(self):
        ota._cached_token = None
        ota._auth_failed = False
        self._orig_os_type = g.os_type
        self._orig_os_version = g.os_version
        self._orig_architecture = g.architecture
        g.os_type = "linux"
        g.os_version = "22.04"
        g.architecture = "x86_64"

    def tearDown(self):
        ota._cached_token = None
        ota._auth_failed = False
        g.os_type = self._orig_os_type
        g.os_version = self._orig_os_version
        g.architecture = self._orig_architecture

    def test_compute_sha256_correct(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"hello world")
            tmp.flush()
            digest = ota._compute_sha256(Path(tmp.name))
        os.unlink(tmp.name)
        expected = hashlib.sha256(b"hello world").hexdigest()
        self.assertEqual(digest, expected)

    @patch("commands.ota_client.authenticate", return_value="tok")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    @patch("commands.ota_client.requests.post")
    @patch("commands.ota_client._compute_sha256", return_value="aabbcc")
    def test_upload_package_happy_path(self, _sha, mock_post, mock_get, _ep, _auth):
        # GET blob exists → False
        # GET packages → existing package
        # Server wraps responses in {"data": ...}
        mock_get.side_effect = [
            _mock_response(json_data={"data": {"exists": False}}),
            _mock_response(json_data={"data": [{"id": "pkg-1"}]}),
        ]

        # POST blob upload, POST manifest, POST tag
        mock_post.side_effect = [
            _mock_response(),  # blob upload
            _mock_response(),  # manifest
            _mock_response(),  # tag
        ]

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(b"fake-zip")
            tmp.flush()
            result = ota.upload_package(Path(tmp.name), "mypkg", "1.0.0", "release")
        os.unlink(tmp.name)

        self.assertTrue(result)
        self.assertEqual(mock_post.call_count, 3)

    @patch("commands.ota_client.authenticate", return_value="tok")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    @patch("commands.ota_client.requests.post")
    @patch("commands.ota_client._compute_sha256", return_value="aabbcc")
    def test_upload_package_blob_dedup(self, _sha, mock_post, mock_get, _ep, _auth):
        # GET blob exists → True (skip upload)
        # GET packages → existing package
        mock_get.side_effect = [
            _mock_response(json_data={"data": {"exists": True}}),
            _mock_response(json_data={"data": [{"id": "pkg-1"}]}),
        ]

        # POST manifest, POST tag (no blob upload)
        mock_post.side_effect = [
            _mock_response(),  # manifest
            _mock_response(),  # tag
        ]

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(b"fake-zip")
            tmp.flush()
            result = ota.upload_package(Path(tmp.name), "mypkg", "1.0.0", "release")
        os.unlink(tmp.name)

        self.assertTrue(result)
        # Only manifest + tag, no blob upload
        self.assertEqual(mock_post.call_count, 2)

    @patch("commands.ota_client.authenticate")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    @patch("commands.ota_client.requests.post")
    @patch("commands.ota_client._compute_sha256", return_value="aabbcc")
    def test_upload_package_401_retry(self, _sha, mock_post, mock_get, _ep, mock_auth):
        # authenticate() is called 3 times:
        #   1) initial upload_package call
        #   2) re-auth after 401 in the except block
        #   3) recursive upload_package call (top of function)
        mock_auth.side_effect = ["old-tok", "new-tok", "new-tok"]

        # First call: blob-exists check raises 401
        err_resp = MagicMock()
        err_resp.status_code = 401
        http_err = ota.requests.HTTPError(response=err_resp)

        mock_get.side_effect = [
            MagicMock(
                raise_for_status=MagicMock(side_effect=http_err),
                status_code=401,
            ),
            # Retry calls (after re-auth):
            _mock_response(json_data={"data": {"exists": True}}),
            _mock_response(json_data={"data": [{"id": "pkg-1"}]}),
        ]
        mock_post.side_effect = [
            _mock_response(),  # manifest
            _mock_response(),  # tag
        ]

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(b"fake-zip")
            tmp.flush()
            result = ota.upload_package(Path(tmp.name), "mypkg", "1.0.0", "release")
        os.unlink(tmp.name)

        self.assertTrue(result)
        # authenticate() called 3 times: initial + re-auth + recursive call
        self.assertEqual(mock_auth.call_count, 3)

    @patch("commands.ota_client.authenticate", return_value=None)
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    def test_upload_package_auth_fails(self, _ep, _auth):
        result = ota.upload_package(Path("/fake.zip"), "mypkg", "1.0.0", "release")
        self.assertFalse(result)


# ============================================================================
# 5. Download Tests
# ============================================================================


class TestDownload(unittest.TestCase):
    """Verify _fetch_archive_manifest, download_package, and version matching."""

    def setUp(self):
        ota._cached_token = None
        ota._auth_failed = False
        ota._archive_cache.clear()
        self._orig_os_type = g.os_type
        self._orig_os_version = g.os_version
        self._orig_architecture = g.architecture
        self._orig_script_directory = g.script_directory
        g.os_type = "linux"
        g.os_version = "22.04"
        g.architecture = "x86_64"

    def tearDown(self):
        ota._cached_token = None
        ota._auth_failed = False
        ota._archive_cache.clear()
        g.os_type = self._orig_os_type
        g.os_version = self._orig_os_version
        g.architecture = self._orig_architecture
        g.script_directory = self._orig_script_directory

    @patch("commands.ota_client.authenticate", return_value="tok")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    def test_fetch_archive_manifest_returns_data(self, mock_get, _ep, _auth):
        # Server returns paginated response wrapped in {data: {archives: [...]}}
        archive_list = [
            {
                "id": "arch-1",
                "version": "v2024.01",
                "packages": [
                    {"packageName": "mypkg", "tagName": "v1.0.0", "packageId": "p1"}
                ],
            }
        ]
        mock_get.return_value = _mock_response(
            json_data={
                "data": {"archives": archive_list, "total": 1, "page": 1, "limit": 20}
            }
        )

        result = ota._fetch_archive_manifest("raisin-robot", "linux-22.04-x86_64")
        self.assertIsNotNone(result)
        packages, archive_id, archive_version = result
        self.assertEqual(archive_id, "arch-1")
        self.assertEqual(archive_version, "v2024.01")
        self.assertEqual(len(packages), 1)

    @patch("commands.ota_client.authenticate", return_value="tok")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    def test_fetch_archive_manifest_caching(self, mock_get, _ep, _auth):
        archive_list = [{"id": "arch-1", "version": "v2024.01", "packages": []}]
        mock_get.return_value = _mock_response(
            json_data={
                "data": {"archives": archive_list, "total": 1, "page": 1, "limit": 20}
            }
        )

        r1 = ota._fetch_archive_manifest("raisin-robot", "linux-22.04-x86_64")
        r2 = ota._fetch_archive_manifest("raisin-robot", "linux-22.04-x86_64")
        self.assertEqual(r1, r2)
        # Only one HTTP call thanks to caching
        self.assertEqual(mock_get.call_count, 1)

    @patch("commands.ota_client._download_package_blob")
    @patch("commands.ota_client._fetch_archive_manifest")
    def test_download_package_happy_path(self, mock_manifest, mock_blob):
        packages = [
            {
                "packageName": "mypkg",
                "tagName": "v1.2.0",
                "packageId": "p1",
                "manifestHash": "a" * 64,
            },
        ]
        mock_manifest.return_value = (packages, "arch-1", "v2024.01")
        mock_blob.return_value = True

        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            install_base = Path(tmpdir) / "release" / "install"
            install_base.mkdir(parents=True)

            # Create a fake zip for extraction
            download_file = Path(tmpdir) / "install" / "mypkg-ota-1.2.0.zip"
            download_file.parent.mkdir(parents=True, exist_ok=True)

            # Write a zip with release.yaml inside
            with zipfile.ZipFile(download_file, "w") as zf:
                zf.writestr("release.yaml", "version: 1.2.0\ndependencies:\n  - depA\n")

            # Make _download_package_blob write the zip to disk (already done)
            def fake_download(archive_id, pkg_id, name, path):
                # File already written above
                return True

            mock_blob.side_effect = fake_download

            result = ota.download_package("mypkg", "", "release", install_base)

        self.assertIsNotNone(result)
        self.assertEqual(result["version"], "1.2.0")
        self.assertIn("depA", result["dependencies"])

    @patch("commands.ota_client._download_package_blob", return_value=True)
    @patch("commands.ota_client._fetch_archive_manifest")
    def test_download_package_version_matching(self, mock_manifest, mock_blob):
        packages = [
            {
                "packageName": "mypkg",
                "tagName": "v1.0.0",
                "packageId": "p1",
                "manifestHash": "a" * 64,
            },
            {
                "packageName": "mypkg",
                "tagName": "v2.0.0",
                "packageId": "p2",
                "manifestHash": "b" * 64,
            },
            {
                "packageName": "mypkg",
                "tagName": "v1.5.0",
                "packageId": "p3",
                "manifestHash": "c" * 64,
            },
        ]
        mock_manifest.return_value = (packages, "arch-1", "v2024.01")

        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            install_base = Path(tmpdir) / "release" / "install"
            install_base.mkdir(parents=True)

            download_file = Path(tmpdir) / "install" / "mypkg-ota-1.5.0.zip"
            download_file.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(download_file, "w") as zf:
                zf.writestr("release.yaml", "version: 1.5.0\n")

            def fake_download(archive_id, pkg_id, name, path):
                return True

            mock_blob.side_effect = fake_download

            # Spec ">=1.0.0,<2.0.0" should pick 1.5.0 (highest matching)
            result = ota.download_package(
                "mypkg", ">=1.0.0 <2.0.0", "release", install_base
            )

        self.assertIsNotNone(result)
        self.assertEqual(result["version"], "1.5.0")

    @patch("commands.ota_client._fetch_archive_manifest")
    def test_download_package_not_in_archive(self, mock_manifest):
        packages = [
            {
                "packageName": "other",
                "tagName": "v1.0.0",
                "packageId": "p1",
                "manifestHash": "a" * 64,
            },
        ]
        mock_manifest.return_value = (packages, "arch-1", "v2024.01")

        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            install_base = Path(tmpdir) / "release" / "install"
            install_base.mkdir(parents=True)

            result = ota.download_package("mypkg", "", "release", install_base)

        self.assertIsNone(result)

    @patch("commands.ota_client._fetch_archive_manifest", return_value=None)
    def test_download_package_manifest_unavailable(self, _manifest):
        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            result = ota.download_package("mypkg", "", "release", Path(tmpdir))
        self.assertIsNone(result)


class TestArchiveNameAndTimestamp(unittest.TestCase):
    """Test archive name derivation and timestamp-based downloads."""

    def setUp(self):
        ota._cached_token = None
        ota._auth_failed = False
        ota._archive_cache.clear()
        self._orig_os_type = g.os_type
        self._orig_os_version = g.os_version
        self._orig_architecture = g.architecture
        self._orig_script_directory = g.script_directory
        g.os_type = "linux"
        g.os_version = "22.04"
        g.architecture = "x86_64"

    def tearDown(self):
        ota._cached_token = None
        ota._auth_failed = False
        ota._archive_cache.clear()
        g.os_type = self._orig_os_type
        g.os_version = self._orig_os_version
        g.architecture = self._orig_architecture
        g.script_directory = self._orig_script_directory
        # Clear env var if set
        if "RAISIN_ARCHIVE_NAME" in os.environ:
            del os.environ["RAISIN_ARCHIVE_NAME"]

    def test_get_archive_name_release(self):
        """Release build type should return 'raisin-robot'."""
        self.assertEqual(ota.get_archive_name("release"), "raisin-robot")

    def test_get_archive_name_debug(self):
        """Debug build type should return 'raisin-robot-debug'."""
        self.assertEqual(ota.get_archive_name("debug"), "raisin-robot-debug")

    @patch.dict(os.environ, {"RAISIN_ARCHIVE_NAME": "custom-archive"})
    def test_get_archive_name_custom_env(self):
        """Custom archive name from env var should be respected."""
        self.assertEqual(ota.get_archive_name("release"), "custom-archive")
        self.assertEqual(ota.get_archive_name("debug"), "custom-archive-debug")

    @patch("commands.ota_client._download_blob_by_hash", return_value=True)
    @patch("commands.ota_client._fetch_package_id_by_name", return_value="pkg-uuid")
    @patch("commands.ota_client.authenticate", return_value="tok")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    def test_download_package_at_timestamp(
        self, mock_get, _ep, _auth, mock_pkg_id, mock_blob_dl
    ):
        """Download package at a specific timestamp using manifests/at API."""
        # Mock the manifests/at response
        mock_get.return_value = _mock_response(
            json_data={
                "data": {
                    "blobHash": "abc123" * 10 + "abcd",
                    "version": "1.5.0",
                }
            }
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            install_base = Path(tmpdir) / "release" / "install"
            install_base.mkdir(parents=True)

            # Pre-create the zip file that _download_blob_by_hash would write
            download_file = Path(tmpdir) / "install" / "mypkg-ota-1.5.0.zip"
            download_file.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(download_file, "w") as zf:
                zf.writestr("release.yaml", "version: 1.5.0\ndependencies:\n  - depB\n")

            result = ota.download_package_at_timestamp(
                "mypkg", "2024-01-15T10:00:00Z", "release", install_base
            )

        self.assertIsNotNone(result)
        self.assertEqual(result["version"], "1.5.0")
        self.assertIn("depB", result["dependencies"])

    @patch("commands.ota_client._download_package_blob", return_value=True)
    @patch("commands.ota_client._fetch_archive_manifest")
    def test_download_all_from_archive(self, mock_manifest, mock_blob):
        """Download all packages from an archive."""
        packages = [
            {"packageName": "pkg1", "tagName": "v1.0.0", "packageId": "p1"},
            {"packageName": "pkg2", "tagName": "v2.0.0", "packageId": "p2"},
        ]
        mock_manifest.return_value = (packages, "arch-1", "v2024.01")

        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            install_base = Path(tmpdir) / "release" / "install"
            install_base.mkdir(parents=True)

            # Pre-create zip files for each package
            for name, ver in [("pkg1", "1.0.0"), ("pkg2", "2.0.0")]:
                download_file = Path(tmpdir) / "install" / f"{name}-ota-{ver}.zip"
                download_file.parent.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(download_file, "w") as zf:
                    zf.writestr("release.yaml", f"version: {ver}\n")

            result = ota.download_all_from_archive("release", install_base)

        self.assertEqual(len(result), 2)
        self.assertIn("pkg1", result)
        self.assertIn("pkg2", result)
        self.assertEqual(result["pkg1"]["version"], "1.0.0")
        self.assertEqual(result["pkg2"]["version"], "2.0.0")


# ============================================================================
# 6. Integration: install.py
# ============================================================================


class TestInstallIntegration(unittest.TestCase):
    """Verify OTA is used (or skipped) correctly in install_command."""

    @patch("commands.install.is_ota_configured", return_value=False)
    @patch("commands.install.load_configuration")
    def test_ota_skipped_when_not_configured(self, mock_config, mock_ota_check):
        """When RAISIN_OTA_ENDPOINT is unset, install should not call OTA."""
        mock_config.return_value = (
            {"mypkg": {"url": "git@github.com:org/mypkg.git"}},
            {"org": "ghtoken"},
            "devel",
            None,
            [],
        )

        # Patch the requests.Session to avoid real HTTP calls
        with patch("commands.install.requests.Session") as MockSession:
            session = MagicMock()
            MockSession.return_value = session

            # Simulate GitHub API returning no matching releases
            resp = _mock_response(json_data=[])
            session.get.return_value = resp

            from commands.install import install_command

            install_command(["mypkg"], "release")

        # is_ota_configured should have been checked but returned False
        mock_ota_check.assert_called()

    @patch("commands.install.is_ota_configured", return_value=True)
    @patch("commands.install.load_configuration")
    def test_ota_attempted_when_configured(self, mock_config, mock_ota_check):
        """When OTA is configured, install should try OTA before GitHub."""
        mock_config.return_value = (
            {"mypkg": {"url": "git@github.com:org/mypkg.git"}},
            {"org": "ghtoken"},
            "devel",
            None,
            [],
        )

        with patch(
            "commands.ota_client.download_package", return_value=None
        ) as mock_dl:
            with patch("commands.install.requests.Session") as MockSession:
                session = MagicMock()
                MockSession.return_value = session
                resp = _mock_response(json_data=[])
                session.get.return_value = resp

                from commands.install import install_command

                install_command(["mypkg"], "release")

            # OTA download should have been attempted for 'mypkg'
            call_args_list = [c[0][0] for c in mock_dl.call_args_list]
            self.assertIn("mypkg", call_args_list)


# ============================================================================
# 7. Integration: publish.py
# ============================================================================


class TestPublishIntegration(unittest.TestCase):
    """Verify OTA messaging in publish dry-run mode."""

    @patch("commands.publish.is_ota_configured", return_value=True)
    @patch("commands.publish.load_configuration")
    @patch("commands.publish.setup")
    @patch("commands.publish.guard_require_version_bump_for_src_packages")
    @patch("commands.publish.get_commit_hash", return_value="abc123")
    @patch("commands.publish.subprocess.run")
    @patch("commands.publish.shutil.make_archive")
    @patch("commands.publish.shutil.copy")
    def test_dry_run_prints_ota_message(
        self,
        _copy,
        _archive,
        _subproc,
        _commit,
        _guard,
        _setup,
        mock_config,
        mock_ota_check,
        capsys=None,
    ):
        mock_config.return_value = (
            {"mypkg": {"url": "git@github.com:org/mypkg.git"}},
            {"org": "ghtoken"},
            "devel",
            None,
            [],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            target_dir = Path(tmpdir) / "src" / "mypkg"
            target_dir.mkdir(parents=True)
            release_yaml = target_dir / "release.yaml"
            release_yaml.write_text("version: 1.0.0\n")

            from commands.publish import publish

            # Capture printed output
            import io
            from contextlib import redirect_stdout

            buf = io.StringIO()
            with redirect_stdout(buf):
                # --upload-ota flag triggers OTA message in dry-run
                publish("mypkg", "release", dry_run=True, upload_ota=True)

            output = buf.getvalue()
            self.assertIn("OTA", output)

    @patch("commands.publish.is_ota_configured", return_value=False)
    @patch("commands.publish.load_configuration")
    @patch("commands.publish.setup")
    @patch("commands.publish.guard_require_version_bump_for_src_packages")
    @patch("commands.publish.get_commit_hash", return_value="abc123")
    @patch("commands.publish.subprocess.run")
    @patch("commands.publish.shutil.make_archive")
    @patch("commands.publish.shutil.copy")
    def test_dry_run_no_ota_message_when_unconfigured(
        self,
        _copy,
        _archive,
        _subproc,
        _commit,
        _guard,
        _setup,
        mock_config,
        mock_ota_check,
    ):
        mock_config.return_value = (
            {"mypkg": {"url": "git@github.com:org/mypkg.git"}},
            {"org": "ghtoken"},
            "devel",
            None,
            [],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            target_dir = Path(tmpdir) / "src" / "mypkg"
            target_dir.mkdir(parents=True)
            release_yaml = target_dir / "release.yaml"
            release_yaml.write_text("version: 1.0.0\n")

            from commands.publish import publish

            import io
            from contextlib import redirect_stdout

            buf = io.StringIO()
            with redirect_stdout(buf):
                publish("mypkg", "release", dry_run=True)

            output = buf.getvalue()
            self.assertNotIn("Would also upload to OTA", output)


# ============================================================================
# Entry point
# ============================================================================


if __name__ == "__main__":
    unittest.main(verbosity=2)
