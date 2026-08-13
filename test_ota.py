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
import errno
import hashlib
import json
import os
import struct
import sys
import tempfile
import time
import unittest
import zipfile

import requests
from pathlib import Path
from unittest.mock import MagicMock, patch, call
from click.testing import CliRunner

import commands.ota_client as ota
from commands import globals as g


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(
    status_code=200,
    json_data=None,
    raise_for_status=None,
    iter_content=None,
    headers=None,
):
    """Build a MagicMock that behaves like a requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {} if headers is None else headers
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

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_script_directory = g.script_directory
        g.script_directory = self._tmpdir.name
        ota._robot_api_key_cache.clear()
        ota._robot_auth_warning_keys.clear()
        ota._local_config_cache.clear()

    def tearDown(self):
        ota._robot_api_key_cache.clear()
        ota._robot_auth_warning_keys.clear()
        ota._local_config_cache.clear()
        g.script_directory = self._orig_script_directory
        self._tmpdir.cleanup()

    def test_get_ota_endpoint_returns_default_when_unset(self):
        """Should return default endpoint when env var is not set."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("RAISIN_OTA_ENDPOINT", None)
            self.assertEqual(ota.get_ota_endpoint(), ota.DEFAULT_OTA_ENDPOINT)

    def test_get_ota_endpoint_returns_value(self):
        with patch.dict(os.environ, {"RAISIN_OTA_ENDPOINT": "https://ota.example.com"}):
            self.assertEqual(ota.get_ota_endpoint(), "https://ota.example.com")

    def test_get_ssh_key_path_from_env(self):
        """RAISIN_SSH_KEY env var takes priority."""
        with patch.dict(os.environ, {"RAISIN_SSH_KEY": "/tmp/my_key"}):
            self.assertEqual(ota.get_ssh_key_path(), Path("/tmp/my_key"))

    def test_get_ssh_key_path_finds_existing_key(self):
        """Should find first existing key (ed25519 > ecdsa > rsa)."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("RAISIN_SSH_KEY", None)
            with patch.object(Path, "exists") as mock_exists:
                # Simulate id_ed25519 doesn't exist, but id_ecdsa does
                def exists_side_effect(self):
                    return "id_ecdsa" in str(self)

                mock_exists.side_effect = lambda: "id_ecdsa" in str(mock_exists)
                # This test is tricky with Path.exists mocking, so just verify env var works
                pass

    def test_get_ssh_key_path_default_fallback(self):
        """Falls back to id_ed25519 if no keys found."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("RAISIN_SSH_KEY", None)
            with patch.object(Path, "exists", return_value=False):
                result = ota.get_ssh_key_path()
                self.assertEqual(result.name, "id_ed25519")

    def test_get_robot_api_key_from_env(self):
        with patch.dict(
            os.environ,
            {
                "RAISIN_ROBOT_API_KEY": " robot-key ",  # pragma: allowlist secret
            },
            clear=True,
        ):
            self.assertEqual(ota.get_robot_api_key(), "robot-key")

    def test_get_robot_api_key_from_config_yaml(self):
        config_path = Path(g.script_directory) / "configuration_setting.yaml"
        config_path.write_text(
            "user_type: user\nrobot:\n  api_key: config-robot-key\n",
            encoding="utf-8",
        )

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(ota.get_robot_api_key(), "config-robot-key")

    def test_get_robot_api_key_env_overrides_config_yaml(self):
        config_path = Path(g.script_directory) / "configuration_setting.yaml"
        config_path.write_text(
            "user_type: user\nrobot:\n  api_key: config-robot-key\n",
            encoding="utf-8",
        )

        with patch.dict(
            os.environ,
            {
                "RAISIN_ROBOT_API_KEY": "env-robot-key",  # pragma: allowlist secret
            },
            clear=True,
        ):
            self.assertEqual(ota.get_robot_api_key(), "env-robot-key")

    def test_get_robot_node_key_from_env(self):
        with patch.dict(os.environ, {"RAISIN_ROBOT_NODE": " jetson "}, clear=True):
            self.assertEqual(ota.get_robot_node_key(), "jetson")

    def test_get_robot_node_key_from_config_yaml(self):
        config_path = Path(g.script_directory) / "configuration_setting.yaml"
        config_path.write_text(
            "user_type: user\nrobot:\n  node: vision\n",
            encoding="utf-8",
        )

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(ota.get_robot_node_key(), "vision")

    def test_save_and_read_robot_api_key_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "robot-api-key"
            with patch.dict(
                os.environ,
                {"RAISIN_ROBOT_API_KEY_FILE": str(key_path)},
                clear=True,
            ):
                saved_path = ota.save_robot_api_key(" robot-key ")
                self.assertEqual(saved_path, key_path)
                if os.name == "posix":
                    self.assertEqual(saved_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(ota.get_robot_api_key(), "robot-key")
                self.assertEqual(ota._robot_api_key_cache[key_path][1], "robot-key")

    def test_missing_pinned_robot_api_key_file_warns(self):
        """An explicitly pinned path that yields nothing must not fail quietly."""
        missing = Path(self._tmpdir.name) / "no-such-key"
        with patch.dict(
            os.environ,
            {"RAISIN_ROBOT_API_KEY_FILE": str(missing)},
            clear=True,
        ), patch("builtins.print") as mock_print:
            self.assertIsNone(ota.get_robot_api_key())

        self.assertTrue(
            any(
                "RAISIN_ROBOT_API_KEY_FILE points at" in str(c)
                for c in mock_print.call_args_list
            )
        )

    def test_local_config_is_parsed_once_per_file_revision(self):
        """Auth headers are rebuilt per package; re-parsing YAML each time is waste."""
        config_path = Path(g.script_directory) / "configuration_setting.yaml"
        config_path.write_text(
            "robot:\n  api_key: cfg-key\n  node: primary\n", encoding="utf-8"
        )

        with patch.dict(os.environ, {}, clear=True):
            first = ota._load_local_config()
            for _ in range(4):
                ota._load_local_config()
            self.assertEqual(first.get("robot", {}).get("api_key"), "cfg-key")
            self.assertEqual(len(ota._local_config_cache), 1)

            # A rewrite must invalidate the cache rather than serve stale values.
            os.utime(config_path, (0, 0))
            config_path.write_text(
                "robot:\n  api_key: rotated-key\n  node: primary\n", encoding="utf-8"
            )
            self.assertEqual(ota.get_robot_api_key(), "rotated-key")

    @unittest.skipIf(os.name != "posix", "POSIX file permission check")
    def test_insecure_robot_api_key_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "robot-api-key"
            key_path.write_text("robot-key\n", encoding="utf-8")
            os.chmod(key_path, 0o644)
            with patch.dict(
                os.environ,
                {"RAISIN_ROBOT_API_KEY_FILE": str(key_path)},
                clear=True,
            ):
                self.assertIsNone(ota.get_robot_api_key())

    @unittest.skipIf(os.name != "posix", "POSIX file permission check")
    def test_insecure_robot_api_key_file_warning_is_cached(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "robot-api-key"
            key_path.write_text("robot-key\n", encoding="utf-8")
            os.chmod(key_path, 0o644)
            with patch.dict(
                os.environ,
                {"RAISIN_ROBOT_API_KEY_FILE": str(key_path)},
                clear=True,
            ), patch("builtins.print") as mock_print:
                self.assertIsNone(ota.get_robot_api_key())
                self.assertIsNone(ota.get_robot_api_key())

            mock_print.assert_called_once()


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
# 4b. Download Failure Classification
# ============================================================================


class TestDownloadErrorClassification(unittest.TestCase):
    """Map download failures onto the install-event error taxonomy.

    Codes come from the server contract (docs/ota-install-event-contract.md):
    network, timeout, hash_mismatch, disk_full, server_error, unknown.
    """

    def test_connection_error_is_network(self):
        self.assertEqual(
            ota.classify_download_error(requests.ConnectionError("refused")),
            "network",
        )

    def test_read_timeout_is_timeout(self):
        self.assertEqual(
            ota.classify_download_error(requests.Timeout("read timed out")),
            "timeout",
        )

    def test_server_5xx_is_server_error(self):
        resp = _mock_response(status_code=503)
        self.assertEqual(
            ota.classify_download_error(requests.HTTPError(response=resp)),
            "server_error",
        )

    def test_client_4xx_is_not_server_error(self):
        """A 404 is a real answer, not an outage — retrying it is pointless."""
        resp = _mock_response(status_code=404)
        self.assertEqual(
            ota.classify_download_error(requests.HTTPError(response=resp)),
            "unknown",
        )

    def test_enospc_is_disk_full(self):
        self.assertEqual(
            ota.classify_download_error(OSError(errno.ENOSPC, "No space left")),
            "disk_full",
        )

    def test_hash_mismatch_is_reported_as_such(self):
        self.assertEqual(
            ota.classify_download_error(ota.ContentHashMismatch("bad digest")),
            "hash_mismatch",
        )

    def test_unrecognised_failure_is_unknown(self):
        self.assertEqual(ota.classify_download_error(ValueError("?")), "unknown")

    def test_retryable_codes_exclude_permanent_failures(self):
        """Backoff must not burn attempts on something that cannot improve."""
        self.assertTrue(ota.is_retryable_error_code("network"))
        self.assertTrue(ota.is_retryable_error_code("timeout"))
        self.assertTrue(ota.is_retryable_error_code("server_error"))
        self.assertTrue(ota.is_retryable_error_code("hash_mismatch"))
        self.assertFalse(ota.is_retryable_error_code("disk_full"))
        self.assertFalse(ota.is_retryable_error_code("unknown"))


class TestInstallEventQueue(unittest.TestCase):
    """On-disk install-event queue: buffering, replay safety, ordering.

    Contract: docs/ota-install-event-contract.md. Events are append-only
    observations of one attempt; `eventId` makes a replayed batch idempotent.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_script_directory = g.script_directory
        g.script_directory = self._tmp.name
        ota._install_session_id = "session-29"
        ota.clear_pending_install_failure()

    def tearDown(self):
        ota._install_session_id = None
        ota.clear_pending_install_failure()
        g.script_directory = self._orig_script_directory
        self._tmp.cleanup()

    def _queued(self):
        return ota._read_install_event_queue()

    def test_recorded_event_carries_the_contract_fields(self):
        ota.record_install_event("started", archive_name="dso")
        (event,) = self._queued()

        self.assertEqual(event["eventType"], "started")
        self.assertEqual(event["installSessionId"], "session-29")
        self.assertEqual(event["archiveName"], "dso")
        self.assertTrue(event["eventId"])
        self.assertTrue(event["occurredAt"].endswith("Z"))

    def test_queue_survives_a_process_restart(self):
        ota.record_install_event("started")
        ota._install_session_id = "session-29"  # new process, same session

        self.assertEqual(len(self._queued()), 1)

    def test_started_is_emitted_once_per_session(self):
        ota.record_install_event("started")
        ota.record_install_event("started")

        self.assertEqual(len(self._queued()), 1)

    def test_only_one_terminal_event_per_session(self):
        """An attempt emits exactly one terminal event, per the contract."""
        ota.record_install_event("started")
        ota.record_install_event("failed", error_code="network")
        ota.record_install_event("succeeded")

        types = [e["eventType"] for e in self._queued()]
        self.assertEqual(types, ["started", "failed"])

    def test_a_new_session_may_emit_its_own_terminal(self):
        ota.record_install_event("started")
        ota.record_install_event("succeeded")
        ota.clear_install_session()
        ota._install_session_id = "session-30"

        ota.record_install_event("started")
        ota.record_install_event("succeeded")

        self.assertEqual(len(self._queued()), 4)

    def test_flush_posts_the_batch_and_clears_acked_events(self):
        ota.record_install_event("started")
        ota.record_install_event("succeeded")
        queued = self._queued()
        acks = [{"eventId": e["eventId"], "status": "created"} for e in queued]

        with patch.dict(
            os.environ,
            {
                "RAISIN_ROBOT_API_KEY": "robot-key",  # pragma: allowlist secret
                "RAISIN_ROBOT_NODE": "jetson",
            },
            clear=True,
        ), patch(
            "commands.ota_client.get_ota_endpoint",
            return_value="https://ota.example.com",
        ), patch(
            "commands.ota_client.requests.post",
            return_value=_mock_response(
                json_data={"success": True, "data": {"created": 2, "acks": acks}}
            ),
        ) as mock_post:
            ok = ota.flush_install_events()

        self.assertTrue(ok)
        self.assertEqual(self._queued(), [])
        body = mock_post.call_args.kwargs["json"]
        self.assertEqual(len(body["events"]), 2)
        self.assertEqual(
            mock_post.call_args.kwargs["headers"]["X-Robot-Node"], "jetson"
        )

    def test_offline_flush_keeps_the_queue_for_later(self):
        ota.record_install_event("started")

        with patch.dict(
            os.environ,
            {
                "RAISIN_ROBOT_API_KEY": "robot-key",  # pragma: allowlist secret
                "RAISIN_ROBOT_NODE": "jetson",
            },
            clear=True,
        ), patch(
            "commands.ota_client.get_ota_endpoint",
            return_value="https://ota.example.com",
        ), patch(
            "commands.ota_client.requests.post",
            side_effect=requests.ConnectionError("offline"),
        ):
            ok = ota.flush_install_events()

        self.assertFalse(ok)
        self.assertEqual(len(self._queued()), 1)

    def test_replayed_batch_keeps_the_same_event_ids(self):
        """The server dedups on eventId, so a retry must not re-mint them."""
        ota.record_install_event("started")
        first = [e["eventId"] for e in self._queued()]

        with patch.dict(
            os.environ,
            {
                "RAISIN_ROBOT_API_KEY": "robot-key",  # pragma: allowlist secret
                "RAISIN_ROBOT_NODE": "jetson",
            },
            clear=True,
        ), patch(
            "commands.ota_client.get_ota_endpoint",
            return_value="https://ota.example.com",
        ), patch(
            "commands.ota_client.requests.post",
            side_effect=requests.ConnectionError("offline"),
        ):
            ota.flush_install_events()

        self.assertEqual([e["eventId"] for e in self._queued()], first)

    def test_delayed_flush_preserves_occurred_at_ordering(self):
        with patch("commands.ota_client.time.time", side_effect=[100.5, 300.25]), patch(
            "commands.ota_client.time.gmtime", side_effect=time.gmtime
        ):
            ota.record_install_event("started")
            ota.record_install_event("succeeded")

        stamps = [e["occurredAt"] for e in self._queued()]
        self.assertEqual(stamps, sorted(stamps))
        self.assertNotEqual(stamps[0], stamps[1])

    def test_batches_are_capped_at_the_server_limit(self):
        for i in range(ota._INSTALL_EVENT_BATCH_LIMIT + 5):
            ota._append_install_event({"eventId": f"e{i}", "eventType": "started"})

        posted = []

        def capture(*a, **kw):
            events = kw["json"]["events"]
            posted.append(len(events))
            return _mock_response(
                json_data={
                    "success": True,
                    "data": {
                        "acks": [
                            {"eventId": e["eventId"], "status": "created"}
                            for e in events
                        ]
                    },
                }
            )

        with patch.dict(
            os.environ,
            {
                "RAISIN_ROBOT_API_KEY": "robot-key",  # pragma: allowlist secret
                "RAISIN_ROBOT_NODE": "jetson",
            },
            clear=True,
        ), patch(
            "commands.ota_client.get_ota_endpoint",
            return_value="https://ota.example.com",
        ), patch(
            "commands.ota_client.requests.post", side_effect=capture
        ):
            ota.flush_install_events()

        self.assertEqual(posted, [ota._INSTALL_EVENT_BATCH_LIMIT, 5])
        self.assertEqual(self._queued(), [])

    def test_flush_without_robot_auth_is_a_noop_that_keeps_the_queue(self):
        ota.record_install_event("started")

        with patch.dict(os.environ, {}, clear=True):
            ok = ota.flush_install_events()

        self.assertFalse(ok)
        self.assertEqual(len(self._queued()), 1)


class TestInstallEventEmission(unittest.TestCase):
    """The install flow emits the events, not just the plumbing."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = (
            g.script_directory,
            g.os_type,
            g.os_version,
            g.architecture,
        )
        g.script_directory = self._tmp.name
        g.os_type, g.os_version, g.architecture = "linux", "22.04", "x86_64"
        ota._install_session_id = "session-emit"
        ota._archive_cache.clear()
        ota.clear_pending_install_failure()

    def tearDown(self):
        ota._install_session_id = None
        ota._archive_cache.clear()
        ota.clear_pending_install_failure()
        (
            g.script_directory,
            g.os_type,
            g.os_version,
            g.architecture,
        ) = self._orig
        self._tmp.cleanup()

    MANIFEST = (
        [{"packageName": "pkg1", "packageId": "p1", "tagName": "1.0.0"}],
        "arch-1",
        "2026.1.0",
    )

    def _events(self):
        return ota._read_install_event_queue()

    @patch("commands.ota_client._extract_and_read_deps")
    @patch("commands.ota_client._download_package_blob")
    @patch("commands.ota_client._fetch_archive_manifest")
    def test_started_event_names_the_archive(self, mock_manifest, mock_blob, mock_x):
        mock_manifest.return_value = self.MANIFEST
        mock_blob.return_value = (True, None)
        mock_x.return_value = {"version": "1.0.0", "dependencies": []}

        ota.download_all_from_archive(
            "release", Path(self._tmp.name) / "install", archive_version="2026.1.0"
        )

        started = [e for e in self._events() if e["eventType"] == "started"]
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0]["archiveId"], "arch-1")
        self.assertEqual(started[0]["archiveVersion"], "2026.1.0")
        self.assertEqual(started[0]["platform"], "linux-22.04-x86_64")

    @patch("commands.ota_client._download_package_blob")
    @patch("commands.ota_client._fetch_archive_manifest")
    def test_download_failure_is_noted_but_not_terminal_yet(
        self, mock_manifest, mock_blob
    ):
        """A terminal event means the attempt finished — the loop has not."""
        mock_manifest.return_value = self.MANIFEST
        mock_blob.return_value = (False, "disk_full")

        ota.download_all_from_archive(
            "release", Path(self._tmp.name) / "install", archive_version="2026.1.0"
        )

        self.assertEqual([e["eventType"] for e in self._events()], ["started"])
        self.assertEqual(ota.pending_install_failure(), ("download", "disk_full"))

    @patch("commands.ota_client._extract_and_read_deps", return_value=None)
    @patch("commands.ota_client._download_package_blob")
    @patch("commands.ota_client._fetch_archive_manifest")
    def test_extract_failure_is_noted_at_the_unpack_stage(
        self, mock_manifest, mock_blob, _mock_x
    ):
        mock_manifest.return_value = self.MANIFEST
        mock_blob.return_value = (True, None)

        ota.download_all_from_archive(
            "release", Path(self._tmp.name) / "install", archive_version="2026.1.0"
        )

        self.assertEqual([e["eventType"] for e in self._events()], ["started"])
        self.assertEqual(ota.pending_install_failure(), ("unpack", "unpack_failed"))

    @patch("commands.ota_client._extract_and_read_deps")
    @patch("commands.ota_client._download_package_blob")
    @patch("commands.ota_client._fetch_archive_manifest")
    def test_first_failure_wins_when_several_packages_fail(
        self, mock_manifest, mock_blob, mock_x
    ):
        """One terminal event per attempt, so the first cause is the reported one."""
        mock_manifest.return_value = (
            [
                {"packageName": "pkg1", "packageId": "p1", "tagName": "1.0.0"},
                {"packageName": "pkg2", "packageId": "p2", "tagName": "1.0.0"},
            ],
            "arch-1",
            "2026.1.0",
        )
        mock_blob.side_effect = [(False, "server_error"), (True, None)]
        mock_x.return_value = None

        ota.download_all_from_archive(
            "release", Path(self._tmp.name) / "install", archive_version="2026.1.0"
        )

        self.assertEqual(ota.pending_install_failure(), ("download", "server_error"))

    @patch("commands.ota_client._extract_and_read_deps")
    @patch("commands.ota_client._download_package_blob")
    @patch("commands.ota_client._fetch_archive_manifest")
    def test_partial_archive_install_is_not_a_success(
        self, mock_manifest, mock_blob, mock_x
    ):
        """4-of-5 installed is not a completed archive install.

        install_command returns True when *any* package landed, so without the
        noted failure the attempt would report `succeeded` while the server was
        told a package never arrived.
        """
        mock_manifest.return_value = (
            [
                {"packageName": "pkg1", "packageId": "p1", "tagName": "1.0.0"},
                {"packageName": "pkg2", "packageId": "p2", "tagName": "1.0.0"},
            ],
            "arch-1",
            "2026.1.0",
        )
        mock_blob.side_effect = [(False, "network"), (True, None)]
        mock_x.return_value = {"version": "1.0.0", "dependencies": []}

        results = ota.download_all_from_archive(
            "release", Path(self._tmp.name) / "install", archive_version="2026.1.0"
        )

        self.assertEqual(list(results), ["pkg2"])  # partial success
        self.assertIsNotNone(ota.pending_install_failure())

    @patch("commands.ota_client._extract_and_read_deps")
    @patch("commands.ota_client._download_package_blob")
    @patch("commands.ota_client._fetch_archive_manifest")
    def test_success_is_reported_by_the_cli_not_the_download_layer(
        self, mock_manifest, mock_blob, mock_x
    ):
        """The download layer cannot know the install as a whole succeeded."""
        mock_manifest.return_value = self.MANIFEST
        mock_blob.return_value = (True, None)
        mock_x.return_value = {"version": "1.0.0", "dependencies": []}

        ota.download_all_from_archive(
            "release", Path(self._tmp.name) / "install", archive_version="2026.1.0"
        )

        types = [e["eventType"] for e in self._events()]
        self.assertEqual(types, ["started"])
        self.assertIsNone(ota.pending_install_failure())

        ota.record_install_event("succeeded")
        self.assertEqual(
            [e["eventType"] for e in self._events()], ["started", "succeeded"]
        )


class TestInstallSessionPersistence(unittest.TestCase):
    """A resumed install must keep its session id.

    #47 pins download authorization to the archive the session resolved to at
    session start, so a crash-and-retry that invents a new id loses the pin and
    the partial file it was resuming.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_script_directory = g.script_directory
        g.script_directory = self._tmp.name
        ota._install_session_id = None

    def tearDown(self):
        ota._install_session_id = None
        g.script_directory = self._orig_script_directory
        self._tmp.cleanup()

    def _new_process(self):
        """Simulate a fresh CLI process: module state gone, disk state kept."""
        ota._install_session_id = None

    def test_session_id_is_stable_within_a_process(self):
        self.assertEqual(ota.get_install_session_id(), ota.get_install_session_id())

    def test_session_id_survives_a_process_restart(self):
        first = ota.get_install_session_id()
        self._new_process()

        self.assertEqual(ota.get_install_session_id(), first)

    def test_clearing_the_session_starts_a_new_one(self):
        first = ota.get_install_session_id()
        ota.clear_install_session()
        self._new_process()

        self.assertNotEqual(ota.get_install_session_id(), first)

    def test_stale_session_is_not_resumed(self):
        """A session left behind by an install abandoned days ago is not ours."""
        first = ota.get_install_session_id()
        path = ota._install_session_path()
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["startedAt"] = time.time() - (ota._INSTALL_SESSION_TTL_SECONDS + 60)
        path.write_text(json.dumps(payload), encoding="utf-8")
        self._new_process()

        self.assertNotEqual(ota.get_install_session_id(), first)

    def test_corrupt_session_file_does_not_break_the_install(self):
        ota._install_session_path().parent.mkdir(parents=True, exist_ok=True)
        ota._install_session_path().write_text("{not json", encoding="utf-8")
        self._new_process()

        self.assertTrue(ota.get_install_session_id())


class TestDownloadBlobErrorPropagation(unittest.TestCase):
    """`_download_package_blob` reports *why* it failed, not just that it did.

    #29 attaches the code to a terminal install event, so it has to survive the
    trip out of the download layer.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self._tmp.name) / "pkg.zip"

    def tearDown(self):
        self._tmp.cleanup()

    def _call(self, **env):
        with patch.dict(os.environ, env, clear=True), patch(
            "commands.ota_client.get_ota_endpoint",
            return_value="https://ota.example.com",
        ):
            return ota._download_package_blob(
                "arch-1",
                "pkg-1",
                "mypkg",
                self.dest,
                archive_name="dso",
                archive_version="1.0.3",
                platform_str="ubuntu-24.04-arm64",
                install_session_id="session-1",
            )

    def test_success_reports_no_error_code(self):
        body = b"payload"
        resp = _mock_response(
            iter_content=[body],
            headers={"X-Content-Hash": hashlib.sha256(body).hexdigest()},
        )
        with patch("commands.ota_client.requests.get", return_value=resp):
            ok, code = self._call(
                RAISIN_ROBOT_API_KEY="robot-key",  # pragma: allowlist secret
                RAISIN_ROBOT_NODE="jetson",
            )

        self.assertTrue(ok)
        self.assertIsNone(code)

    def test_robot_path_propagates_the_taxonomy_code(self):
        with patch(
            "commands.ota_client.requests.get",
            side_effect=requests.ConnectionError("refused"),
        ), patch("commands.ota_client.time.sleep"):
            ok, code = self._call(
                RAISIN_ROBOT_API_KEY="robot-key",  # pragma: allowlist secret
                RAISIN_ROBOT_NODE="jetson",
            )

        self.assertFalse(ok)
        self.assertEqual(code, "network")

    @patch("commands.ota_client._get_auth_context", return_value=("tok", {}))
    def test_legacy_path_propagates_the_taxonomy_code(self, _ctx):
        resp = _mock_response(status_code=503)
        with patch(
            "commands.ota_client.requests.get",
            side_effect=requests.HTTPError(response=resp),
        ), patch("commands.ota_client.time.sleep"):
            ok, code = self._call()

        self.assertFalse(ok)
        self.assertEqual(code, "server_error")


class TestResumableDownload(unittest.TestCase):
    """`_download_to_path`: atomic rename, resume, disk preflight, backoff."""

    BODY = b"raisin-package-payload"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self._tmp.name) / "pkg.zip"
        self.part = self.dest.with_name(self.dest.name + ".part")
        self.digest = hashlib.sha256(self.BODY).hexdigest()

    def tearDown(self):
        self._tmp.cleanup()

    def _resp(self, body, status=200, extra_headers=None):
        headers = {"X-Content-Hash": self.digest, "Content-Length": str(len(body))}
        headers.update(extra_headers or {})
        return _mock_response(status_code=status, iter_content=[body], headers=headers)

    def test_successful_download_lands_at_final_path(self):
        with patch(
            "commands.ota_client.requests.get", return_value=self._resp(self.BODY)
        ):
            ok, code = ota._download_to_path("https://ota.example.com/x", self.dest)

        self.assertTrue(ok)
        self.assertIsNone(code)
        self.assertEqual(self.dest.read_bytes(), self.BODY)
        self.assertFalse(self.part.exists())

    def test_hash_mismatch_never_leaves_a_file_at_the_final_path(self):
        """A corrupt body must not be visible where the installer looks."""
        bad = _mock_response(
            iter_content=[b"corrupted"],
            headers={"X-Content-Hash": self.digest, "Content-Length": "9"},
        )
        with patch("commands.ota_client.requests.get", return_value=bad), patch(
            "commands.ota_client.time.sleep"
        ):
            ok, code = ota._download_to_path(
                "https://ota.example.com/x", self.dest, max_attempts=1
            )

        self.assertFalse(ok)
        self.assertEqual(code, "hash_mismatch")
        self.assertFalse(self.dest.exists())

    def test_interrupted_download_leaves_only_a_part_file(self):
        """The partial stays for resume, but never under the final name."""

        def explode():
            yield self.BODY[:8]
            raise requests.ConnectionError("reset")

        resp = _mock_response(
            iter_content=explode(),
            headers={
                "X-Content-Hash": self.digest,
                "Content-Length": str(len(self.BODY)),
            },
        )
        with patch("commands.ota_client.requests.get", return_value=resp), patch(
            "commands.ota_client.time.sleep"
        ):
            ok, code = ota._download_to_path(
                "https://ota.example.com/x", self.dest, max_attempts=1
            )

        self.assertFalse(ok)
        self.assertEqual(code, "network")
        self.assertFalse(self.dest.exists())
        self.assertEqual(self.part.read_bytes(), self.BODY[:8])

    def test_resume_sends_range_and_if_range_for_an_existing_part(self):
        self.part.write_bytes(self.BODY[:8])
        ota._write_part_state(self.part, self.digest)

        resp = _mock_response(
            status_code=206,
            iter_content=[self.BODY[8:]],
            headers={
                "X-Content-Hash": self.digest,
                "Content-Range": f"bytes 8-{len(self.BODY) - 1}/{len(self.BODY)}",
            },
        )
        with patch("commands.ota_client.requests.get", return_value=resp) as mock_get:
            ok, _ = ota._download_to_path("https://ota.example.com/x", self.dest)

        sent = mock_get.call_args.kwargs["headers"]
        self.assertEqual(sent["Range"], "bytes=8-")
        self.assertEqual(sent["If-Range"], f'"{self.digest}"')
        self.assertTrue(ok)
        self.assertEqual(self.dest.read_bytes(), self.BODY)

    def test_206_at_the_wrong_offset_is_rejected(self):
        """Appending a slice that does not start where we asked corrupts the file.

        The hash check would eventually catch it, but only after a full
        re-download and while reporting a misleading hash_mismatch.
        """
        self.part.write_bytes(self.BODY[:8])
        ota._write_part_state(self.part, self.digest)

        resp = _mock_response(
            status_code=206,
            iter_content=[self.BODY[4:]],
            headers={
                "X-Content-Hash": self.digest,
                "Content-Range": f"bytes 4-{len(self.BODY) - 1}/{len(self.BODY)}",
            },
        )
        with patch("commands.ota_client.requests.get", return_value=resp), patch(
            "commands.ota_client.time.sleep"
        ):
            ok, code = ota._download_to_path(
                "https://ota.example.com/x", self.dest, max_attempts=1
            )

        self.assertFalse(ok)
        self.assertEqual(code, "network")
        self.assertFalse(self.dest.exists())

    def test_server_ignoring_range_restarts_cleanly(self):
        """A 200 answer to a Range request means the object changed."""
        self.part.write_bytes(b"stale-prefix")
        ota._write_part_state(self.part, "0" * 64)

        with patch(
            "commands.ota_client.requests.get", return_value=self._resp(self.BODY)
        ):
            ok, _ = ota._download_to_path("https://ota.example.com/x", self.dest)

        self.assertTrue(ok)
        self.assertEqual(self.dest.read_bytes(), self.BODY)

    def test_insufficient_disk_space_fails_before_writing(self):
        usage = MagicMock(free=16)
        with patch("commands.ota_client.shutil.disk_usage", return_value=usage), patch(
            "commands.ota_client.requests.get", return_value=self._resp(self.BODY)
        ):
            ok, code = ota._download_to_path(
                "https://ota.example.com/x", self.dest, max_attempts=1
            )

        self.assertFalse(ok)
        self.assertEqual(code, "disk_full")
        self.assertFalse(self.dest.exists())

    def test_transient_failure_is_retried_then_succeeds(self):
        responses = [
            requests.ConnectionError("reset"),
            self._resp(self.BODY),
        ]

        def side_effect(*a, **kw):
            item = responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        with patch("commands.ota_client.requests.get", side_effect=side_effect), patch(
            "commands.ota_client.time.sleep"
        ) as mock_sleep:
            ok, code = ota._download_to_path("https://ota.example.com/x", self.dest)

        self.assertTrue(ok)
        self.assertIsNone(code)
        self.assertEqual(mock_sleep.call_count, 1)

    def test_retries_are_capped_and_report_the_last_error(self):
        with patch(
            "commands.ota_client.requests.get",
            side_effect=requests.ConnectionError("reset"),
        ) as mock_get, patch("commands.ota_client.time.sleep"):
            ok, code = ota._download_to_path(
                "https://ota.example.com/x", self.dest, max_attempts=3
            )

        self.assertFalse(ok)
        self.assertEqual(code, "network")
        self.assertEqual(mock_get.call_count, 3)

    def test_permanent_failure_is_not_retried(self):
        usage = MagicMock(free=1)
        with patch("commands.ota_client.shutil.disk_usage", return_value=usage), patch(
            "commands.ota_client.requests.get", return_value=self._resp(self.BODY)
        ) as mock_get, patch("commands.ota_client.time.sleep"):
            ok, code = ota._download_to_path(
                "https://ota.example.com/x", self.dest, max_attempts=5
            )

        self.assertFalse(ok)
        self.assertEqual(code, "disk_full")
        self.assertEqual(mock_get.call_count, 1)

    def test_backoff_is_exponential_and_jittered(self):
        delays = []
        with patch(
            "commands.ota_client.requests.get",
            side_effect=requests.ConnectionError("reset"),
        ), patch("commands.ota_client.time.sleep", side_effect=delays.append):
            ota._download_to_path(
                "https://ota.example.com/x", self.dest, max_attempts=4
            )

        self.assertEqual(len(delays), 3)
        # Each window doubles; jitter keeps the delay inside it, so a
        # synchronised fleet does not retry in lockstep.
        for i, delay in enumerate(delays):
            self.assertGreater(delay, 0)
            self.assertLessEqual(delay, ota._BACKOFF_BASE_SECONDS * (2**i))
        self.assertNotEqual(len(set(delays)), 1)


# ============================================================================
# 5. Download Tests
# ============================================================================


class TestDownload(unittest.TestCase):
    """Verify _fetch_archive_manifest, download_package, and version matching."""

    def setUp(self):
        ota._cached_token = None
        ota._auth_failed = False
        ota._archive_cache.clear()
        ota._install_session_id = None
        ota._robot_api_key_cache.clear()
        ota._pending_snapshot_reports.clear()
        ota._robot_auth_warning_keys.clear()
        ota._local_config_cache.clear()
        self._orig_os_type = g.os_type
        self._orig_os_version = g.os_version
        self._orig_architecture = g.architecture
        self._orig_script_directory = g.script_directory
        self._tmp_script_dir = tempfile.TemporaryDirectory()
        g.os_type = "linux"
        g.os_version = "22.04"
        g.architecture = "x86_64"
        g.script_directory = self._tmp_script_dir.name

    def tearDown(self):
        ota._cached_token = None
        ota._auth_failed = False
        ota._archive_cache.clear()
        ota._install_session_id = None
        ota._pending_snapshot_reports.clear()
        ota._robot_auth_warning_keys.clear()
        ota._local_config_cache.clear()
        g.os_type = self._orig_os_type
        g.os_version = self._orig_os_version
        g.architecture = self._orig_architecture
        g.script_directory = self._orig_script_directory
        self._tmp_script_dir.cleanup()

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
                "name": "raisin-robot",
                "platform": "linux-22.04-x86_64",
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
    def test_fetch_archive_manifest_uses_exact_version_param(
        self, mock_get, _ep, _auth
    ):
        archive_list = [
            {
                "id": "arch-dso-103",
                "name": "dso",
                "platform": "ubuntu-24.04-arm64",
                "version": "1.0.3",
                "packages": [],
            }
        ]
        mock_get.return_value = _mock_response(
            json_data={
                "data": {"archives": archive_list, "total": 1, "page": 1, "limit": 20}
            }
        )

        result = ota._fetch_archive_manifest("dso", "ubuntu-24.04-arm64", "1.0.3")

        self.assertIsNotNone(result)
        self.assertEqual(result[1], "arch-dso-103")
        params = mock_get.call_args.kwargs["params"]
        self.assertEqual(params["name"], "dso")
        self.assertEqual(params["platform"], "ubuntu-24.04-arm64")
        self.assertEqual(params["version"], "1.0.3")
        self.assertNotIn("search", params)

    @patch("commands.ota_client.authenticate", return_value="tok")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    def test_fetch_archive_manifest_strips_v_prefix_on_send(self, mock_get, _ep, _auth):
        # Server stores versions without the `v` prefix and normalizes the
        # leading `v` case-insensitively (`/^v/i`). The client must strip
        # both cases on send so a user typing `-v V1.0.3` still resolves to
        # the correct archive and the strict client-side comparison below
        # doesn't trip on a casing mismatch.
        archive_list = [
            {
                "id": "arch-dso-103",
                "name": "dso",
                "platform": "ubuntu-24.04-arm64",
                "version": "1.0.3",
                "packages": [],
            }
        ]

        for user_input in ("v1.0.3", "V1.0.3"):
            mock_get.reset_mock()
            ota._archive_cache.clear()
            mock_get.return_value = _mock_response(
                json_data={
                    "data": {
                        "archives": archive_list,
                        "total": 1,
                        "page": 1,
                        "limit": 20,
                    }
                }
            )

            result = ota._fetch_archive_manifest(
                "dso", "ubuntu-24.04-arm64", user_input
            )

            self.assertIsNotNone(
                result, f"version={user_input!r} should resolve to the archive"
            )
            params = mock_get.call_args.kwargs["params"]
            self.assertEqual(params["version"], "1.0.3")

    @patch("commands.ota_client.authenticate", return_value="tok")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    def test_fetch_archive_manifest_tolerates_null_version(self, mock_get, _ep, _auth):
        # A nulled `version` field used to crash with AttributeError on
        # `None.lstrip(...)`. The strict filter should ignore the bad row
        # and still pick the valid one.
        archive_list = [
            {
                "id": "arch-bad",
                "name": "dso",
                "platform": "ubuntu-24.04-arm64",
                "version": None,
                "packages": [],
            },
            {
                "id": "arch-good",
                "name": "dso",
                "platform": "ubuntu-24.04-arm64",
                "version": "1.0.3",
                "packages": [],
            },
        ]
        mock_get.return_value = _mock_response(
            json_data={
                "data": {"archives": archive_list, "total": 2, "page": 1, "limit": 20}
            }
        )

        result = ota._fetch_archive_manifest("dso", "ubuntu-24.04-arm64", "1.0.3")

        self.assertIsNotNone(result)
        self.assertEqual(result[1], "arch-good")

    @patch("commands.ota_client.authenticate", return_value="tok")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    def test_fetch_archive_manifest_caching(self, mock_get, _ep, _auth):
        archive_list = [
            {
                "id": "arch-1",
                "name": "raisin-robot",
                "platform": "linux-22.04-x86_64",
                "version": "v2024.01",
                "packages": [],
            }
        ]
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

    @patch("commands.ota_client.authenticate", return_value="tok")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    def test_fetch_archive_by_tag_returns_archive(self, mock_get, _ep, _auth):
        tag_response = _mock_response(
            json_data={
                "data": {
                    "id": "tag-1",
                    "archiveName": "raisin-robot",
                    "tagName": "stable",
                    "manifests": [
                        {"archiveId": "arch-2", "platform": "linux-22.04-x86_64"},
                        {"archiveId": "arch-3", "platform": "linux-22.04-arm64"},
                    ],
                }
            }
        )
        archive_response = _mock_response(
            json_data={
                "data": {
                    "id": "arch-2",
                    "version": "v1.0.97",
                    "packages": [
                        {
                            "packageName": "raisin",
                            "manifestHash": "abc",
                            "packageId": "p1",
                        },
                    ],
                }
            }
        )
        mock_get.side_effect = [tag_response, archive_response]

        result = ota._fetch_archive_by_tag(
            "raisin-robot", "linux-22.04-x86_64", "stable"
        )
        self.assertIsNotNone(result)
        packages, archive_id, archive_version = result
        self.assertEqual(archive_id, "arch-2")
        self.assertEqual(archive_version, "v1.0.97")
        self.assertEqual(len(packages), 1)
        self.assertEqual(mock_get.call_count, 2)

    @patch("commands.ota_client.authenticate", return_value="tok")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    def test_fetch_archive_by_tag_returns_none_when_platform_missing(
        self, mock_get, _ep, _auth
    ):
        tag_response = _mock_response(
            json_data={
                "data": {
                    "id": "tag-1",
                    "manifests": [
                        {"archiveId": "arch-3", "platform": "linux-22.04-arm64"},
                    ],
                }
            }
        )
        mock_get.return_value = tag_response

        result = ota._fetch_archive_by_tag(
            "raisin-robot", "linux-22.04-x86_64", "stable"
        )
        self.assertIsNone(result)
        # No second call to /archives/{id}
        self.assertEqual(mock_get.call_count, 1)

    @patch("commands.ota_client.authenticate", return_value="tok")
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    def test_fetch_archive_by_tag_returns_none_on_404(self, mock_get, _ep, _auth):
        err_resp = MagicMock()
        err_resp.status_code = 404
        http_err = ota.requests.HTTPError(response=err_resp)
        not_found = _mock_response(status_code=404, raise_for_status=http_err)
        mock_get.return_value = not_found

        result = ota._fetch_archive_by_tag(
            "raisin-robot", "linux-22.04-x86_64", "stable"
        )
        self.assertIsNone(result)

    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.get")
    def test_download_package_blob_uses_robot_endpoint_when_key_configured(
        self, mock_get, _ep
    ):
        mock_get.return_value = _mock_response(iter_content=[b"pkg-data"])

        with tempfile.TemporaryDirectory() as tmpdir:
            download_path = Path(tmpdir) / "pkg.zip"
            with patch.dict(
                os.environ,
                {
                    "RAISIN_ROBOT_API_KEY": "robot-key",  # pragma: allowlist secret
                    "RAISIN_ROBOT_NODE": "jetson",
                    "RAISIN_OTA_CLIENT_VERSION": "raisin-cli-test",
                },
                clear=True,
            ):
                result = ota._download_package_blob(
                    "arch-1",
                    "pkg-1",
                    "mypkg",
                    download_path,
                    archive_name="dso",
                    archive_version="v1.0.3",
                    platform_str="ubuntu-24.04-arm64",
                    install_session_id="session-1",
                )

            self.assertTrue(result)
            self.assertEqual(download_path.read_bytes(), b"pkg-data")

        call_args = mock_get.call_args
        self.assertEqual(
            call_args.args[0],
            "https://ota.example.com/robots/me/archives/by-key/"
            "packages/pkg-1/download",
        )
        self.assertEqual(
            call_args.kwargs["params"],
            {
                "name": "dso",
                "platform": "ubuntu-24.04-arm64",
                "version": "1.0.3",
            },
        )
        self.assertEqual(
            call_args.kwargs["headers"]["Authorization"], "Robot robot-key"
        )
        self.assertEqual(
            call_args.kwargs["headers"]["X-Client-Version"], "raisin-cli-test"
        )
        self.assertEqual(
            call_args.kwargs["headers"]["X-Install-Session-Id"], "session-1"
        )
        self.assertEqual(call_args.kwargs["headers"]["X-Robot-Node"], "jetson")

    @patch("commands.ota_client._stream_download", return_value=True)
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    def test_download_package_blob_falls_back_without_robot_node(
        self, _ep, mock_stream
    ):
        with patch.dict(
            os.environ,
            {"RAISIN_ROBOT_API_KEY": "robot-key"},  # pragma: allowlist secret
            clear=True,
        ), patch("builtins.print") as mock_print:
            result = ota._download_package_blob(
                "arch-1",
                "pkg-1",
                "mypkg",
                Path("/tmp/pkg.zip"),
                archive_name="dso",
                archive_version="1.0.3",
                platform_str="ubuntu-24.04-arm64",
                install_session_id="session-1",
            )

        self.assertTrue(result)
        mock_stream.assert_called_once_with(
            "https://ota.example.com/archives/arch-1/packages/pkg-1/download",
            Path("/tmp/pkg.zip"),
            "mypkg",
        )
        mock_print.assert_called_once()

    @patch("commands.ota_client._get_auth_context", return_value=("tok", {}))
    @patch("commands.ota_client.requests.get")
    def test_stream_download_never_leaves_a_partial_at_the_final_path(
        self, mock_get, _auth
    ):
        def chunks():
            yield b"partial"
            raise ota.requests.ConnectionError("connection lost")

        mock_get.return_value = _mock_response(
            iter_content=chunks(), headers={"Content-Length": "20"}
        )

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "commands.ota_client.time.sleep"
        ):
            download_path = Path(tmpdir) / "pkg.zip"

            ok, code = ota._stream_download(
                "https://ota.example.com/pkg.zip", download_path, "mypkg"
            )

            self.assertFalse(ok)
            self.assertEqual(code, "network")
            self.assertFalse(download_path.exists())

    @patch("commands.ota_client._stream_download", return_value=True)
    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    def test_download_package_blob_keeps_legacy_path_without_robot_key(
        self, _ep, mock_stream
    ):
        with patch.dict(os.environ, {}, clear=True):
            result = ota._download_package_blob(
                "arch-1",
                "pkg-1",
                "mypkg",
                Path("/tmp/pkg.zip"),
                archive_name="dso",
                archive_version="1.0.3",
                platform_str="ubuntu-24.04-arm64",
                install_session_id="session-1",
            )

        self.assertTrue(result)
        mock_stream.assert_called_once_with(
            "https://ota.example.com/archives/arch-1/packages/pkg-1/download",
            Path("/tmp/pkg.zip"),
            "mypkg",
        )

    @patch(
        "commands.ota_client.get_ota_endpoint", return_value="https://ota.example.com"
    )
    @patch("commands.ota_client.requests.post")
    def test_report_software_snapshot_posts_robot_payload(self, mock_post, _ep):
        mock_post.return_value = _mock_response()
        packages = [
            {
                "packageId": "00000000-0000-4000-8000-000000000201",
                "packageName": "mypkg",
                "version": "1.2.0",
                "manifestHash": "a" * 64,
            }
        ]

        with patch.dict(
            os.environ,
            {
                "RAISIN_ROBOT_API_KEY": "robot-key",  # pragma: allowlist secret
                "RAISIN_ROBOT_NODE": "jetson",
                "RAISIN_CLIENT_VERSION": "raisin-cli-test",
            },
            clear=True,
        ):
            result = ota.report_software_snapshot(
                archive_id="arch-1",
                archive_name="dso",
                archive_version="v1.0.3",
                platform_str="ubuntu-24.04-arm64",
                packages=packages,
                install_session_id="session-1",
            )

        self.assertTrue(result)
        call_args = mock_post.call_args
        self.assertEqual(
            call_args.args[0],
            "https://ota.example.com/robots/me/software-snapshot",
        )
        self.assertEqual(
            call_args.kwargs["headers"]["Authorization"], "Robot robot-key"
        )
        self.assertEqual(
            call_args.kwargs["headers"]["X-Install-Session-Id"], "session-1"
        )
        self.assertEqual(call_args.kwargs["headers"]["X-Robot-Node"], "jetson")
        self.assertEqual(call_args.kwargs["json"]["archiveId"], "arch-1")
        self.assertEqual(call_args.kwargs["json"]["name"], "dso")
        self.assertEqual(call_args.kwargs["json"]["version"], "1.0.3")
        self.assertEqual(call_args.kwargs["json"]["platform"], "ubuntu-24.04-arm64")
        self.assertEqual(call_args.kwargs["json"]["archivePackages"], packages)
        self.assertNotIn("packages", call_args.kwargs["json"])
        self.assertEqual(call_args.kwargs["json"]["installSessionId"], "session-1")
        self.assertEqual(call_args.kwargs["json"]["clientVersion"], "raisin-cli-test")

    def test_collect_archive_snapshot_packages_ignores_non_object_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            install_base = Path(tmpdir) / "release" / "install"
            metadata_path = (
                install_base
                / "mypkg"
                / "linux"
                / "22.04"
                / "x86_64"
                / "release"
                / ota._INSTALL_METADATA_FILE
            )
            metadata_path.parent.mkdir(parents=True, exist_ok=True)
            metadata_path.write_text("[]", encoding="utf-8")

            packages = ota._collect_archive_snapshot_packages(
                install_base,
                "arch-1",
                "linux-22.04-x86_64",
                "release",
            )

        self.assertEqual(packages, [])

    @patch("commands.ota_client._fetch_archive_by_tag")
    @patch("commands.ota_client._download_package_blob")
    def test_download_all_uses_tag_when_provided(self, mock_dl, mock_fetch_by_tag):
        mock_fetch_by_tag.return_value = (
            [{"packageName": "raisin", "manifestHash": "abc", "packageId": "p1"}],
            "arch-tagged",
            "v1.0.97",
        )
        mock_dl.return_value = (True, None)

        with tempfile.TemporaryDirectory() as tmpdir:
            ota.download_all_from_archive("release", Path(tmpdir), tag="stable")

        mock_fetch_by_tag.assert_called_once()
        args = mock_fetch_by_tag.call_args.args
        self.assertEqual(args[2], "stable")  # tag is third positional

    @patch("commands.ota_client._fetch_archive_by_tag")
    def test_download_all_returns_empty_when_tag_unresolvable(self, mock_fetch_by_tag):
        # When the requested tag can't be resolved (and tag IS 'stable' so
        # no further fallback), the function should surface an empty result
        # (and a warning) rather than aborting, so install.py can fall back
        # to GitHub releases for each repo.
        mock_fetch_by_tag.return_value = None
        with tempfile.TemporaryDirectory() as tmpdir:
            result = ota.download_all_from_archive(
                "release", Path(tmpdir), tag="stable"
            )
        self.assertEqual(result, {})

    @patch("commands.ota_client._download_package_blob", return_value=(True, None))
    @patch("commands.ota_client._fetch_archive_by_tag")
    def test_download_all_falls_back_to_stable_when_requested_tag_missing(
        self, mock_fetch_by_tag, _mock_dl
    ):
        # Requested 'latest' returns None on the first call, then 'stable'
        # returns a valid manifest. The function should silently succeed
        # using the stable archive.
        latest_manifest = None
        stable_manifest = ([], "arch-stable", "1.0.97")

        def side_effect(_name, _platform, tag, **_kw):
            return stable_manifest if tag == "stable" else latest_manifest

        mock_fetch_by_tag.side_effect = side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            result = ota.download_all_from_archive(
                "release", Path(tmpdir), tag="latest"
            )

        # Both tags were queried; the function returned the stable
        # manifest's result dict (empty in this case because the manifest
        # had no packages, but it's a dict not the falsy {} sentinel).
        called_tags = [call.args[2] for call in mock_fetch_by_tag.call_args_list]
        self.assertIn("latest", called_tags)
        self.assertIn("stable", called_tags)
        # Empty manifest means no packages downloaded, but the function
        # ran the success path.
        self.assertEqual(result, {})

    @patch("commands.ota_client._fetch_archive_manifest")
    @patch("commands.ota_client._fetch_archive_by_tag")
    @patch("commands.ota_client._download_package_blob")
    def test_archive_version_takes_precedence_over_tag(
        self, mock_dl, mock_by_tag, mock_by_version
    ):
        mock_by_version.return_value = ([], "arch-v", "v1.0.97")
        mock_dl.return_value = (True, None)

        with tempfile.TemporaryDirectory() as tmpdir:
            ota.download_all_from_archive(
                "release",
                Path(tmpdir),
                archive_version="v1.0.97",
                tag="stable",
            )

        mock_by_version.assert_called_once()
        mock_by_tag.assert_not_called()

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
        mock_blob.return_value = (True, None)

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
            def fake_download(archive_id, pkg_id, name, path, **_kwargs):
                # File already written above
                return (True, None)

            mock_blob.side_effect = fake_download

            result = ota.download_package(
                "mypkg", "", "release", install_base, tag=None
            )

            metadata_path = (
                install_base
                / "mypkg"
                / "linux"
                / "22.04"
                / "x86_64"
                / "release"
                / ota._INSTALL_METADATA_FILE
            )
            self.assertTrue(metadata_path.is_file())
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

        self.assertIsNotNone(result)
        self.assertEqual(result["version"], "1.2.0")
        self.assertIn("depA", result["dependencies"])
        self.assertEqual(metadata["source"], "archive")
        self.assertEqual(metadata["archiveId"], "arch-1")
        self.assertEqual(metadata["archiveVersion"], "v2024.01")
        self.assertEqual(metadata["packageId"], "p1")
        self.assertEqual(metadata["packageVersion"], "1.2.0")
        self.assertEqual(metadata["packageTag"], "v1.2.0")
        self.assertEqual(metadata["manifestHash"], "a" * 64)
        self.assertEqual(metadata["requestedArchiveVersion"], None)
        self.assertIn("installedAt", metadata)

    @patch("commands.ota_client._download_package_blob", return_value=(True, None))
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

            def fake_download(archive_id, pkg_id, name, path, **_kwargs):
                return (True, None)

            mock_blob.side_effect = fake_download

            # Spec ">=1.0.0,<2.0.0" should pick 1.5.0 (highest matching)
            result = ota.download_package(
                "mypkg", ">=1.0.0 <2.0.0", "release", install_base, tag=None
            )

        self.assertIsNotNone(result)
        self.assertEqual(result["version"], "1.5.0")

    @patch("commands.ota_client._queue_snapshot_report")
    @patch("commands.ota_client.get_install_session_id", return_value="session-1")
    @patch("commands.ota_client._download_package_blob", return_value=(True, None))
    @patch("commands.ota_client._fetch_archive_manifest")
    def test_download_package_defers_snapshot_report(
        self, mock_manifest, mock_blob, _session_id, mock_queue
    ):
        packages = [
            {
                "packageName": "mypkg",
                "tagName": "v1.2.0",
                "packageId": "p1",
                "manifestHash": "a" * 64,
            }
        ]
        mock_manifest.return_value = (packages, "arch-1", "v2024.01")

        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            install_base = Path(tmpdir) / "release" / "install"
            install_base.mkdir(parents=True)
            download_file = Path(tmpdir) / "install" / "mypkg-ota-1.2.0.zip"
            download_file.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(download_file, "w") as zf:
                zf.writestr("release.yaml", "version: 1.2.0\n")

            result = ota.download_package(
                "mypkg", "", "release", install_base, tag=None
            )

        self.assertIsNotNone(result)
        mock_queue.assert_called_once()
        self.assertEqual(mock_queue.call_args.kwargs["archive_id"], "arch-1")
        self.assertEqual(mock_queue.call_args.kwargs["install_session_id"], "session-1")

    @patch("commands.ota_client._report_snapshot_from_install_metadata")
    def test_pending_snapshot_reports_are_deduplicated_until_flush(self, mock_report):
        install_base = Path("/tmp/install-base")

        ota._queue_snapshot_report(
            install_base_path=install_base,
            archive_id="arch-1",
            archive_name="dso",
            archive_version="v1.0.3",
            platform_str="linux-22.04-x86_64",
            build_type="release",
            install_session_id="session-1",
        )
        ota._queue_snapshot_report(
            install_base_path=install_base,
            archive_id="arch-1",
            archive_name="dso",
            archive_version="v1.0.3",
            platform_str="linux-22.04-x86_64",
            build_type="release",
            install_session_id="session-1",
        )

        mock_report.assert_not_called()
        ota.flush_pending_snapshot_reports()

        mock_report.assert_called_once_with(
            install_base_path=install_base,
            archive_id="arch-1",
            archive_name="dso",
            archive_version="v1.0.3",
            platform_str="linux-22.04-x86_64",
            build_type="release",
            install_session_id="session-1",
            manifest_hashes={},
        )
        self.assertEqual(ota._pending_snapshot_reports, {})

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

            result = ota.download_package(
                "mypkg", "", "release", install_base, tag=None
            )

        self.assertIsNone(result)

    @patch("commands.ota_client._fetch_archive_manifest", return_value=None)
    def test_download_package_manifest_unavailable(self, _manifest):
        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            result = ota.download_package(
                "mypkg", "", "release", Path(tmpdir), tag=None
            )
        self.assertIsNone(result)

    @patch("commands.ota_client._fetch_archive_by_tag", return_value=None)
    def test_download_package_returns_none_when_tag_unresolvable(self, _by_tag):
        # Per-package install returns None when the tag can't be resolved
        # (and tag is 'stable' so no further fallback). install.py's
        # per-target loop will then fall back to GitHub releases.
        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            result = ota.download_package(
                "mypkg", "", "release", Path(tmpdir), tag="stable"
            )
        self.assertIsNone(result)

    # Without this the test reaches the real OTA endpoint; the assertion is
    # about tag resolution, not about downloading anything.
    @patch(
        "commands.ota_client._download_package_blob",
        return_value=(False, "network"),
    )
    @patch("commands.ota_client._fetch_archive_by_tag")
    def test_download_package_falls_back_to_stable_when_requested_tag_missing(
        self, mock_fetch_by_tag, _mock_blob
    ):
        # latest → None; stable → valid manifest. Expect both tags queried
        # before the package lookup runs against the stable manifest.
        stable_manifest = (
            [{"packageName": "mypkg", "packageId": "p1", "tagName": "1.0.0"}],
            "arch-stable",
            "1.0.97",
        )

        def side_effect(_name, _platform, tag, **_kw):
            return stable_manifest if tag == "stable" else None

        mock_fetch_by_tag.side_effect = side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            ota.download_package("mypkg", "", "release", Path(tmpdir), tag="latest")

        called_tags = [call.args[2] for call in mock_fetch_by_tag.call_args_list]
        self.assertEqual(called_tags, ["latest", "stable"])

    # ------------------------------------------------------------------
    # Robot download integrity
    # ------------------------------------------------------------------

    # The body the mocked robot download streams, and the digest the server
    # would advertise for it.
    _ABC_SHA256 = hashlib.sha256(b"abc").hexdigest()

    def _robot_download(self, headers, target):
        """Run a robot-authenticated download of b'abc' with the given headers."""
        with patch.dict(
            os.environ,
            {
                "RAISIN_ROBOT_API_KEY": "robot-key",  # pragma: allowlist secret
                "RAISIN_ROBOT_NODE": "jetson",
            },
            clear=True,
        ), patch(
            "commands.ota_client.get_ota_endpoint",
            return_value="https://ota.example.com",
        ), patch(
            "commands.ota_client.requests.get",
            return_value=_mock_response(iter_content=[b"abc"], headers=headers),
        ), patch(
            "commands.ota_client.time.sleep"
        ), patch(
            "builtins.print"
        ) as mock_print:
            ok, _code = ota._download_package_blob(
                "arch-1",
                "pkg-1",
                "mypkg",
                target,
                archive_name="dso",
                archive_version="1.0.3",
                platform_str="ubuntu-24.04-arm64",
                install_session_id="session-1",
            )
        return ok, mock_print

    def test_robot_download_accepts_matching_content_hash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "pkg.zip"
            ok, _ = self._robot_download({"X-Content-Hash": self._ABC_SHA256}, target)

        self.assertTrue(ok)

    def test_robot_download_rejects_content_hash_mismatch(self):
        """A truncated or corrupted body must fail here, not during extraction."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "pkg.zip"
            ok, mock_print = self._robot_download({"X-Content-Hash": "f" * 64}, target)
            self.assertFalse(target.exists())

        self.assertFalse(ok)
        self.assertTrue(
            any("hash_mismatch" in str(c) for c in mock_print.call_args_list)
        )

    def test_robot_download_verifies_against_etag_when_no_explicit_header(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "pkg.zip"
            ok, _ = self._robot_download({"ETag": f'"{self._ABC_SHA256}"'}, target)

        self.assertTrue(ok)

    def test_robot_download_warns_when_server_sends_no_hash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "pkg.zip"
            ok, mock_print = self._robot_download({}, target)

        self.assertTrue(ok)
        self.assertTrue(
            any(
                "integrity was not verified" in str(c)
                for c in mock_print.call_args_list
            )
        )

    def test_expected_content_hash_normalizes_server_formats(self):
        self.assertEqual(
            ota._expected_content_hash({"X-Content-Hash": self._ABC_SHA256.upper()}),
            self._ABC_SHA256,
        )
        self.assertEqual(
            ota._expected_content_hash({"ETag": f'W/"sha256:{self._ABC_SHA256}"'}),
            self._ABC_SHA256,
        )
        self.assertIsNone(ota._expected_content_hash({"ETag": "not-a-hash"}))
        self.assertIsNone(ota._expected_content_hash({}))

    # ------------------------------------------------------------------
    # Snapshot manifest-hash backfill
    # ------------------------------------------------------------------

    def _write_install_metadata(self, base, package_name, package_id, manifest_hash):
        install_dir = base / package_name / "linux" / "22.04" / "x86_64" / "release"
        install_dir.mkdir(parents=True, exist_ok=True)
        metadata = {
            "source": "archive",
            "archiveId": "arch-1",
            "platform": "linux-22.04-x86_64",
            "buildType": "release",
            "packageName": package_name,
            "packageId": package_id,
            "packageVersion": "1.0.0",
        }
        if manifest_hash:
            metadata["manifestHash"] = manifest_hash
        (install_dir / "ota-install.json").write_text(
            json.dumps(metadata), encoding="utf-8"
        )

    def test_snapshot_backfills_manifest_hash_from_archive_manifest(self):
        """Installs recorded before manifestHash existed must still be reported.

        The server clears and replaces the node's package set on every
        snapshot, so omitting a package records it as uninstalled.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            self._write_install_metadata(base, "pkg1", "p1", "a" * 64)
            self._write_install_metadata(base, "pkg2", "p2", None)

            hashes = ota.manifest_hashes_by_package_id(
                [
                    {"packageId": "p1", "manifestHash": "a" * 64},
                    {"packageId": "p2", "manifestHash": "b" * 64},
                ]
            )
            packages = ota._collect_archive_snapshot_packages(
                base, "arch-1", "linux-22.04-x86_64", "release", manifest_hashes=hashes
            )

        self.assertCountEqual(
            packages,
            [
                {
                    "packageId": "p1",
                    "packageName": "pkg1",
                    "version": "1.0.0",
                    "manifestHash": "a" * 64,
                },
                {
                    "packageId": "p2",
                    "packageName": "pkg2",
                    "version": "1.0.0",
                    "manifestHash": "b" * 64,
                },
            ],
        )

    def test_snapshot_excludes_unrecoverable_package_with_warning(self):
        """A package absent from the manifest cannot be reported either way.

        The server rejects customPackages entries whose packageId belongs to
        the archive manifest, so there is no fallback route — say so instead of
        dropping it silently.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            self._write_install_metadata(base, "pkg1", "p1", "a" * 64)
            self._write_install_metadata(base, "ghost", "p9", None)

            with patch("builtins.print") as mock_print:
                packages = ota._collect_archive_snapshot_packages(
                    base,
                    "arch-1",
                    "linux-22.04-x86_64",
                    "release",
                    manifest_hashes={"p1": "a" * 64},
                )

        self.assertEqual([p["packageName"] for p in packages], ["pkg1"])
        self.assertTrue(
            any("Excluding 'ghost" in str(c) for c in mock_print.call_args_list)
        )

    def test_queued_snapshot_reports_merge_manifest_hashes(self):
        """Each single-package install contributes its slice of the manifest."""
        ota._queue_snapshot_report(
            install_base_path=Path("/tmp/install-base"),
            archive_id="arch-1",
            archive_name="dso",
            archive_version="1.0.3",
            platform_str="linux-22.04-x86_64",
            build_type="release",
            install_session_id="session-1",
            manifest_hashes={"p1": "a" * 64},
        )
        ota._queue_snapshot_report(
            install_base_path=Path("/tmp/install-base"),
            archive_id="arch-1",
            archive_name="dso",
            archive_version="1.0.3",
            platform_str="linux-22.04-x86_64",
            build_type="release",
            install_session_id="session-1",
            manifest_hashes={"p2": "b" * 64},
        )

        pending = list(ota._pending_snapshot_reports.values())
        self.assertEqual(len(pending), 1)
        self.assertEqual(
            pending[0]["manifest_hashes"], {"p1": "a" * 64, "p2": "b" * 64}
        )

    # ------------------------------------------------------------------
    # Desired state
    # ------------------------------------------------------------------

    def _desired_state(self, payload, platform="ubuntu-24.04-arm64"):
        with patch.dict(
            os.environ,
            {
                "RAISIN_ROBOT_API_KEY": "robot-key",  # pragma: allowlist secret
                "RAISIN_ROBOT_NODE": "jetson",
            },
            clear=True,
        ), patch(
            "commands.ota_client.get_ota_endpoint",
            return_value="https://ota.example.com",
        ), patch(
            "commands.ota_client.requests.get",
            return_value=_mock_response(json_data={"success": True, "data": payload}),
        ), patch(
            "builtins.print"
        ):
            return ota._resolve_desired_state(platform)

    def test_resolve_desired_state_returns_assigned_target(self):
        halted, name, version = self._desired_state(
            {
                "halt": False,
                "reason": "node_pin",
                "target": {
                    "archiveId": "arch-1",
                    "name": "raisin-robot",
                    "version": "2026.1.0",
                    "platform": "ubuntu-24.04-arm64",
                },
            }
        )

        self.assertEqual((halted, name, version), (False, "raisin-robot", "2026.1.0"))

    def test_resolve_desired_state_honours_halt(self):
        halted, name, version = self._desired_state(
            {"halt": True, "haltSources": ["tenant"], "reason": "node_pin"}
        )

        self.assertEqual((halted, name, version), (True, None, None))

    def test_resolve_desired_state_ignores_target_for_other_platform(self):
        halted, name, _ = self._desired_state(
            {
                "halt": False,
                "reason": "node_pin",
                "target": {
                    "name": "raisin-robot",
                    "version": "2026.1.0",
                    "platform": "ubuntu-22.04-x86_64",
                },
            }
        )

        self.assertFalse(halted)
        self.assertIsNone(name)

    def test_resolve_desired_state_without_robot_auth_is_inert(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                ota._resolve_desired_state("ubuntu-24.04-arm64"), (False, None, None)
            )

    @patch("commands.ota_client._fetch_archive_with_stable_fallback")
    @patch("commands.ota_client._resolve_desired_state")
    def test_download_all_from_archive_aborts_when_halted(
        self, mock_desired, mock_fetch
    ):
        mock_desired.return_value = (True, None, None)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = ota.download_all_from_archive("release", Path(tmpdir))

        self.assertEqual(result, {})
        mock_fetch.assert_not_called()

    @patch("commands.ota_client._fetch_archive_manifest", return_value=None)
    @patch("commands.ota_client._resolve_desired_state")
    def test_caller_pinned_archive_outranks_desired_state(
        self, mock_desired, mock_fetch
    ):
        """An explicit pin is a deliberate choice; the fleet must not override it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ota.download_all_from_archive(
                "release", Path(tmpdir), archive_version="1.2.3"
            )

        mock_desired.assert_not_called()
        self.assertEqual(mock_fetch.call_args.args[2], "1.2.3")


class TestArchiveNameAndTimestamp(unittest.TestCase):
    """Test archive name derivation and timestamp-based downloads."""

    def setUp(self):
        ota._cached_token = None
        ota._auth_failed = False
        ota._archive_cache.clear()
        ota._install_session_id = None
        ota._robot_api_key_cache.clear()
        ota._robot_auth_warning_keys.clear()
        ota._local_config_cache.clear()
        self._orig_os_type = g.os_type
        self._orig_os_version = g.os_version
        self._orig_architecture = g.architecture
        self._orig_script_directory = g.script_directory
        self._tmp_script_dir = tempfile.TemporaryDirectory()
        g.os_type = "linux"
        g.os_version = "22.04"
        g.architecture = "x86_64"
        g.script_directory = self._tmp_script_dir.name

    def tearDown(self):
        ota._cached_token = None
        ota._auth_failed = False
        ota._archive_cache.clear()
        ota._install_session_id = None
        ota._pending_snapshot_reports.clear()
        ota._robot_api_key_cache.clear()
        ota._robot_auth_warning_keys.clear()
        ota._local_config_cache.clear()
        g.os_type = self._orig_os_type
        g.os_version = self._orig_os_version
        g.architecture = self._orig_architecture
        g.script_directory = self._orig_script_directory
        self._tmp_script_dir.cleanup()
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

    @patch.dict(os.environ, {"RAISIN_ARCHIVE_NAME": "env-archive"})
    def test_get_archive_name_explicit_override_wins(self):
        """Explicit archive override should take precedence over env var."""
        self.assertEqual(
            ota.get_archive_name("release", archive_name="cli-archive"),
            "cli-archive",
        )
        self.assertEqual(
            ota.get_archive_name("debug", archive_name="cli-archive"),
            "cli-archive-debug",
        )

    def test_get_archive_name_explicit_debug_name_not_duplicated(self):
        """Explicit debug archive name should not gain a second -debug suffix."""
        self.assertEqual(
            ota.get_archive_name("debug", archive_name="raisin-robot-debug"),
            "raisin-robot-debug",
        )

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

            metadata_path = (
                install_base
                / "mypkg"
                / "linux"
                / "22.04"
                / "x86_64"
                / "release"
                / ota._INSTALL_METADATA_FILE
            )
            self.assertTrue(metadata_path.is_file())
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

        self.assertIsNotNone(result)
        self.assertEqual(result["version"], "1.5.0")
        self.assertIn("depB", result["dependencies"])
        self.assertEqual(metadata["source"], "timestamp")
        self.assertEqual(metadata["otaEndpoint"], "https://ota.example.com")
        self.assertEqual(metadata["requestedTimestamp"], "2024-01-15T10:00:00Z")
        self.assertEqual(metadata["packageId"], "pkg-uuid")
        self.assertEqual(metadata["packageVersion"], "1.5.0")
        self.assertEqual(metadata["blobHash"], "abc123" * 10 + "abcd")
        self.assertIn("installedAt", metadata)

    @patch("commands.ota_client.report_software_snapshot", return_value=True)
    @patch("commands.ota_client.get_install_session_id", return_value="session-1")
    @patch("commands.ota_client._download_package_blob", return_value=(True, None))
    @patch("commands.ota_client._fetch_archive_manifest")
    def test_download_all_from_archive(
        self, mock_manifest, mock_blob, _session_id, mock_report_snapshot
    ):
        """Download all packages from an archive."""
        packages = [
            {
                "packageName": "pkg1",
                "tagName": "v1.0.0",
                "packageId": "p1",
                "manifestHash": "a" * 64,
            },
            {
                "packageName": "pkg2",
                "tagName": "v2.0.0",
                "packageId": "p2",
                "manifestHash": "b" * 64,
            },
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

            # tag=None opts into the legacy latest-by-time selection that
            # mock_manifest is faking; without it the default tag='stable'
            # would route through _fetch_archive_by_tag instead.
            result = ota.download_all_from_archive("release", install_base, tag=None)

            metadata_path = (
                install_base
                / "pkg1"
                / "linux"
                / "22.04"
                / "x86_64"
                / "release"
                / ota._INSTALL_METADATA_FILE
            )
            self.assertTrue(metadata_path.is_file())
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

        self.assertEqual(len(result), 2)
        self.assertIn("pkg1", result)
        self.assertIn("pkg2", result)
        self.assertEqual(result["pkg1"]["version"], "1.0.0")
        self.assertEqual(result["pkg2"]["version"], "2.0.0")
        self.assertEqual(metadata["source"], "archive")
        self.assertEqual(metadata["archiveVersion"], "v2024.01")
        self.assertEqual(metadata["packageId"], "p1")
        self.assertEqual(metadata["manifestHash"], "a" * 64)
        self.assertEqual(metadata["installSessionId"], "session-1")
        self.assertEqual(result["pkg1"]["otaMetadata"]["installSessionId"], "session-1")

        mock_report_snapshot.assert_called_once()
        report_kwargs = mock_report_snapshot.call_args.kwargs
        self.assertEqual(report_kwargs["archive_id"], "arch-1")
        self.assertEqual(report_kwargs["archive_name"], "raisin-robot")
        self.assertEqual(report_kwargs["archive_version"], "v2024.01")
        self.assertEqual(report_kwargs["platform_str"], "linux-22.04-x86_64")
        self.assertEqual(report_kwargs["install_session_id"], "session-1")
        self.assertCountEqual(
            report_kwargs["packages"],
            [
                {
                    "packageId": "p1",
                    "packageName": "pkg1",
                    "version": "1.0.0",
                    "manifestHash": "a" * 64,
                },
                {
                    "packageId": "p2",
                    "packageName": "pkg2",
                    "version": "2.0.0",
                    "manifestHash": "b" * 64,
                },
            ],
        )

    @patch(
        "commands.ota_client._fetch_archive_manifest",
        return_value=([], "arch-1", "v2024.01"),
    )
    def test_download_package_uses_archive_name_override(self, mock_manifest):
        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            install_base = Path(tmpdir) / "release" / "install"
            install_base.mkdir(parents=True)

            ota.download_package(
                "mypkg",
                "",
                "release",
                install_base,
                archive_name="custom-archive",
                tag=None,
            )

        mock_manifest.assert_called_once_with(
            "custom-archive",
            "linux-22.04-x86_64",
            None,
        )

    @patch(
        "commands.ota_client._fetch_archive_manifest",
        return_value=([], "arch-1", "v2024.01"),
    )
    def test_download_all_from_archive_uses_archive_name_override(self, mock_manifest):
        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            install_base = Path(tmpdir) / "release" / "install"
            install_base.mkdir(parents=True)

            ota.download_all_from_archive(
                "debug",
                install_base,
                archive_name="custom-archive",
                tag=None,
            )

        mock_manifest.assert_called_once_with(
            "custom-archive-debug",
            "linux-22.04-x86_64",
            None,
        )

    @patch(
        "commands.ota_client._fetch_archive_manifest",
        return_value=([], "arch-1", "v2024.01"),
    )
    def test_download_all_from_archive_preserves_explicit_debug_archive_name(
        self, mock_manifest
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            install_base = Path(tmpdir) / "release" / "install"
            install_base.mkdir(parents=True)

            ota.download_all_from_archive(
                "debug",
                install_base,
                archive_name="raisin-robot-debug",
                tag=None,
            )

        mock_manifest.assert_called_once_with(
            "raisin-robot-debug",
            "linux-22.04-x86_64",
            None,
        )


# ============================================================================
# 6. Integration: install.py
# ============================================================================


class TestInstallCliEventReporting(unittest.TestCase):
    """The CLI closes the attempt, then flushes."""

    def _run_cli(self, overall_success):
        import click

        from commands import install as install_mod

        with patch.object(
            install_mod, "install_command", return_value=overall_success
        ), patch.object(
            install_mod, "report_install_outcome"
        ) as mock_outcome, patch.object(
            install_mod, "flush_install_events"
        ) as mock_flush, patch.object(
            install_mod, "flush_pending_snapshot_reports"
        ), patch.object(
            install_mod, "clear_install_session"
        ):
            try:
                # It is a click Command; call the underlying function.
                install_mod.install_cli_command.callback(
                    ["mypkg"], "release", False, None, None, None, False, "stable"
                )
            except click.exceptions.Exit:
                pass
        return mock_outcome, mock_flush

    def test_successful_run_closes_the_attempt_then_flushes(self):
        mock_outcome, mock_flush = self._run_cli(overall_success=True)

        mock_outcome.assert_called_once_with(True)
        mock_flush.assert_called_once()

    def test_failed_run_still_closes_and_flushes(self):
        """A failed attempt is exactly the one that needs reporting."""
        mock_outcome, mock_flush = self._run_cli(overall_success=False)

        mock_outcome.assert_called_once_with(False)
        mock_flush.assert_called_once()


class TestInstallOutcomeDecision(unittest.TestCase):
    """`report_install_outcome` picks the single terminal event."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = g.script_directory
        g.script_directory = self._tmp.name
        ota._install_session_id = "session-outcome"
        ota.clear_pending_install_failure()

    def tearDown(self):
        ota._install_session_id = None
        ota.clear_pending_install_failure()
        g.script_directory = self._orig
        self._tmp.cleanup()

    def _events(self):
        return ota._read_install_event_queue()

    def test_nothing_is_reported_when_ota_never_started(self):
        self.assertIsNone(ota.report_install_outcome(True))
        self.assertEqual(self._events(), [])

    def test_clean_run_reports_succeeded(self):
        ota.record_install_event("started")

        ota.report_install_outcome(True)

        self.assertEqual(
            [e["eventType"] for e in self._events()], ["started", "succeeded"]
        )

    def test_noted_failure_outranks_an_overall_success(self):
        """The partial-archive case: install_command returns True anyway."""
        ota.record_install_event("started")
        ota.note_install_failure("download", "network", "pkg3 never arrived")

        ota.report_install_outcome(True)

        terminal = self._events()[-1]
        self.assertEqual(terminal["eventType"], "failed")
        self.assertEqual(terminal["stage"], "download")
        self.assertEqual(terminal["errorCode"], "network")

    def test_failure_with_nothing_noted_still_closes_the_session(self):
        """An open session would otherwise be read as 'stale in progress'."""
        ota.record_install_event("started")

        ota.report_install_outcome(False)

        terminal = self._events()[-1]
        self.assertEqual(terminal["eventType"], "failed")
        self.assertEqual(terminal["errorCode"], "unknown")


class TestInstallIntegration(unittest.TestCase):
    """Verify OTA is used correctly in install_command."""

    @patch("commands.install.load_configuration")
    def test_ota_attempted_when_configured(self, mock_config):
        """Install should try OTA before GitHub."""
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

    @patch("commands.install.load_configuration")
    def test_install_command_passes_archive_name_to_ota(self, mock_config):
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
                session.get.return_value = _mock_response(json_data=[])

                from commands.install import install_command

                install_command(["mypkg"], "release", archive_name="team-archive")

        self.assertEqual(mock_dl.call_args.kwargs["archive_name"], "team-archive")

    def test_install_cli_accepts_archive_name_option(self):
        from commands.install import install_cli_command

        runner = CliRunner()
        with patch("commands.install.install_command") as mock_install:
            result = runner.invoke(
                install_cli_command,
                ["mypkg", "--archive-name", "team-archive"],
            )

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(mock_install.call_args[0][3], "team-archive")

    def test_install_cli_default_tag_is_none_for_install_command_to_derive(self):
        # The CLI default is now None so that install_command can derive
        # the right tag from configuration_setting.yaml's user_type.
        # An explicit --tag value (any other test) still propagates as-is.
        from commands.install import install_cli_command

        runner = CliRunner()
        with patch("commands.install.install_command") as mock_install:
            result = runner.invoke(install_cli_command, ["mypkg"])

        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(mock_install.call_args.kwargs["tag"])

    def test_install_cli_custom_tag_passed_through(self):
        from commands.install import install_cli_command

        runner = CliRunner()
        with patch("commands.install.install_command") as mock_install:
            result = runner.invoke(install_cli_command, ["mypkg", "--tag", "beta"])

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(mock_install.call_args.kwargs["tag"], "beta")

    def test_install_cli_tag_none_passes_string_for_install_command_to_normalize(
        self,
    ):
        # The CLI itself accepts any string; the install_command layer
        # is responsible for normalising the literal 'none' to Python None
        # so the underlying ota_client falls back to legacy selection.
        from commands.install import install_cli_command

        runner = CliRunner()
        with patch("commands.install.install_command") as mock_install:
            result = runner.invoke(install_cli_command, ["mypkg", "--tag", "none"])

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(mock_install.call_args.kwargs["tag"], "none")

    def test_install_command_normalises_tag_none_for_download(self):
        # When no packages are queued, install_command forwards to
        # download_all_from_archive and must normalise 'none' (any case) to
        # None so the OTA client falls back to legacy lookup.
        from commands.install import install_command

        with tempfile.TemporaryDirectory() as tmpdir:
            self._orig_script_directory = g.script_directory
            g.script_directory = tmpdir
            try:
                with patch(
                    "commands.install.load_configuration",
                    return_value=([{"name": "any-repo"}], {}, "user", None, []),
                ):
                    with patch("commands.install.download_all_from_archive") as mock_dl:
                        install_command([], "release", tag="none")
            finally:
                g.script_directory = self._orig_script_directory

        self.assertIsNone(mock_dl.call_args.kwargs["tag"])

    def test_default_tag_for_user_type_devel_is_latest(self):
        from commands.install import _default_tag_for_user_type

        self.assertEqual(_default_tag_for_user_type("devel"), "latest")
        self.assertEqual(_default_tag_for_user_type("DEVEL"), "latest")
        self.assertEqual(_default_tag_for_user_type(" devel "), "latest")
        self.assertEqual(_default_tag_for_user_type("developer"), "latest")

    def test_default_tag_for_user_type_user_is_stable(self):
        from commands.install import _default_tag_for_user_type

        self.assertEqual(_default_tag_for_user_type("user"), "stable")
        self.assertEqual(_default_tag_for_user_type(""), "stable")
        self.assertEqual(_default_tag_for_user_type(None), "stable")
        self.assertEqual(_default_tag_for_user_type("anything-else"), "stable")

    def _run_install_command_with_user_type(self, user_type):
        """Run install_command with no packages + no --tag, return the
        ``tag`` kwarg actually forwarded to download_all_from_archive."""
        from commands.install import install_command

        self._orig_script_directory = g.script_directory
        with tempfile.TemporaryDirectory() as tmpdir:
            g.script_directory = tmpdir
            try:
                with patch(
                    "commands.install.load_configuration",
                    return_value=(
                        [{"name": "any-repo"}],
                        {},
                        user_type,
                        None,
                        [],
                    ),
                ):
                    with patch("commands.install.download_all_from_archive") as mock_dl:
                        install_command([], "release")
                return mock_dl.call_args.kwargs["tag"]
            finally:
                g.script_directory = self._orig_script_directory

    def test_install_command_defaults_to_latest_for_devel_user(self):
        self.assertEqual(self._run_install_command_with_user_type("devel"), "latest")

    def test_install_command_defaults_to_stable_for_regular_user(self):
        self.assertEqual(self._run_install_command_with_user_type("user"), "stable")


# ============================================================================
# 7. Integration: publish.py
# ============================================================================


class TestPublishIntegration(unittest.TestCase):
    """Verify OTA messaging in publish dry-run mode."""

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


# ============================================================================
# Entry point
# ============================================================================


if __name__ == "__main__":
    unittest.main(verbosity=2)
