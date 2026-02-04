"""
OTA client for RAISIN.

Handles all interactions with the raisin-ota-server:
- SSH challenge-response authentication (no passwords)
- Package upload (used by publish command)
- Package download (used by install command)

Uses DEFAULT_OTA_ENDPOINT by default. Override with RAISIN_OTA_ENDPOINT env var.
All operations fail gracefully — OTA is supplementary, never blocks existing flows.
"""

import base64
import json
import os
import re
import hashlib
import shutil
import struct
import subprocess
import tempfile
import time
import zipfile

import requests
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from pathlib import Path
from typing import Optional

from commands import globals as g
from commands.utils import parse_version_specifier

# Module-level cached auth token (lives for the CLI session)
_cached_token = None

# Prevents repeated auth attempts after a failure within the same session
_auth_failed = False

# Module-level archive manifest cache to avoid repeated API calls
# Key: (archive_name, platform_str) → Value: (packages_list, archive_id, archive_version)
_archive_cache = {}

# Default archive name prefix (build_type is appended for debug)
DEFAULT_ARCHIVE_NAME = "raisin-robot"

# Default OTA server endpoint
DEFAULT_OTA_ENDPOINT = "https://raisin-ota-api.raionrobotics.com/api"

# Persistent token cache file name (stored in script_directory)
_TOKEN_CACHE_FILE = ".ota_token_cache.json"


# ============================================================================
# Configuration
# ============================================================================


def get_ota_endpoint() -> str:
    """Read RAISIN_OTA_ENDPOINT env var, or use default.

    Returns the OTA server endpoint. Uses DEFAULT_OTA_ENDPOINT if env var is not set.
    """
    return os.environ.get("RAISIN_OTA_ENDPOINT", DEFAULT_OTA_ENDPOINT).strip()


def get_ssh_key_path() -> Path:
    """Get SSH private key path for OTA authentication.

    Resolution order:
        1. RAISIN_SSH_KEY environment variable (if set)
        2. First existing key from: id_ed25519, id_ecdsa, id_rsa
        3. Default to ~/.ssh/id_ed25519 (even if not exists)
    """
    # 1. Check env var
    env_key = os.environ.get("RAISIN_SSH_KEY", "").strip()
    if env_key:
        return Path(env_key).expanduser()

    # 2. Try common key locations in order of preference
    ssh_dir = Path.home() / ".ssh"
    for key_name in ("id_ed25519", "id_ecdsa", "id_rsa"):
        key_path = ssh_dir / key_name
        if key_path.exists():
            return key_path

    # 3. Default fallback
    return ssh_dir / "id_ed25519"


def get_archive_name(build_type: str) -> str:
    """Get archive name based on build type.

    Convention:
        - release → 'raisin-robot'
        - debug → 'raisin-robot-debug'
    """
    base = os.environ.get("RAISIN_ARCHIVE_NAME", DEFAULT_ARCHIVE_NAME)
    if build_type.lower() == "debug":
        return f"{base}-debug"
    return base


# ============================================================================
# Token Persistence
# ============================================================================


def _get_token_cache_path() -> Path:
    """Path to the persistent token cache file."""
    return Path(g.script_directory) / _TOKEN_CACHE_FILE


def _is_jwt_expired(token: str) -> bool:
    """Check if a JWT token is expired by decoding its payload.

    Decodes the JWT payload (no signature verification — just reading
    the ``exp`` claim) and returns True if the token expires within
    30 seconds.
    """
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.b64decode(padded))
        exp = payload.get("exp")
        if exp is None:
            return False
        return time.time() > (exp - 30)
    except Exception:
        return True


def _load_cached_token() -> Optional[str]:
    """Load token from persistent cache file if it's still valid.

    Uses the ``expiresAt`` timestamp saved alongside the token rather
    than re-parsing the JWT, so this works for opaque tokens too.
    """
    cache_path = _get_token_cache_path()
    try:
        if not cache_path.is_file():
            return None
        with open(cache_path, "r") as f:
            data = json.loads(f.read())
        token = data.get("accessToken")
        endpoint = data.get("endpoint")
        expires_at = data.get("expiresAt", 0)
        if endpoint != get_ota_endpoint():
            return None
        if not token:
            return None
        # 30-second buffer to avoid using a token that's about to expire
        if time.time() > (expires_at - 30):
            return None
        return token
    except Exception:
        return None


def _extract_jwt_expiry(token: str) -> float:
    """Try to read the ``exp`` claim from a JWT. Returns epoch seconds.

    Falls back to 1 hour from now if the token can't be parsed.
    """
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.b64decode(padded))
        exp = payload.get("exp")
        if exp is not None:
            return float(exp)
    except Exception:
        pass
    return time.time() + 3600


def _save_token(token: str):
    """Save token and its expiry to persistent cache file."""
    try:
        cache_path = _get_token_cache_path()
        data = {
            "accessToken": token,
            "endpoint": get_ota_endpoint(),
            "expiresAt": _extract_jwt_expiry(token),
        }
        with open(cache_path, "w") as f:
            f.write(json.dumps(data))
    except Exception:
        pass


def _clear_cached_token():
    """Clear both in-memory and persistent token caches, and reset failure flag."""
    global _cached_token, _auth_failed
    _cached_token = None
    _auth_failed = False
    try:
        cache_path = _get_token_cache_path()
        if cache_path.is_file():
            cache_path.unlink()
    except Exception:
        pass


# ============================================================================
# SSH Authentication
# ============================================================================


def _get_ssh_fingerprint(key_path: Path) -> str:
    """Run ssh-keygen -lf <key.pub> and return hex-encoded SHA256 fingerprint.

    The OTA server expects the fingerprint as a hex string without the
    ``SHA256:`` prefix that ssh-keygen normally prints.
    """
    pub_key = key_path.with_suffix(".pub") if key_path.suffix != ".pub" else key_path
    result = subprocess.run(
        ["ssh-keygen", "-lf", str(pub_key)],
        capture_output=True,
        text=True,
        check=True,
    )
    # Output format: "256 SHA256:<base64> user@host (ED25519)"
    parts = result.stdout.strip().split()
    sha256_b64 = parts[1].split(":", 1)[1]  # strip "SHA256:" prefix
    # Convert base64 → raw bytes → hex
    padded = sha256_b64 + "=" * (-len(sha256_b64) % 4)
    return base64.b64decode(padded).hex()


def _sign_nonce(nonce: str, key_path: Path) -> str:
    """Sign nonce with SSH private key (supports ed25519, RSA, ECDSA).

    Loads the SSH private key via the ``cryptography`` library and signs
    the nonce bytes directly. Returns the signature as base64-encoded SSH
    wire format (length-prefixed algorithm name + length-prefixed raw signature).

    Supported key types:
        - Ed25519 (ssh-ed25519)
        - RSA (ssh-rsa) - uses SHA-256 with PKCS1v15 padding
        - ECDSA (ecdsa-sha2-nistp256, nistp384, nistp521)
    """
    with open(key_path, "rb") as f:
        private_key = serialization.load_ssh_private_key(f.read(), password=None)

    data = bytes.fromhex(nonce)

    # Sign based on key type
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        algo = b"ssh-ed25519"
        raw_sig = private_key.sign(data)

    elif isinstance(private_key, rsa.RSAPrivateKey):
        algo = b"ssh-rsa"
        raw_sig = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        # Determine curve and algorithm name
        curve_name = private_key.curve.name
        if curve_name == "secp256r1":
            algo = b"ecdsa-sha2-nistp256"
            hash_algo = hashes.SHA256()
        elif curve_name == "secp384r1":
            algo = b"ecdsa-sha2-nistp384"
            hash_algo = hashes.SHA384()
        elif curve_name == "secp521r1":
            algo = b"ecdsa-sha2-nistp521"
            hash_algo = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported ECDSA curve: {curve_name}")
        raw_sig = private_key.sign(data, ec.ECDSA(hash_algo))

    else:
        raise ValueError(f"Unsupported SSH key type: {type(private_key).__name__}")

    # Build SSH wire format: length-prefixed algo + length-prefixed signature
    sig_wire = (
        struct.pack(">I", len(algo)) + algo + struct.pack(">I", len(raw_sig)) + raw_sig
    )
    return base64.b64encode(sig_wire).decode()


def authenticate() -> Optional[str]:
    """Return a valid JWT access token, authenticating only if necessary.

    Token resolution order:
    1. In-memory cache (fastest, same CLI session)
    2. Persistent file cache (~/.ota_token_cache.json)
    3. SSH challenge-response against the OTA server

    Tokens are checked for JWT expiry before reuse.
    Returns access token string, or None on failure.
    """
    global _cached_token, _auth_failed

    # 1. In-memory cache (same CLI session — always trust it; if expired
    #    the server returns 401 and the retry handler clears the cache)
    if _cached_token:
        return _cached_token

    # Don't retry after a failure in the same session
    if _auth_failed:
        return None

    # 2. Persistent file cache
    file_token = _load_cached_token()
    if file_token:
        _cached_token = file_token
        return _cached_token

    # 3. SSH challenge-response
    endpoint = get_ota_endpoint()
    key_path = get_ssh_key_path()

    if not key_path.exists():
        print(f"⚠️ SSH key not found at {key_path}. Skipping OTA.")
        _auth_failed = True
        return None

    try:
        fingerprint = _get_ssh_fingerprint(key_path)
        base = endpoint.rstrip("/")

        # Step 1: Request challenge
        resp = requests.post(
            f"{base}/auth/ssh/challenge",
            json={"fingerprint": fingerprint},
            timeout=10,
        )
        resp.raise_for_status()
        nonce = _unwrap_response(resp.json())["nonce"]

        # Step 2: Sign nonce locally
        signature = _sign_nonce(nonce, key_path)

        # Step 3: Verify signature with server
        resp = requests.post(
            f"{base}/auth/ssh/verify",
            json={
                "fingerprint": fingerprint,
                "nonce": nonce,
                "signature": signature,
            },
            timeout=10,
        )
        resp.raise_for_status()
        _cached_token = _unwrap_response(resp.json())["accessToken"]
        _save_token(_cached_token)
        return _cached_token

    except FileNotFoundError:
        print("⚠️ ssh-keygen not found. Skipping OTA authentication.")
        _auth_failed = True
        return None
    except subprocess.CalledProcessError as e:
        print(f"⚠️ SSH key operation failed: {e.stderr.strip()}. Skipping OTA.")
        _auth_failed = True
        return None
    except requests.RequestException as e:
        print(f"⚠️ OTA server unreachable: {e}. Skipping OTA.")
        _auth_failed = True
        return None
    except (KeyError, ValueError) as e:
        print(f"⚠️ Unexpected OTA auth response: {e}. Skipping OTA.")
        _auth_failed = True
        return None


def _unwrap_response(resp_json):
    """Unwrap the OTA server's standard response envelope.

    The server wraps all JSON responses in ``{"success": bool, "data": ...}``.
    Returns the inner ``data`` payload, or the original value if not wrapped.
    """
    if isinstance(resp_json, dict) and "data" in resp_json:
        return resp_json["data"]
    return resp_json


def _auth_headers(token: str) -> dict:
    """Build Authorization header dict for authenticated requests."""
    return {"Authorization": f"Bearer {token}"}


def _get_auth_context() -> Optional[tuple]:
    """Get authenticated context for OTA API calls.

    Returns:
        Tuple of (base_url, headers) on success, None on auth failure.
        base_url is the endpoint with trailing slash stripped.
    """
    token = authenticate()
    if not token:
        return None
    base = get_ota_endpoint().rstrip("/")
    headers = _auth_headers(token)
    return (base, headers)


# ============================================================================
# Upload Functions (used by publish command)
# ============================================================================


def _compute_sha256(file_path: Path) -> str:
    """SHA256 hex digest of file, read in 8KB chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def upload_package(
    archive_path: Path,
    package_name: str,
    version: str,
    build_type: str,
    _retry: bool = True,
) -> bool:
    """Upload a package archive to the OTA server.

    Steps:
    1. Authenticate (SSH challenge-response)
    2. Compute SHA256 of archive for deduplication
    3. Check if blob already exists on server
    4. Upload blob if needed
    5. Ensure package record exists
    6. Create manifest entry
    7. Create version tag

    Returns True on success, False on failure. Never raises.
    """
    ctx = _get_auth_context()
    if not ctx:
        return False
    base, headers = ctx

    try:
        # 1. Compute SHA256
        sha256 = _compute_sha256(archive_path)
        platform_str = f"{g.os_type}-{g.os_version}-{g.architecture}"

        # 2. Check if blob already exists (deduplication)
        resp = requests.get(
            f"{base}/blobs/{sha256}/exists", headers=headers, timeout=10
        )
        resp.raise_for_status()
        blob_exists = _unwrap_response(resp.json()).get("exists", False)

        # 3. Upload blob if needed
        if not blob_exists:
            with open(archive_path, "rb") as f:
                resp = requests.post(
                    f"{base}/blobs",
                    headers=headers,
                    files={"file": (archive_path.name, f, "application/zip")},
                    data={"sha256": sha256},
                    timeout=120,
                )
                resp.raise_for_status()

        # 4. Ensure package record exists
        resp = requests.get(
            f"{base}/packages",
            headers=headers,
            params={"name": package_name},
            timeout=10,
        )
        resp.raise_for_status()
        packages = _unwrap_response(resp.json())

        if packages and len(packages) > 0:
            package_id = packages[0]["id"]
        else:
            resp = requests.post(
                f"{base}/packages",
                headers=headers,
                json={"name": package_name},
                timeout=10,
            )
            resp.raise_for_status()
            package_id = _unwrap_response(resp.json())["id"]

        # 5. Create manifest
        resp = requests.post(
            f"{base}/packages/{package_id}/manifests",
            headers=headers,
            json={
                "version": version,
                "platform": platform_str,
                "buildType": build_type,
                "blobHash": sha256,
            },
            timeout=10,
        )
        resp.raise_for_status()

        # 6. Create version tag
        resp = requests.post(
            f"{base}/packages/{package_id}/tags",
            headers=headers,
            json={
                "tag": f"v{version.lstrip('v')}",
                "version": version,
                "platform": platform_str,
                "buildType": build_type,
            },
            timeout=10,
        )
        resp.raise_for_status()

        return True

    except requests.HTTPError as e:
        if _retry and e.response is not None and e.response.status_code == 401:
            # Token may have expired — clear caches and retry auth once
            _clear_cached_token()
            token = authenticate()
            if token:
                print("🔄 Re-authenticated with OTA server, retrying upload...")
                return upload_package(
                    archive_path, package_name, version, build_type, _retry=False
                )
        print(f"⚠️ OTA upload failed: {e}")
        return False
    except requests.RequestException as e:
        print(f"⚠️ OTA upload failed: {e}")
        return False


# ============================================================================
# Download Functions (used by install command)
# ============================================================================


def _fetch_archive_manifest(
    archive_name: str,
    platform_str: str,
    archive_version: Optional[str] = None,
):
    """Fetch available archive manifest from OTA server.

    Args:
        archive_name: Name of the archive (e.g., 'raisin-robot', 'raisin-robot-debug')
        platform_str: Platform string (e.g., 'ubuntu-24.04-x86_64')
        archive_version: Optional specific version (e.g., 'v2024.01'). If None,
            fetches the latest available archive.

    Returns:
        Tuple of (packages_list, archive_id, archive_version) on success, None on failure.
        Uses a module-level cache to avoid repeated calls during a single install run.
    """
    cache_key = (archive_name, platform_str, archive_version)
    if cache_key in _archive_cache:
        return _archive_cache[cache_key]

    ctx = _get_auth_context()
    if not ctx:
        return None
    base, headers = ctx

    try:
        params = {
            "name": archive_name,
            "platform": platform_str,
            "status": "available",
        }
        if archive_version:
            params["search"] = archive_version

        resp = requests.get(
            f"{base}/archives",
            headers=headers,
            params=params,
            timeout=10,
        )
        resp.raise_for_status()
        result_data = _unwrap_response(resp.json())
        # Response is paginated: {archives: [...], total, page, ...}
        archives = (
            result_data.get("archives", [])
            if isinstance(result_data, dict)
            else result_data
        )
        if not archives:
            return None

        # Find matching archive (exact version match if specified)
        archive = None
        if archive_version:
            for a in archives:
                if a.get("version") == archive_version:
                    archive = a
                    break
            if not archive:
                # Try without 'v' prefix
                v_stripped = archive_version.lstrip("v")
                for a in archives:
                    if a.get("version", "").lstrip("v") == v_stripped:
                        archive = a
                        break
        if not archive:
            # Use the most recent archive
            archive = archives[0]

        result = (
            archive.get("packages", []),
            archive.get("id"),
            archive.get("version"),
        )
        _archive_cache[cache_key] = result
        return result

    except requests.RequestException as e:
        print(f"⚠️ OTA server unreachable: {e}")
        return None


def _stream_download(url: str, download_path: Path, error_context: str = "") -> bool:
    """Stream download a file from a URL.

    Args:
        url: Full URL to download from.
        download_path: Local path to save the file.
        error_context: Context string for error messages (e.g., package name).

    Returns:
        True on success, False on failure.
    """
    ctx = _get_auth_context()
    if not ctx:
        return False
    _, headers = ctx

    try:
        download_path.parent.mkdir(parents=True, exist_ok=True)
        with requests.get(url, headers=headers, stream=True, timeout=60) as resp:
            resp.raise_for_status()
            with open(download_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
        return True
    except requests.RequestException as e:
        context = f" for '{error_context}'" if error_context else ""
        print(f"⚠️ OTA download failed{context}: {e}")
        return False


def _download_package_blob(
    archive_id: str,
    package_id: str,
    package_name: str,
    download_path: Path,
) -> bool:
    """Download a single package blob from an archive."""
    base = get_ota_endpoint().rstrip("/")
    url = f"{base}/archives/{archive_id}/packages/{package_id}/download"
    return _stream_download(url, download_path, package_name)


def _extract_and_read_deps(
    download_file: Path,
    install_dir: Path,
    package_name: str,
    version: str,
) -> Optional[dict]:
    """Extract downloaded package and read dependencies.

    Returns dict with 'version' and 'dependencies' on success, None on failure.
    """
    if install_dir.exists():
        shutil.rmtree(install_dir)
    install_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(download_file, "r") as zip_ref:
            zip_ref.extractall(install_dir)
        download_file.unlink()
    except (zipfile.BadZipFile, OSError) as e:
        print(f"⚠️ Failed to extract OTA package '{package_name}': {e}")
        if download_file.exists():
            download_file.unlink()
        return None

    print(f"✅ Successfully installed '{package_name}=={version}' from OTA server.")

    # Read dependencies from release.yaml
    dependencies = []
    release_yaml = install_dir / "release.yaml"
    if release_yaml.is_file():
        with open(release_yaml, "r") as f:
            release_info = yaml.safe_load(f) or {}
            dependencies = release_info.get("dependencies", [])

    return {"version": version, "dependencies": dependencies}


def download_package(
    package_name: str,
    spec_str: str,
    build_type: str,
    install_base_path: Path,
    archive_version: Optional[str] = None,
) -> Optional[dict]:
    """Download a single package from the OTA server's archive.

    Looks up the package in the archive manifest for the current platform,
    checks version compatibility, downloads and extracts to install_base_path.

    Args:
        package_name: Name of the package to download.
        spec_str: Version specifier string (e.g. ">=1.0", "==1.1.0", "" for any).
        build_type: "debug" or "release".
        install_base_path: Path to release/install/ directory.
        archive_version: Optional specific archive version (e.g., 'v2024.01').
            If None, uses the latest available archive.

    Returns:
        dict with 'version' and 'dependencies' on success, None on failure.
    """
    from packaging.version import parse as parse_version, InvalidVersion

    platform_str = f"{g.os_type}-{g.os_version}-{g.architecture}"
    archive_name = get_archive_name(build_type)

    manifest = _fetch_archive_manifest(archive_name, platform_str, archive_version)
    if manifest is None:
        return None

    packages, archive_id, actual_version = manifest
    if not archive_id:
        return None

    # Parse version specifier
    spec = parse_version_specifier(spec_str)
    if spec is None:
        return None

    # Find best matching package in archive
    # Manifest entries have tagName (e.g. "v1.0.0") instead of version
    best_pkg = None
    best_version = None
    for pkg in packages:
        name = pkg.get("packageName") or pkg.get("name", "")
        if name != package_name:
            continue
        tag = pkg.get("tagName") or pkg.get("version", "")
        pkg_version_str = tag.lstrip("v") if tag else ""
        try:
            pkg_version = parse_version(pkg_version_str)
            if spec.contains(pkg_version):
                if best_version is None or pkg_version > best_version:
                    best_version = pkg_version
                    best_pkg = pkg
        except InvalidVersion:
            continue

    if not best_pkg:
        return None

    # Download the package
    pkg_id = best_pkg.get("packageId") or best_pkg.get("id")
    if not pkg_id:
        return None
    tag = best_pkg.get("tagName") or best_pkg.get("version", "")
    version = tag.lstrip("v") if tag else "0.0.0"

    install_dir = (
        install_base_path
        / package_name
        / g.os_type
        / g.os_version
        / g.architecture
        / build_type
    )

    download_file = (
        Path(g.script_directory) / "install" / f"{package_name}-ota-{version}.zip"
    )

    print(f"⬇️  Downloading '{package_name}' v{version} from OTA server...")
    if not _download_package_blob(archive_id, pkg_id, package_name, download_file):
        return None

    return _extract_and_read_deps(download_file, install_dir, package_name, version)


def download_all_from_archive(
    build_type: str,
    install_base_path: Path,
    archive_version: Optional[str] = None,
    package_filter: Optional[list] = None,
) -> dict:
    """Download all packages from an archive.

    Args:
        build_type: "debug" or "release".
        install_base_path: Path to release/install/ directory.
        archive_version: Optional specific archive version (e.g., 'v2024.01').
            If None, uses the latest available archive.
        package_filter: Optional list of package names to download. If None,
            downloads all packages in the archive.

    Returns:
        dict mapping package_name to {'version': str, 'dependencies': list}
        for successfully downloaded packages. Empty dict on complete failure.
    """
    platform_str = f"{g.os_type}-{g.os_version}-{g.architecture}"
    archive_name = get_archive_name(build_type)

    manifest = _fetch_archive_manifest(archive_name, platform_str, archive_version)
    if manifest is None:
        print(f"⚠️ No archive found for '{archive_name}' on {platform_str}")
        return {}

    packages, archive_id, actual_version = manifest
    if not archive_id:
        return {}

    print(f"📦 Using archive: {archive_name} v{actual_version or 'latest'}")

    results = {}
    for pkg in packages:
        name = pkg.get("packageName") or pkg.get("name", "")
        if not name:
            continue
        if package_filter and name not in package_filter:
            continue

        pkg_id = pkg.get("packageId") or pkg.get("id")
        if not pkg_id:
            continue

        tag = pkg.get("tagName") or pkg.get("version", "")
        version = tag.lstrip("v") if tag else "0.0.0"

        install_dir = (
            install_base_path
            / name
            / g.os_type
            / g.os_version
            / g.architecture
            / build_type
        )

        download_file = (
            Path(g.script_directory) / "install" / f"{name}-ota-{version}.zip"
        )

        print(f"⬇️  Downloading '{name}' v{version} from OTA server...")
        if not _download_package_blob(archive_id, pkg_id, name, download_file):
            continue

        result = _extract_and_read_deps(download_file, install_dir, name, version)
        if result:
            results[name] = result

    return results


def _fetch_package_id_by_name(package_name: str) -> Optional[str]:
    """Fetch package ID by name from the OTA server.

    Returns package UUID on success, None on failure.
    """
    ctx = _get_auth_context()
    if not ctx:
        return None
    base, headers = ctx

    try:
        resp = requests.get(
            f"{base}/packages",
            headers=headers,
            params={"name": package_name},
            timeout=10,
        )
        resp.raise_for_status()
        result = _unwrap_response(resp.json())
        packages = (
            result.get("packages", result) if isinstance(result, dict) else result
        )
        if packages and len(packages) > 0:
            return packages[0].get("id")
        return None
    except requests.RequestException:
        return None


def _download_blob_by_hash(blob_hash: str, download_path: Path) -> bool:
    """Download a blob directly by its hash."""
    base = get_ota_endpoint().rstrip("/")
    url = f"{base}/blobs/{blob_hash}/download"
    return _stream_download(url, download_path, f"blob {blob_hash[:8]}")


def download_package_at_timestamp(
    package_name: str,
    timestamp: str,
    build_type: str,
    install_base_path: Path,
) -> Optional[dict]:
    """Download a package at a specific timestamp (time-travel).

    Uses the /packages/:id/manifests/at API to find the manifest that was
    current at the given timestamp, then downloads the blob directly.

    Args:
        package_name: Name of the package to download.
        timestamp: ISO 8601 timestamp (e.g., '2024-01-15' or '2024-01-15T10:00:00Z').
        build_type: "debug" or "release".
        install_base_path: Path to release/install/ directory.

    Returns:
        dict with 'version' and 'dependencies' on success, None on failure.
    """
    # Get package ID first (this handles its own auth)
    package_id = _fetch_package_id_by_name(package_name)
    if not package_id:
        print(f"⚠️ Package '{package_name}' not found on OTA server.")
        return None

    ctx = _get_auth_context()
    if not ctx:
        return None
    base, headers = ctx
    platform_str = f"{g.os_type}-{g.os_version}-{g.architecture}"

    try:
        # Fetch manifest at timestamp
        resp = requests.get(
            f"{base}/packages/{package_id}/manifests/at",
            headers=headers,
            params={
                "timestamp": timestamp,
                "platform": platform_str,
                "buildType": build_type,
            },
            timeout=10,
        )
        resp.raise_for_status()
        manifest = _unwrap_response(resp.json())

        if not manifest:
            print(f"⚠️ No manifest found for '{package_name}' at {timestamp}")
            return None

        blob_hash = manifest.get("blobHash")
        version = manifest.get("version", "0.0.0")

        if not blob_hash:
            print(f"⚠️ Manifest for '{package_name}' has no blob hash")
            return None

        install_dir = (
            install_base_path
            / package_name
            / g.os_type
            / g.os_version
            / g.architecture
            / build_type
        )

        download_file = (
            Path(g.script_directory) / "install" / f"{package_name}-ota-{version}.zip"
        )

        print(f"⬇️  Downloading '{package_name}' v{version} (at {timestamp})...")
        if not _download_blob_by_hash(blob_hash, download_file):
            return None

        return _extract_and_read_deps(download_file, install_dir, package_name, version)

    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            print(f"⚠️ No manifest found for '{package_name}' at {timestamp}")
        else:
            print(f"⚠️ OTA error: {e}")
        return None
    except requests.RequestException as e:
        print(f"⚠️ OTA server unreachable: {e}")
        return None


def download_all_at_timestamp(
    timestamp: str,
    build_type: str,
    install_base_path: Path,
    package_filter: Optional[list] = None,
) -> dict:
    """Download all packages at a specific timestamp.

    Fetches the list of all packages, then downloads each one's manifest
    at the given timestamp.

    Args:
        timestamp: ISO 8601 timestamp (e.g., '2024-01-15').
        build_type: "debug" or "release".
        install_base_path: Path to release/install/ directory.
        package_filter: Optional list of package names to download.

    Returns:
        dict mapping package_name to {'version': str, 'dependencies': list}
        for successfully downloaded packages.
    """
    ctx = _get_auth_context()
    if not ctx:
        return {}
    base, headers = ctx

    try:
        # Fetch all packages
        resp = requests.get(
            f"{base}/packages",
            headers=headers,
            params={"limit": 1000},
            timeout=10,
        )
        resp.raise_for_status()
        result = _unwrap_response(resp.json())
        packages = (
            result.get("packages", result) if isinstance(result, dict) else result
        )

        if not packages:
            print("⚠️ No packages found on OTA server.")
            return {}

        print(f"📦 Downloading packages at timestamp: {timestamp}")

        results = {}
        for pkg in packages:
            name = pkg.get("name", "")
            if not name:
                continue
            if package_filter and name not in package_filter:
                continue

            result = download_package_at_timestamp(
                name, timestamp, build_type, install_base_path
            )
            if result:
                results[name] = result

        return results

    except requests.RequestException as e:
        print(f"⚠️ OTA server unreachable: {e}")
        return {}
