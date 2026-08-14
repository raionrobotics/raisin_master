"""SSH nonce signing for the user-authenticated OTA path.

Split out because it is the only place the core needs `cryptography`, a
native extension. A robot authenticates with its own credential and never
calls this, so it should not have to build or patch one.
"""

import base64
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa


def sign_nonce(nonce: str, key_path: Path) -> str:
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
        algo = b"rsa-sha2-256"
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
