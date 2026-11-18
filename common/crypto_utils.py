"""
Cryptography helpers: SHA-256 hashing and ECDSA P-256 signatures.

ECDSA on the NIST P-256 curve with SHA-256 is what ESP32 "Secure Boot V2" style
schemes and most embedded update systems use: short keys (32 bytes), small
signatures (~72 bytes) and fast verification on a microcontroller.

Signatures are stored as base64 text so they fit in a JSON manifest.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of `data` as a 64-character lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    """Create a brand-new random ECDSA P-256 private key."""
    return ec.generate_private_key(ec.SECP256R1())


def save_private_key(private_key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    """Write a private key to `path` as PEM (PKCS#8).

    The file is not password protected because this is a teaching simulation.
    On a real signing machine the key would live in an HSM or be encrypted.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)  # owner read/write only (ignored on Windows)
    except OSError:
        pass


def save_public_key(public_key: ec.EllipticCurvePublicKey, path: Path) -> None:
    """Write a public key to `path` as PEM (SubjectPublicKeyInfo)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def _require_p256(key: object) -> None:
    """Raise ValueError unless `key` is an elliptic-curve key on the P-256 curve."""
    if not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        raise ValueError("key is not an elliptic-curve key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(f"key uses curve {key.curve.name}, expected secp256r1 (P-256)")


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    """Load a PEM private key from `path` and check that it is P-256."""
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    _require_p256(key)
    return key  # type: ignore[return-value]


def load_public_key(path: Path) -> ec.EllipticCurvePublicKey:
    """Load a PEM public key from `path` and check that it is P-256."""
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    _require_p256(key)
    return key  # type: ignore[return-value]


def sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> str:
    """Sign `data` with ECDSA P-256 / SHA-256 and return the signature as base64 text."""
    der_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(der_signature).decode("ascii")


def verify(public_key: ec.EllipticCurvePublicKey, data: bytes, signature_b64: str) -> bool:
    """Check a base64 ECDSA signature over `data`.

    Returns True only if the signature is valid for this exact data and key.
    Any problem (bad base64, wrong key, modified data) simply returns False,
    so callers never have to deal with exceptions here.
    """
    try:
        der_signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return False
    try:
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
