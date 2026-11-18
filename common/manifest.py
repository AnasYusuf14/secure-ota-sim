"""
The release manifest: build, canonically serialize, parse and verify it.

Example manifest.json:

    {
      "name": "SmartSensor",
      "version": "1.1.0",
      "size": 65536,
      "sha256": "<hex>",
      "signature": "<base64>"
    }

The signature covers the *canonical serialization* of every field except
"signature" itself: keys sorted alphabetically, no whitespace, ASCII only.
Because name, version, size and hash are signed together, an attacker can not
change ANY of them (for example bump the version to 9.9.9) without making the
signature invalid. And because the hash of the firmware is signed, the firmware
itself is protected too.

Why "canonical"? JSON allows the same data to be written in many ways
({"a":1,"b":2} vs { "b": 2, "a": 1 }). The signer and the verifier must turn the
fields into *exactly the same bytes*, otherwise a valid signature would fail.
"""

from __future__ import annotations

import json
import re
from typing import Any

from common.crypto_utils import sha256_hex, sign, verify
from common.version import parse_version

# Field name -> required Python type.
REQUIRED_FIELDS: dict[str, type] = {
    "name": str,
    "version": str,
    "size": int,
    "sha256": str,
    "signature": str,
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(ValueError):
    """Raised when a manifest is malformed (missing fields, wrong types, ...)."""


def canonical_bytes(fields: dict[str, Any]) -> bytes:
    """Serialize `fields` deterministically: sorted keys, no whitespace, ASCII only."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def signed_part(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the manifest without the "signature" field (= what gets signed)."""
    return {key: value for key, value in manifest.items() if key != "signature"}


def build_manifest(name: str, version: str, firmware: bytes, private_key) -> dict[str, Any]:
    """Create and sign the manifest for a firmware image.

    Args:
        name:        product name, e.g. "SmartSensor".
        version:     firmware version, e.g. "1.1.0".
        firmware:    the complete firmware image bytes.
        private_key: the vendor's ECDSA P-256 private key.
    """
    parse_version(version)  # refuse to sign nonsense versions
    fields = {
        "name": name,
        "version": version,
        "size": len(firmware),
        "sha256": sha256_hex(firmware),
    }
    signature = sign(private_key, canonical_bytes(fields))
    return {**fields, "signature": signature}


def verify_manifest(manifest: dict[str, Any], public_key) -> bool:
    """Return True if the manifest's signature is valid for all its other fields."""
    signature = manifest.get("signature")
    if not isinstance(signature, str):
        return False
    return verify(public_key, canonical_bytes(signed_part(manifest)), signature)


def parse_manifest(raw: bytes) -> dict[str, Any]:
    """Decode manifest JSON received from the network and check its structure.

    This only checks the *shape* of the data (fields present, correct types).
    It does NOT prove authenticity: that is verify_manifest()'s job.

    Raises ManifestError if anything is wrong.
    """
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ManifestError("manifest must be a JSON object")

    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in manifest:
            raise ManifestError(f"manifest is missing field {field!r}")
        value = manifest[field]
        # bool is a subclass of int in Python, so exclude it explicitly.
        if not isinstance(value, expected_type) or isinstance(value, bool):
            raise ManifestError(f"manifest field {field!r} has wrong type")

    try:
        parse_version(manifest["version"])
    except ValueError as exc:
        raise ManifestError(str(exc)) from exc
    if not _SHA256_RE.match(manifest["sha256"]):
        raise ManifestError("manifest sha256 must be 64 lowercase hex characters")
    return manifest


def manifest_to_json(manifest: dict[str, Any]) -> str:
    """Pretty-print a manifest for writing to manifest.json (human readable).

    Pretty-printing is fine because the signature is over the canonical form,
    not over the bytes of this file.
    """
    return json.dumps(manifest, indent=2) + "\n"
