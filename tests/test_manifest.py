"""Unit tests for common/manifest.py (canonical serialization, signing, parsing)."""

import json

import pytest

from common.crypto_utils import generate_private_key, sha256_hex
from common.manifest import (
    ManifestError,
    build_manifest,
    canonical_bytes,
    manifest_to_json,
    parse_manifest,
    signed_part,
    verify_manifest,
)

FIRMWARE = b"firmware-bytes" * 100


@pytest.fixture(scope="module")
def key():
    """One vendor key for this module."""
    return generate_private_key()


def test_canonical_sorted_and_compact():
    """Keys are sorted and there is no whitespace."""
    assert canonical_bytes({"version": "1.0.0", "name": "X", "size": 5}) == b'{"name":"X","size":5,"version":"1.0.0"}'


def test_canonical_independent_of_key_order():
    """The same fields in a different order give identical bytes."""
    a = {"name": "X", "version": "1.0.0", "size": 1, "sha256": "ab"}
    b = {"sha256": "ab", "size": 1, "version": "1.0.0", "name": "X"}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_canonical_is_ascii():
    """Non-ASCII characters are escaped, so encoding can never differ."""
    assert canonical_bytes({"name": "Sensör"}) == b'{"name":"Sens\\u00f6r"}'


def test_build_manifest_fields(key):
    """Built manifest has all fields with correct values."""
    m = build_manifest("SmartSensor", "1.1.0", FIRMWARE, key)
    assert m["name"] == "SmartSensor"
    assert m["version"] == "1.1.0"
    assert m["size"] == len(FIRMWARE)
    assert m["sha256"] == sha256_hex(FIRMWARE)
    assert "signature" not in signed_part(m)


def test_verify_valid_manifest(key):
    """A freshly signed manifest verifies, also after a JSON round-trip with pretty-printing."""
    m = build_manifest("SmartSensor", "1.1.0", FIRMWARE, key)
    reparsed = parse_manifest(manifest_to_json(m).encode())
    assert verify_manifest(reparsed, key.public_key())


@pytest.mark.parametrize(
    "field, value",
    [("version", "9.9.9"), ("name", "OtherProduct"), ("size", 1), ("sha256", "0" * 64)],
)
def test_editing_any_field_breaks_signature(key, field, value):
    """Every signed field is protected - e.g. version 1.1.0 -> 9.9.9."""
    m = build_manifest("SmartSensor", "1.1.0", FIRMWARE, key)
    m[field] = value
    assert not verify_manifest(m, key.public_key())


def test_adding_a_field_breaks_signature(key):
    """Extra injected fields are also covered by the signature."""
    m = build_manifest("SmartSensor", "1.1.0", FIRMWARE, key)
    m["url"] = "http://evil.example"
    assert not verify_manifest(m, key.public_key())


def test_wrong_key_fails(key):
    """Manifest signed by another key does not verify."""
    m = build_manifest("SmartSensor", "1.1.0", FIRMWARE, generate_private_key())
    assert not verify_manifest(m, key.public_key())


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[1, 2, 3]",
        json.dumps({"name": "X", "version": "1.0.0", "size": 1, "sha256": "0" * 64}).encode(),  # no signature
        json.dumps({"name": "X", "version": "1.0", "size": 1, "sha256": "0" * 64, "signature": "x"}).encode(),
        json.dumps({"name": "X", "version": "1.0.0", "size": "1", "sha256": "0" * 64, "signature": "x"}).encode(),
        json.dumps({"name": "X", "version": "1.0.0", "size": True, "sha256": "0" * 64, "signature": "x"}).encode(),
        json.dumps({"name": "X", "version": "1.0.0", "size": 1, "sha256": "xyz", "signature": "x"}).encode(),
    ],
)
def test_parse_rejects_malformed(raw):
    """Structurally invalid manifests raise ManifestError."""
    with pytest.raises(ManifestError):
        parse_manifest(raw)
