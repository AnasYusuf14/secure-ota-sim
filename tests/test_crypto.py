"""Unit tests for common/crypto_utils.py (hashing, ECDSA sign/verify, key files)."""

import base64

import pytest

from common.crypto_utils import (
    generate_private_key,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    sha256_hex,
    sign,
    verify,
)


def test_sha256_known_vector():
    """SHA-256 of "abc" matches the official test vector."""
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sign_and_verify_roundtrip():
    """A fresh signature verifies with the matching public key."""
    key = generate_private_key()
    signature = sign(key, b"hello firmware")
    assert verify(key.public_key(), b"hello firmware", signature)


def test_verify_fails_for_modified_data():
    """Changing one byte of the data breaks the signature."""
    key = generate_private_key()
    signature = sign(key, b"hello firmware")
    assert not verify(key.public_key(), b"hello firmwarE", signature)


def test_verify_fails_for_wrong_key():
    """A signature from another key (the attacker's) is rejected."""
    vendor, attacker = generate_private_key(), generate_private_key()
    signature = sign(attacker, b"evil")
    assert not verify(vendor.public_key(), b"evil", signature)


@pytest.mark.parametrize("bad_sig", ["", "not base64!!", base64.b64encode(b"\x00" * 70).decode()])
def test_verify_fails_for_garbage_signature(bad_sig):
    """Malformed signatures return False instead of raising."""
    key = generate_private_key()
    assert not verify(key.public_key(), b"data", bad_sig)


def test_key_files_roundtrip(tmp_path):
    """Keys survive being written to and read from PEM files."""
    key = generate_private_key()
    save_private_key(key, tmp_path / "priv.pem")
    save_public_key(key.public_key(), tmp_path / "pub.pem")
    loaded_priv = load_private_key(tmp_path / "priv.pem")
    loaded_pub = load_public_key(tmp_path / "pub.pem")
    assert verify(loaded_pub, b"x", sign(loaded_priv, b"x"))
