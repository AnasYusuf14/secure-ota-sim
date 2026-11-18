"""
Focused tests of device-side rules that the scenarios rely on:
flash slot safety, min_allowed_version, bootloader fallbacks, server endpoints.
"""

import json
import urllib.error
import urllib.request

import pytest

from common.firmware_image import build_image
from demo.harness import attempt_update
from device.bootloader import boot
from device.flash import EMPTY, INVALID, SLOT_SIZE, VALID, DeviceBricked, FlashError
from device.ota_client import REJECTED, ota_begin
from server.ota_server import running_server, tamper_bytes


def test_factory_state(ctx):
    """After factory reset: v1.0.0 VALID in slot a, slot b empty, key embedded."""
    status = ctx.device.status()
    assert status["active_slot"] == "a"
    assert status["slots"]["a"]["state"] == VALID
    assert status["slots"]["b"]["state"] == EMPTY
    assert status["min_allowed_version"] == "1.0.0"
    assert ctx.device.trusted_key_path.exists()


def test_ota_begin_refuses_active_slot(ctx):
    """The running firmware's slot can never be opened for writing."""
    with pytest.raises(RuntimeError):
        ota_begin(ctx.device.flash, "a")


def test_flash_slot_overflow(ctx):
    """Writing more than a slot can hold raises FlashError."""
    with pytest.raises(FlashError):
        ctx.device.flash.append_to_slot("b", b"\x00" * (SLOT_SIZE + 1))


def test_min_allowed_version_blocks_even_if_newer_than_running(ctx):
    """Anti-rollback counter: a version newer than running but below the counter is refused."""
    otadata = ctx.device.flash.load_otadata()
    otadata["min_allowed_version"] = "1.2.0"     # e.g. counter burned by a previous update
    ctx.device.flash.save_otadata(otadata)
    attempt = attempt_update(ctx, ctx.release("1.1.0"))
    assert attempt.update.status == REJECTED
    assert "min_allowed_version" in attempt.update.reason
    assert "downgrade/replay" in attempt.update.reason


def test_same_version_is_replay(ctx):
    """Re-installing the running version is refused as a replay."""
    attempt = attempt_update(ctx, ctx.release("1.0.0"))
    assert attempt.update.status == REJECTED
    assert "downgrade/replay" in attempt.update.reason


def test_corrupted_active_slot_falls_back(ctx):
    """If the active image no longer matches its hash, boot the other VALID slot."""
    attempt_update(ctx, ctx.release("1.1.0"))          # now on slot b, slot a = 1.0.0 VALID
    flash = ctx.device.flash
    data = bytearray(flash.read_slot("b"))
    data[-1] ^= 0xFF                                    # flip one bit in the running image
    flash.write_slot("b", bytes(data))
    result = boot(flash)
    assert result.version == "1.0.0"
    assert result.rolled_back


def test_no_valid_slot_is_bricked(ctx):
    """With no bootable image at all, the bootloader reports DeviceBricked."""
    flash = ctx.device.flash
    otadata = flash.load_otadata()
    otadata["slots"]["a"]["state"] = INVALID
    flash.save_otadata(otadata)
    with pytest.raises(DeviceBricked):
        boot(flash)


def test_oversized_manifest_rejected(ctx, tmp_path):
    """A (validly signed) manifest claiming > 1 MB is rejected before any flash write."""
    from common.crypto_utils import load_private_key
    from common.manifest import build_manifest, manifest_to_json

    key = load_private_key(ctx.private_key_path)
    big = build_image("SmartSensor", "5.0.0", size=SLOT_SIZE + 4096)
    release = tmp_path / "big"
    release.mkdir()
    (release / "firmware.bin").write_bytes(big)
    (release / "manifest.json").write_text(manifest_to_json(build_manifest("SmartSensor", "5.0.0", big, key)))
    attempt = attempt_update(ctx, release)
    assert attempt.update.status == REJECTED
    assert "does not fit" in attempt.update.reason
    assert ctx.device.inactive_slot_size == 0


def test_server_endpoints(ctx):
    """Server serves exactly two files and 404s everything else (e.g. the private key)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with running_server(ctx.release("1.1.0")) as srv:
        manifest = json.loads(opener.open(f"{srv.url}/manifest.json").read())
        firmware = opener.open(f"{srv.url}/firmware.bin").read()
        assert manifest["version"] == "1.1.0"
        assert len(firmware) == manifest["size"]
        with pytest.raises(urllib.error.HTTPError):
            opener.open(f"{srv.url}/../keys/private_key.pem")


def test_tamper_bytes_changes_content():
    """The MITM helper changes bytes but keeps the length."""
    data = bytes(4096)
    tampered = tamper_bytes(data)
    assert len(tampered) == len(data) and tampered != data
