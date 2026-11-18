"""
End-to-end tests: one test per demo scenario (1-10).

Every test gets a factory-fresh device on v1.0.0 (see conftest.py). Scenarios
2-10 assume the device already runs 1.1.0, so they first perform scenario 1.
"""

from attacks import (
    downgrade,
    fake_server_wrong_key,
    interrupted_download,
    manifest_version_forgery,
    tamper_in_transit,
)
from demo.scenarios import (
    SCENARIOS,
    scenario_1_normal_update,
    scenario_7_power_loss,
    scenario_8_selftest_fail,
    scenario_9_crash,
    scenario_10_fixed_release,
)
from device.flash import INVALID, VALID


def _on_1_1_0(ctx):
    """Bring the device to 1.1.0 (scenario 1) and sanity-check it."""
    result = scenario_1_normal_update(ctx)
    assert result.passed, result.actual
    assert ctx.device.current_version == "1.1.0"


def test_01_normal_update(ctx):
    """1.0.0 -> 1.1.0 is accepted, booted and marked VALID; counter raised."""
    result = scenario_1_normal_update(ctx)
    assert result.passed, result.actual
    status = ctx.device.status()
    assert ctx.device.current_version == "1.1.0"
    assert ctx.device.current_state == VALID
    assert status["min_allowed_version"] == "1.1.0"
    assert status["active_slot"] == "b"
    assert status["slots"]["a"]["version"] == "1.0.0"   # old image kept as fallback
    assert result.verify_ms is not None and result.firmware_size == 65536


def test_02_tamper_in_transit(ctx):
    """Modified firmware -> hash mismatch -> rejected, slot erased."""
    _on_1_1_0(ctx)
    result = tamper_in_transit.run(ctx)
    assert result.passed, result.actual
    assert ctx.device.current_version == "1.1.0"


def test_03_fake_server_wrong_key(ctx):
    """Release signed with an attacker key -> signature invalid."""
    _on_1_1_0(ctx)
    result = fake_server_wrong_key.run(ctx)
    assert result.passed, result.actual


def test_04_manifest_version_forgery(ctx):
    """Version edited to 9.9.9 -> signature invalid; counter untouched."""
    _on_1_1_0(ctx)
    result = manifest_version_forgery.run(ctx)
    assert result.passed, result.actual
    assert ctx.device.status()["min_allowed_version"] == "1.1.0"


def test_05_downgrade(ctx):
    """Genuine old releases 1.0.0 and 0.9.0 -> downgrade/replay."""
    _on_1_1_0(ctx)
    result = downgrade.run(ctx)
    assert result.passed, result.actual
    assert "downgrade/replay" in result.actual


def test_06_interrupted_download(ctx):
    """Connection cut at 50% -> aborted, inactive slot erased."""
    _on_1_1_0(ctx)
    result = interrupted_download.run(ctx)
    assert result.passed, result.actual
    assert ctx.device.inactive_slot_size == 0


def test_07_power_loss(ctx):
    """Power loss half-way -> reboot into old valid firmware."""
    _on_1_1_0(ctx)
    result = scenario_7_power_loss(ctx)
    assert result.passed, result.actual
    assert ctx.device.current_version == "1.1.0"
    assert ctx.device.current_state == VALID


def test_08_selftest_fail_rollback(ctx):
    """1.2.0 installs, self-test fails, automatic rollback to 1.1.0."""
    _on_1_1_0(ctx)
    result = scenario_8_selftest_fail(ctx)
    assert result.passed, result.actual
    status = ctx.device.status()
    assert ctx.device.current_version == "1.1.0"
    bad = [s for s in status["slots"].values() if s["version"] == "1.2.0"]
    assert bad and bad[0]["state"] == INVALID


def test_09_crash_rollback(ctx):
    """1.2.1 crashes on boot, watchdog reboot, then automatic rollback."""
    _on_1_1_0(ctx)
    result = scenario_9_crash(ctx)
    assert result.passed, result.actual
    assert "CRASH" in result.actual and "ROLLBACK" in result.actual
    assert ctx.device.current_version == "1.1.0"


def test_10_fixed_release(ctx):
    """1.3.0 accepted and VALID; min_allowed_version becomes 1.3.0."""
    _on_1_1_0(ctx)
    result = scenario_10_fixed_release(ctx)
    assert result.passed, result.actual
    assert ctx.device.status()["min_allowed_version"] == "1.3.0"


def test_full_sequence_like_demo(ctx):
    """All ten scenarios in order on one device, exactly like the demo."""
    results = [func(ctx) for _number, _title, func in SCENARIOS]
    failed = [(r.number, r.actual) for r in results if not r.passed]
    assert not failed
    assert ctx.device.current_version == "1.3.0"
