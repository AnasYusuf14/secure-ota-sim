"""
The ten scenarios, in the order the demo runs them.

Scenarios 2-6 are attacks and live in attacks/*.py. The others (normal
update, power loss, self-test failure, crash, fixed release) are here.
Each function takes a SimContext, acts on its device, and returns a
ScenarioResult. They are meant to run in order on the same device:
the device starts on 1.0.0, moves to 1.1.0 in scenario 1 and ends on 1.3.0.
"""

from __future__ import annotations

import time
from typing import Callable

from attacks import (
    downgrade,
    fake_server_wrong_key,
    interrupted_download,
    manifest_version_forgery,
    tamper_in_transit,
)
from common import log
from demo.harness import ScenarioResult, SimContext, attempt_update, firmware_size
from device.flash import EMPTY, INVALID, VALID
from device.ota_client import INSTALLED, PowerLoss
from server.ota_server import running_server


def scenario_1_normal_update(ctx: SimContext) -> ScenarioResult:
    """1. Normal update 1.0.0 -> 1.1.0: accepted, boots 1.1.0, marked VALID."""
    attempt = attempt_update(ctx, ctx.release("1.1.0"))
    upd, boot = attempt.update, attempt.boot
    passed = (
        upd.status == INSTALLED
        and boot is not None
        and boot.version == "1.1.0"
        and boot.state == VALID
        and not boot.rolled_back
    )
    return ScenarioResult(
        number=1,
        title="Normal update 1.0.0 -> 1.1.0",
        expected="Accepted, boots 1.1.0, marked VALID",
        actual=f"{upd.status}, booted {boot.version} ({boot.state})" if boot else f"{upd.status}: {upd.reason}",
        passed=passed,
        firmware_size=upd.firmware_size,
        verify_ms=upd.verify_ms,
        update_ms=attempt.total_ms,
        version_after=ctx.device.current_version,
    )


def scenario_7_power_loss(ctx: SimContext) -> ScenarioResult:
    """7. Power loss half-way through writing the inactive slot, then reboot."""
    before = ctx.device.current_version
    release = ctx.release("1.3.0")
    size = firmware_size(release)
    power_lost = False
    with running_server(release) as server:
        start = time.perf_counter()
        try:
            ctx.device.check_update(server.url, power_loss_after=size // 2)
        except PowerLoss:
            power_lost = True
            log.warn("DEVICE", "*** device is OFF - half-written image left in the inactive slot ***")
        until_power_loss_ms = (time.perf_counter() - start) * 1000

    status = ctx.device.status()
    inactive = "b" if status["active_slot"] == "a" else "a"
    left_half_written = len(ctx.device.flash.read_slot(inactive)) > 0
    log.log("DEVICE", f"Power restored - inactive slot {inactive} holds {len(ctx.device.flash.read_slot(inactive))} bytes")
    boot_start = time.perf_counter()
    boot = ctx.device.boot()
    # Time spent updating until the power cut + the recovery boot (server shutdown excluded).
    total_ms = until_power_loss_ms + (time.perf_counter() - boot_start) * 1000

    cleaned = ctx.device.status()["slots"][inactive]["state"] == EMPTY and ctx.device.inactive_slot_size == 0
    passed = power_lost and left_half_written and boot.version == before and boot.state == VALID and cleaned
    return ScenarioResult(
        number=7,
        title="Power loss mid-write, then reboot",
        expected="Boots old valid firmware",
        actual=f"booted {boot.version} ({boot.state}), partial slot {'erased' if cleaned else 'NOT erased'}",
        passed=passed,
        firmware_size=size,
        update_ms=total_ms,
        version_after=boot.version,
    )


def _rollback_scenario(ctx: SimContext, number: int, version: str, title: str, expected: str) -> ScenarioResult:
    """Shared logic of scenarios 8 and 9: install a bad release, expect automatic rollback."""
    before = ctx.device.current_version
    attempt = attempt_update(ctx, ctx.release(version))
    upd, boot = attempt.update, attempt.boot
    status = ctx.device.status()
    bad_slot_states = [s["state"] for s in status["slots"].values() if s["version"] == version]
    passed = (
        upd.status == INSTALLED
        and boot is not None
        and boot.rolled_back
        and boot.version == before
        and boot.state == VALID
        and bad_slot_states == [INVALID]
        and status["min_allowed_version"] == before   # counter NOT raised by a bad image
    )
    actual = (
        f"installed, {'+'.join(boot.events)} -> running {boot.version}, v{version} INVALID"
        if boot
        else f"{upd.status}: {upd.reason}"
    )
    return ScenarioResult(
        number=number,
        title=title,
        expected=expected,
        actual=actual,
        passed=passed,
        firmware_size=upd.firmware_size,
        verify_ms=upd.verify_ms,
        update_ms=attempt.total_ms,
        version_after=ctx.device.current_version,
    )


def scenario_8_selftest_fail(ctx: SimContext) -> ScenarioResult:
    """8. Signed 1.2.0 whose self-test fails -> automatic rollback to 1.1.0."""
    return _rollback_scenario(
        ctx, 8, "1.2.0", "Signed 1.2.0 fails self-test", "Installed, then automatic ROLLBACK to 1.1.0"
    )


def scenario_9_crash(ctx: SimContext) -> ScenarioResult:
    """9. Signed 1.2.1 that crashes on boot -> watchdog reboot -> automatic rollback."""
    return _rollback_scenario(ctx, 9, "1.2.1", "Signed 1.2.1 crashes on boot", "Automatic ROLLBACK")


def scenario_10_fixed_release(ctx: SimContext) -> ScenarioResult:
    """10. Fixed 1.3.0: accepted and VALID; the anti-rollback counter moves to 1.3.0."""
    attempt = attempt_update(ctx, ctx.release("1.3.0"))
    upd, boot = attempt.update, attempt.boot
    min_allowed = ctx.device.status()["min_allowed_version"]
    passed = (
        upd.status == INSTALLED
        and boot is not None
        and boot.version == "1.3.0"
        and boot.state == VALID
        and not boot.rolled_back
        and min_allowed == "1.3.0"
    )
    return ScenarioResult(
        number=10,
        title="Fixed release 1.3.0",
        expected="Accepted, VALID",
        actual=f"{upd.status}, booted {boot.version} ({boot.state}), min_allowed={min_allowed}"
        if boot
        else f"{upd.status}: {upd.reason}",
        passed=passed,
        firmware_size=upd.firmware_size,
        verify_ms=upd.verify_ms,
        update_ms=attempt.total_ms,
        version_after=ctx.device.current_version,
    )


# (number, title, function) in execution order
SCENARIOS: list[tuple[int, str, Callable[[SimContext], ScenarioResult]]] = [
    (1, "Normal update 1.0.0 -> 1.1.0", scenario_1_normal_update),
    (2, "Firmware tampered in transit (MITM)", tamper_in_transit.run),
    (3, "Fake server, release signed with attacker's key", fake_server_wrong_key.run),
    (4, "Manifest version edited by attacker (1.1.0 -> 9.9.9)", manifest_version_forgery.run),
    (5, "Downgrade: old but genuinely signed 1.0.0 / 0.9.0", downgrade.run),
    (6, "Interrupted download (connection cut at 50%)", interrupted_download.run),
    (7, "Power loss mid-write, then reboot", scenario_7_power_loss),
    (8, "Signed 1.2.0 that fails self-test", scenario_8_selftest_fail),
    (9, "Signed 1.2.1 that crashes on boot", scenario_9_crash),
    (10, "Fixed 1.3.0", scenario_10_fixed_release),
]
