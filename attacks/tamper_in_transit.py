"""
Scenario 2 - firmware tampered in transit (man-in-the-middle).

Attacker model: someone between the server and the device (rogue Wi-Fi
access point, compromised router, ...) modifies bytes of firmware.bin while
it is downloaded. The manifest is left untouched because the attacker can
not re-sign it.

Defence: the device hashes the image while writing it and compares the
result with the SHA-256 inside the *signed* manifest. Mismatch -> the
inactive slot is erased and the update is rejected.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import log  # noqa: E402
from demo.harness import ScenarioResult, SimContext, attempt_update, firmware_size  # noqa: E402
from device.ota_client import REJECTED  # noqa: E402

TARGET_VERSION = "1.3.0"   # a genuine, newer release that the attacker modifies


def run(ctx: SimContext) -> ScenarioResult:
    """Serve a genuine release through a tampering 'server' and check it is rejected."""
    before = ctx.device.current_version
    log.warn("ATTACK", f"MITM will modify genuine v{TARGET_VERSION} firmware while it is downloaded")
    attempt = attempt_update(ctx, ctx.release(TARGET_VERSION), tamper=True)
    upd = attempt.update

    after = ctx.device.current_version
    passed = (
        upd.status == REJECTED
        and "hash mismatch" in upd.reason
        and after == before
        and ctx.device.inactive_slot_size == 0
    )
    return ScenarioResult(
        number=2,
        title="Firmware tampered in transit (MITM)",
        expected=f"Rejected (hash mismatch), stays on {before}",
        actual=f"{upd.status} ({upd.reason.split(':')[0]}), running {after}",
        passed=passed,
        firmware_size=firmware_size(ctx.release(TARGET_VERSION)),
        verify_ms=upd.verify_ms,
        update_ms=attempt.total_ms,
        version_after=after,
    )


if __name__ == "__main__":
    from attacks._standalone import run_standalone

    sys.exit(run_standalone(run))
