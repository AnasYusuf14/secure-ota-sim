"""
Scenario 6 - interrupted download (connection cut at 50 %).

Attacker / fault model: the connection drops half-way, either by accident
(weak Wi-Fi) or on purpose (an attacker trying to leave a half-written image
behind and brick the device).

Defence: the image goes into the INACTIVE slot only; the size is checked
against the signed manifest; on any transport error the partial image is
erased and the device keeps running the current firmware.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import log  # noqa: E402
from demo.harness import ScenarioResult, SimContext, attempt_update, firmware_size  # noqa: E402
from device.ota_client import ABORTED  # noqa: E402

TARGET_VERSION = "1.3.0"


def run(ctx: SimContext) -> ScenarioResult:
    """Cut the firmware download at 50 % and check the device recovers cleanly."""
    before = ctx.device.current_version
    size = firmware_size(ctx.release(TARGET_VERSION))
    cut_at = size // 2
    log.warn("ATTACK", f"Network will drop after {cut_at} of {size} bytes (50%)")
    attempt = attempt_update(ctx, ctx.release(TARGET_VERSION), cut_at=cut_at)
    upd = attempt.update

    after = ctx.device.current_version
    erased = ctx.device.inactive_slot_size == 0
    passed = upd.status == ABORTED and after == before and erased and ctx.device.current_state == "VALID"
    return ScenarioResult(
        number=6,
        title="Interrupted download (cut at 50%)",
        expected="Aborted, inactive slot erased, stays on current",
        actual=f"{upd.status}, inactive slot {'erased' if erased else 'NOT erased'}, running {after}",
        passed=passed,
        firmware_size=size,
        verify_ms=upd.verify_ms,
        update_ms=attempt.total_ms,
        version_after=after,
    )


if __name__ == "__main__":
    from attacks._standalone import run_standalone

    sys.exit(run_standalone(run))
