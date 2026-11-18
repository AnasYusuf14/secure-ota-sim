"""
Scenario 5 - downgrade / replay attack with OLD but GENUINELY SIGNED firmware.

Attacker model: the attacker replays an old official release (1.0.0 or
0.9.0) that has a known vulnerability. Its signature is perfectly valid -
the vendor really did sign it years ago - so signature checking alone can
not stop this.

Defence: after the signature check, the device requires
    new_version > current_version  AND  new_version >= min_allowed_version
where min_allowed_version is an anti-rollback counter (on ESP32: eFuse
"secure version" / NVS) that only ever increases.
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

OLD_VERSIONS = ("1.0.0", "0.9.0")


def run(ctx: SimContext) -> ScenarioResult:
    """Offer each old genuine release; every one must be rejected as downgrade/replay."""
    before = ctx.device.current_version
    outcomes = []
    verify_times = []
    total_ms = 0.0
    for version in OLD_VERSIONS:
        log.warn("ATTACK", f"Replaying old, genuinely signed release v{version}")
        attempt = attempt_update(ctx, ctx.release(version))
        upd = attempt.update
        total_ms += attempt.total_ms
        if upd.verify_ms is not None:
            verify_times.append(upd.verify_ms)
        outcomes.append((version, upd.status == REJECTED and "downgrade/replay" in upd.reason))

    after = ctx.device.current_version
    passed = all(ok for _, ok in outcomes) and after == before
    summary = ", ".join(f"{v}: {'rejected' if ok else 'NOT rejected'}" for v, ok in outcomes)
    return ScenarioResult(
        number=5,
        title="Downgrade: genuine old 1.0.0 / 0.9.0",
        expected="Rejected (downgrade/replay)",
        actual=f"REJECTED (downgrade/replay) - {summary}" if passed else summary,
        passed=passed,
        firmware_size=firmware_size(ctx.release(OLD_VERSIONS[0])),
        verify_ms=sum(verify_times) / len(verify_times) if verify_times else None,
        update_ms=total_ms,
        version_after=after,
    )


if __name__ == "__main__":
    from attacks._standalone import run_standalone

    sys.exit(run_standalone(run))
