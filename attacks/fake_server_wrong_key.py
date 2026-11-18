"""
Scenario 3 - fake update server with a release signed by the attacker's own key.

Attacker model: the attacker controls DNS or sets up a look-alike server and
publishes malicious firmware "2.0.0". They know the manifest format and sign
it correctly - but with THEIR key, because the vendor's private key never
leaves the offline signing machine.

Defence: the device only trusts the public key embedded at the factory, so
the signature check fails and the firmware is never even downloaded.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import log  # noqa: E402
from common.crypto_utils import generate_private_key  # noqa: E402
from common.firmware_image import build_image  # noqa: E402
from demo.harness import ScenarioResult, SimContext, attempt_update, firmware_size  # noqa: E402
from device.ota_client import REJECTED  # noqa: E402
from tools.sign_release import sign_release  # noqa: E402

MALICIOUS_VERSION = "2.0.0"


def run(ctx: SimContext) -> ScenarioResult:
    """Build + sign a malicious release with a fresh attacker key and offer it to the device."""
    before = ctx.device.current_version
    attacker_dir = ctx.releases_dir / "_attacker"
    attacker_key = generate_private_key()   # kept in memory only - it is the attacker's key
    log.warn("ATTACK", "Attacker generated their own ECDSA P-256 key pair")

    malicious = build_image("SmartSensor", MALICIOUS_VERSION, "ok", blink_ms=50)
    release = sign_release(malicious, attacker_key, attacker_dir)
    log.warn("ATTACK", f"Fake server offers v{MALICIOUS_VERSION} signed with the attacker's key")

    attempt = attempt_update(ctx, release)
    upd = attempt.update
    after = ctx.device.current_version
    passed = upd.status == REJECTED and "signature invalid" in upd.reason and after == before
    return ScenarioResult(
        number=3,
        title="Fake server, attacker-signed release",
        expected="Rejected (signature invalid)",
        actual=f"{upd.status} (signature invalid), running {after}" if passed else f"{upd.status}: {upd.reason}",
        passed=passed,
        firmware_size=firmware_size(release),
        verify_ms=upd.verify_ms,
        update_ms=attempt.total_ms,
        version_after=after,
    )


if __name__ == "__main__":
    from attacks._standalone import run_standalone

    sys.exit(run_standalone(run))
