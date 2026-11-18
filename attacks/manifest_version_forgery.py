"""
Scenario 4 - attacker edits the version number in a genuine manifest (1.1.0 -> 9.9.9).

Attacker model: the attacker takes a real, correctly signed release and
changes "version" to 9.9.9, keeping the original signature. Goals could be
to force an install, or to push the device's anti-rollback counter so high
that no future genuine update is ever accepted (a denial-of-service).

Defence: the signature covers the canonical serialization of ALL manifest
fields (name, version, size, sha256). Changing any of them invalidates it.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import log  # noqa: E402
from demo.harness import ScenarioResult, SimContext, attempt_update, firmware_size  # noqa: E402
from device.ota_client import REJECTED  # noqa: E402

ORIGINAL_VERSION = "1.1.0"
FORGED_VERSION = "9.9.9"


def forge_release(ctx: SimContext) -> Path:
    """Copy the genuine release and edit the version in its manifest (signature kept)."""
    forged_dir = ctx.releases_dir / "_forged" / FORGED_VERSION
    if forged_dir.exists():
        shutil.rmtree(forged_dir)
    shutil.copytree(ctx.release(ORIGINAL_VERSION), forged_dir)
    manifest_path = forged_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = FORGED_VERSION
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    log.warn("ATTACK", f"Edited genuine manifest: version {ORIGINAL_VERSION} -> {FORGED_VERSION} (signature unchanged)")
    return forged_dir


def run(ctx: SimContext) -> ScenarioResult:
    """Serve the forged manifest and check the device rejects it."""
    before = ctx.device.current_version
    release = forge_release(ctx)
    attempt = attempt_update(ctx, release)
    upd = attempt.update
    after = ctx.device.current_version
    min_allowed = ctx.device.status()["min_allowed_version"]
    passed = (
        upd.status == REJECTED
        and "signature invalid" in upd.reason
        and after == before
        and min_allowed != FORGED_VERSION
    )
    return ScenarioResult(
        number=4,
        title=f"Manifest version forged ({ORIGINAL_VERSION} -> {FORGED_VERSION})",
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
