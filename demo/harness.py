"""
Shared plumbing for the demo, the attack scripts and the tests.

* SimContext     - where the keys/releases are and which Device is under test
* ScenarioResult - one row of the final summary table
* create_context - keys + signed releases + factory-fresh device on v1.0.0
* attempt_update - start a server for a release, run the device's update, stop server
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from common import log
from common.paths import (
    DEVICE_FLASH_DIR,
    FIRMWARE_SRC_DIR,
    KEYS_DIR,
    PRIVATE_KEY_NAME,
    PUBLIC_KEY_NAME,
    RELEASES_DIR,
    TRUSTED_KEY_PATH,
)
from device.bootloader import BootResult
from device.device import Device
from device.ota_client import UpdateResult
from server.ota_server import running_server
from tools.keygen import generate_keys
from tools.sign_release import make_release

FACTORY_VERSION = "1.0.0"


@dataclass
class SimContext:
    """Everything a scenario needs."""

    keys_dir: Path
    releases_dir: Path
    device: Device

    @property
    def private_key_path(self) -> Path:
        """The vendor's private key (signing machine only)."""
        return self.keys_dir / PRIVATE_KEY_NAME

    @property
    def public_key_path(self) -> Path:
        """The vendor's public key."""
        return self.keys_dir / PUBLIC_KEY_NAME

    def release(self, version: str) -> Path:
        """Folder of a genuine signed release, e.g. releases/1.1.0"""
        return self.releases_dir / version


@dataclass
class ScenarioResult:
    """One row of the summary table."""

    number: int
    title: str
    expected: str
    actual: str
    passed: bool
    firmware_size: int = 0
    verify_ms: float | None = None   # signature verification time
    update_ms: float | None = None   # whole update incl. reboot / rollback
    version_after: str = ""


@dataclass
class UpdateAttempt:
    """Result of attempt_update()."""

    update: UpdateResult
    boot: BootResult | None
    total_ms: float


def load_build_definitions() -> list[dict]:
    """Read firmware_src/builds.json (the list of sample firmware builds)."""
    data = json.loads((FIRMWARE_SRC_DIR / "builds.json").read_text(encoding="utf-8"))
    return data["builds"]


def ensure_keys(keys_dir: Path) -> None:
    """Generate the vendor key pair if it does not exist yet."""
    if not (keys_dir / PRIVATE_KEY_NAME).exists():
        log.warn("DEMO", f"No signing key in {keys_dir} - generating one (normally: python tools/keygen.py)")
        generate_keys(keys_dir)


def build_all_releases(keys_dir: Path, releases_dir: Path) -> None:
    """Build and sign every sample firmware listed in firmware_src/builds.json."""
    for build in load_build_definitions():
        make_release(
            build["version"],
            build["behavior"],
            keys_dir / PRIVATE_KEY_NAME,
            releases_dir,
            blink_ms=build.get("blink_ms"),
        )


def create_context(
    keys_dir: Path = KEYS_DIR,
    releases_dir: Path = RELEASES_DIR,
    flash_dir: Path = DEVICE_FLASH_DIR,
    trusted_key_path: Path = TRUSTED_KEY_PATH,
    build_releases: bool = True,
) -> SimContext:
    """Prepare keys + releases and return a factory-fresh device running v1.0.0."""
    ensure_keys(keys_dir)
    if build_releases:
        build_all_releases(keys_dir, releases_dir)
    ctx = SimContext(keys_dir=keys_dir, releases_dir=releases_dir, device=Device(flash_dir, trusted_key_path))
    factory_image = (releases_dir / FACTORY_VERSION / "firmware.bin").read_bytes()
    ctx.device.factory_reset(factory_image, ctx.public_key_path)
    ctx.device.boot()
    return ctx


def attempt_update(
    ctx: SimContext,
    release_dir: Path,
    *,
    tamper: bool = False,
    cut_at: int | None = None,
    power_loss_after: int | None = None,
) -> UpdateAttempt:
    """Serve `release_dir`, let the device check for an update, then stop the server.

    total_ms covers download, verification, installation AND the reboot
    (including any self-test and rollback).
    """
    with running_server(release_dir, tamper=tamper, cut_at=cut_at) as server:
        start = time.perf_counter()
        update, boot_result = ctx.device.check_update(server.url, power_loss_after=power_loss_after)
        total_ms = (time.perf_counter() - start) * 1000
    return UpdateAttempt(update=update, boot=boot_result, total_ms=total_ms)


def firmware_size(release_dir: Path) -> int:
    """Size in bytes of a release's firmware.bin."""
    return (Path(release_dir) / "firmware.bin").stat().st_size
