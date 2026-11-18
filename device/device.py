"""
The simulated device and its command-line interface.

    python device/device.py factory-reset      # flash v1.0.0 + embed the public key
    python device/device.py boot               # power on
    python device/device.py check-update --server http://127.0.0.1:8000
    python device/device.py status             # show otadata

Typical manual session (three terminals not needed - one is enough):

    python tools/keygen.py
    python tools/sign_release.py --version 1.0.0
    python tools/sign_release.py --version 1.1.0
    python device/device.py factory-reset
    python server/ota_server.py --release releases/1.1.0 &
    python device/device.py check-update
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import log  # noqa: E402
from common.crypto_utils import load_public_key, sha256_hex  # noqa: E402
from common.firmware_image import parse_header  # noqa: E402
from common.paths import (  # noqa: E402
    DEVICE_FLASH_DIR,
    KEYS_DIR,
    PUBLIC_KEY_NAME,
    RELEASES_DIR,
    TRUSTED_KEY_PATH,
)
from device.bootloader import BootResult, boot  # noqa: E402
from device.flash import VALID, Flash  # noqa: E402
from device.ota_client import UpdateResult, check_and_install  # noqa: E402


class Device:
    """A simulated microcontroller: flash memory + embedded trusted public key."""

    def __init__(self, flash_dir: Path = DEVICE_FLASH_DIR, trusted_key_path: Path = TRUSTED_KEY_PATH) -> None:
        """Create a device whose flash lives in `flash_dir`."""
        self.flash = Flash(flash_dir)
        self.trusted_key_path = Path(trusted_key_path)

    # ---------------------------------------------------------------- factory
    def factory_reset(self, factory_image: bytes, public_key_path: Path) -> None:
        """Simulate manufacturing: erase flash, flash the factory image into slot a,
        and embed the vendor's public key in the device."""
        header = parse_header(factory_image)
        log.log("DEVICE", f"Factory reset: flashing {header['name']} v{header['version']} into slot a")
        self.flash.format()
        self.flash.write_slot("a", factory_image)
        otadata = self.flash.load_otadata()
        otadata["slots"]["a"] = {"state": VALID, "version": header["version"], "sha256": sha256_hex(factory_image)}
        otadata["min_allowed_version"] = header["version"]
        self.flash.save_otadata(otadata)

        self.trusted_key_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(public_key_path, self.trusted_key_path)
        log.ok("DEVICE", f"Factory reset done - trusted public key embedded ({self.trusted_key_path.name})")

    # -------------------------------------------------------------- runtime
    def trusted_key(self):
        """Load the public key embedded at the factory."""
        if not self.trusted_key_path.exists():
            raise FileNotFoundError(f"{self.trusted_key_path} missing - run factory-reset first")
        return load_public_key(self.trusted_key_path)

    def boot(self) -> BootResult:
        """Power on / reboot the device."""
        return boot(self.flash)

    def check_update(
        self, server_url: str, power_loss_after: int | None = None
    ) -> tuple[UpdateResult, BootResult | None]:
        """Run the secure OTA procedure and, if something was installed, reboot.

        Returns (update_result, boot_result). boot_result is None when nothing
        was installed (the device simply keeps running).
        A simulated power loss (power_loss_after) raises ota_client.PowerLoss.
        """
        result = check_and_install(self.flash, server_url, self.trusted_key(), power_loss_after)
        if not result.installed:
            log.log("DEVICE", f"Still running v{self.current_version}")
            return result, None
        log.log("DEVICE", "Rebooting into the new firmware...")
        return result, self.boot()

    # --------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        """Return a copy of otadata."""
        return self.flash.snapshot()

    @property
    def current_version(self) -> str:
        """Version in the active slot."""
        otadata = self.flash.load_otadata()
        return otadata["slots"][otadata["active_slot"]]["version"]

    @property
    def current_state(self) -> str:
        """Image state of the active slot."""
        otadata = self.flash.load_otadata()
        return otadata["slots"][otadata["active_slot"]]["state"]

    @property
    def inactive_slot_size(self) -> int:
        """Number of bytes in the inactive slot (0 means erased)."""
        otadata = self.flash.load_otadata()
        inactive = "b" if otadata["active_slot"] == "a" else "a"
        return len(self.flash.read_slot(inactive))


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Simulated OTA-capable device.")
    parser.add_argument("--flash-dir", type=Path, default=DEVICE_FLASH_DIR, help="virtual flash folder")
    sub = parser.add_subparsers(dest="command", required=True)

    reset = sub.add_parser("factory-reset", help="flash factory firmware and embed the public key")
    reset.add_argument("--image", type=Path, default=RELEASES_DIR / "1.0.0" / "firmware.bin")
    reset.add_argument("--public-key", type=Path, default=KEYS_DIR / PUBLIC_KEY_NAME)

    sub.add_parser("boot", help="power on the device")

    update = sub.add_parser("check-update", help="download and install an update")
    update.add_argument("--server", default="http://127.0.0.1:8000")

    sub.add_parser("status", help="print otadata")

    args = parser.parse_args(argv)
    device = Device(args.flash_dir)

    if args.command == "factory-reset":
        for path, hint in ((args.image, "python tools/sign_release.py --version 1.0.0"),
                           (args.public_key, "python tools/keygen.py")):
            if not path.exists():
                log.fail("DEVICE", f"{path} not found - run: {hint}")
                return 1
        device.factory_reset(args.image.read_bytes(), args.public_key)
        device.boot()
    elif not device.flash.is_formatted():
        log.fail("DEVICE", "flash is blank - run: python device/device.py factory-reset")
        return 1
    elif args.command == "boot":
        device.boot()
    elif args.command == "check-update":
        device.check_update(args.server)
    elif args.command == "status":
        print(json.dumps(device.status(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
