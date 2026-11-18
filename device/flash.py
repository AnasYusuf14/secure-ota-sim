"""
Virtual flash memory of the simulated microcontroller.

On a real ESP32 the flash chip is divided into partitions. For OTA we need:

    ota_0   -> device_flash/slot_a.bin    (one firmware image)
    ota_1   -> device_flash/slot_b.bin    (the other firmware image)
    otadata -> device_flash/otadata.json  (which slot to boot + state of each image)

At any time one slot is ACTIVE (the firmware that is running) and the other
is INACTIVE (the place where the next update is downloaded). The running
firmware is never overwritten, so there is always a known-good image to go
back to.

otadata.json looks like this:

    {
      "active_slot": "a",
      "previous_slot": null,
      "boot_attempts": 0,
      "min_allowed_version": "1.0.0",       # anti-rollback counter (NVS / eFuse on ESP32)
      "slots": {
        "a": {"state": "VALID", "version": "1.0.0", "sha256": "..."},
        "b": {"state": "EMPTY", "version": null,    "sha256": null}
      }
    }

otadata.json is always written atomically (write a temp file, then rename),
like ESP-IDF which keeps two copies of otadata so a power cut during the
write can never corrupt it.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

from common import log

SLOT_SIZE = 1024 * 1024      # each OTA partition is 1 MB
SLOTS = ("a", "b")

# Image states (same names as ESP-IDF's esp_ota_img_states_t)
EMPTY = "EMPTY"                    # slot erased, nothing in it
WRITING = "WRITING"                # an update is being written right now (simulation bookkeeping)
PENDING_VERIFY = "PENDING_VERIFY"  # new image, first boot not yet confirmed
VALID = "VALID"                    # image confirmed working
INVALID = "INVALID"                # image failed, must never be booted again


class FlashError(Exception):
    """Raised for impossible flash operations (e.g. writing past the end of a slot)."""


class DeviceBricked(Exception):
    """Raised when no bootable firmware is left (the situation OTA design must prevent)."""


def other_slot(slot: str) -> str:
    """Return the name of the other slot ("a" <-> "b")."""
    return "b" if slot == "a" else "a"


def _empty_slot_info() -> dict[str, Any]:
    """The otadata entry of an erased slot."""
    return {"state": EMPTY, "version": None, "sha256": None}


class Flash:
    """File-backed model of the device flash: two OTA slots + otadata."""

    def __init__(self, root: Path) -> None:
        """`root` is the folder that plays the role of the flash chip."""
        self.root = Path(root)

    # ------------------------------------------------------------------ paths
    @property
    def otadata_path(self) -> Path:
        """Location of otadata.json."""
        return self.root / "otadata.json"

    def slot_path(self, slot: str) -> Path:
        """Location of slot_a.bin / slot_b.bin."""
        if slot not in SLOTS:
            raise FlashError(f"unknown slot {slot!r}")
        return self.root / f"slot_{slot}.bin"

    def is_formatted(self) -> bool:
        """True if the flash contains an otadata partition."""
        return self.otadata_path.exists()

    # ------------------------------------------------------------- whole chip
    def format(self) -> None:
        """Erase the whole chip: both slots empty, otadata reset."""
        self.root.mkdir(parents=True, exist_ok=True)
        for slot in SLOTS:
            self.slot_path(slot).write_bytes(b"")
        self.save_otadata(
            {
                "active_slot": "a",
                "previous_slot": None,
                "boot_attempts": 0,
                "min_allowed_version": "0.0.0",
                "slots": {slot: _empty_slot_info() for slot in SLOTS},
            }
        )

    # ---------------------------------------------------------------- slots
    def read_slot(self, slot: str) -> bytes:
        """Return the raw contents of a slot."""
        path = self.slot_path(slot)
        return path.read_bytes() if path.exists() else b""

    def erase_slot(self, slot: str) -> None:
        """Erase a slot (the file becomes empty)."""
        self.slot_path(slot).write_bytes(b"")
        log.log("FLASH", f"Erased slot {slot}")

    def append_to_slot(self, slot: str, data: bytes) -> None:
        """Append bytes to a slot, refusing to overflow the partition size."""
        path = self.slot_path(slot)
        current = path.stat().st_size if path.exists() else 0
        if current + len(data) > SLOT_SIZE:
            raise FlashError(f"write would overflow slot {slot} ({SLOT_SIZE} bytes)")
        with open(path, "ab") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    def write_slot(self, slot: str, data: bytes) -> None:
        """Replace a slot's contents completely (used only at the factory)."""
        if len(data) > SLOT_SIZE:
            raise FlashError("image larger than slot")
        self.slot_path(slot).write_bytes(data)

    # -------------------------------------------------------------- otadata
    def load_otadata(self) -> dict[str, Any]:
        """Read otadata.json."""
        return json.loads(self.otadata_path.read_text(encoding="utf-8"))

    def save_otadata(self, data: dict[str, Any]) -> None:
        """Write otadata.json atomically (temp file + rename)."""
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.otadata_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.otadata_path)

    def set_slot_info(self, slot: str, state: str, version: str | None = None, sha256: str | None = None) -> None:
        """Update one slot's entry in otadata."""
        data = self.load_otadata()
        data["slots"][slot] = {"state": state, "version": version, "sha256": sha256}
        self.save_otadata(data)

    def snapshot(self) -> dict[str, Any]:
        """A deep copy of otadata, handy for status output and tests."""
        return copy.deepcopy(self.load_otadata())
