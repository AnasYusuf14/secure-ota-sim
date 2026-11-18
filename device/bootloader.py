"""
The (simulated) second-stage bootloader with automatic rollback.

What happens on every boot:

1. Clean up: a slot that is not active but was left "WRITING" means power was
   lost during an update. It is erased. (The active slot was never touched.)
2. Check the active slot is bootable: state must be VALID or PENDING_VERIFY and
   the image hash must match the hash recorded in otadata (a simple model of
   secure boot). If not -> fall back to the other slot if that one is VALID.
3. If the active image is PENDING_VERIFY (first boot after an update):
     * increment boot_attempts and save it BEFORE starting the firmware,
       so that a crash/hang is still counted on the next boot;
     * if boot_attempts > 1 the previous attempt never confirmed itself
       (it crashed or hung and the watchdog reset the chip) -> ROLLBACK;
     * run the firmware's self-test:
           pass  -> mark_app_valid()                 (state VALID)
           fail  -> mark_app_invalid_and_rollback()  (ROLLBACK + reboot)
           crash -> watchdog reset -> reboot (counter catches it next time)
4. Start the application (prints "SmartSensor v1.1.0 running — LED blink 500 ms").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from common import log
from common.crypto_utils import sha256_hex
from common.firmware_image import ImageError, parse_header
from device.flash import (
    EMPTY,
    PENDING_VERIFY,
    VALID,
    WRITING,
    DeviceBricked,
    Flash,
    other_slot,
)
from device.ota_client import mark_app_invalid_and_rollback, mark_app_valid

MAX_BOOT_ATTEMPTS = 1   # a new image gets exactly one chance to confirm itself
MAX_REBOOTS = 5         # safety net so the simulation can never loop forever


class FirmwareCrash(Exception):
    """Raised by firmware whose behavior is "crash" (models a hard fault / hang)."""


@dataclass
class BootResult:
    """Outcome of booting the device."""

    slot: str
    version: str
    state: str
    app_message: str
    rolled_back: bool = False
    reboots: int = 0                                  # extra reboots needed (crash, rollback, ...)
    events: list[str] = field(default_factory=list)   # short notes, e.g. ["CRASH", "ROLLBACK"]


# ---------------------------------------------------------------------------
# The "firmware": what the image does when it runs
# ---------------------------------------------------------------------------


def run_self_test(header: dict[str, Any]) -> bool:
    """Run the firmware's power-on self-test, according to its `behavior` field.

    Returns True/False, or raises FirmwareCrash for behavior "crash".
    """
    behavior = header.get("behavior", "ok")
    log.log("APP", f"{header['name']} v{header['version']}: running self-test...")
    if behavior == "crash":
        raise FirmwareCrash("Guru Meditation Error: LoadProhibited (null pointer) in app_main()")
    if behavior == "fail_selftest":
        log.fail("APP", "Self-test: sensor I2C read failed")
        return False
    log.ok("APP", "Self-test: flash, sensor and Wi-Fi OK")
    return True


def run_application(header: dict[str, Any]) -> str:
    """Start the normal application and return its status line."""
    message = f"{header['name']} v{header['version']} running — LED blink {header.get('blink_ms', 1000)} ms"
    log.ok("APP", message)
    return message


# ---------------------------------------------------------------------------
# Bootloader helpers
# ---------------------------------------------------------------------------


def _erase_incomplete_slots(flash: Flash, otadata: dict[str, Any]) -> None:
    """Erase any non-active slot that was left half-written by a power loss."""
    for slot, info in otadata["slots"].items():
        if slot != otadata["active_slot"] and info["state"] == WRITING:
            log.warn("BOOT", f"Slot {slot} holds an incomplete image (power lost during update) - erasing it")
            flash.erase_slot(slot)
            flash.set_slot_info(slot, EMPTY)


def _slot_problem(flash: Flash, slot: str, info: dict[str, Any]) -> str | None:
    """Return why `slot` can not be booted, or None if it looks fine."""
    if info["state"] not in (VALID, PENDING_VERIFY):
        return f"slot {slot} is {info['state']}"
    image = flash.read_slot(slot)
    if not image:
        return f"slot {slot} is empty"
    if info.get("sha256") and sha256_hex(image) != info["sha256"]:
        return f"slot {slot} image hash does not match otadata (corrupted)"
    try:
        parse_header(image)
    except ImageError as exc:
        return f"slot {slot} image unreadable ({exc})"
    return None


def _fall_back(flash: Flash, bad_slot: str, problem: str) -> None:
    """Switch to the other slot if it is VALID; otherwise the device is bricked."""
    otadata = flash.load_otadata()
    target = other_slot(bad_slot)
    target_info = otadata["slots"][target]
    if target_info["state"] != VALID or _slot_problem(flash, target, target_info):
        raise DeviceBricked(f"{problem}, and slot {target} is not bootable either")
    otadata["active_slot"] = target
    otadata["previous_slot"] = None
    otadata["boot_attempts"] = 0
    flash.save_otadata(otadata)
    log.warn("BOOT", f"ROLLBACK: {problem} -> booting slot {target} (v{target_info['version']})")


# ---------------------------------------------------------------------------
# Main boot routine
# ---------------------------------------------------------------------------


def boot(flash: Flash) -> BootResult:
    """Boot the device, performing verification and rollback as needed."""
    rolled_back = False
    events: list[str] = []

    for boot_number in range(1, MAX_REBOOTS + 1):
        otadata = flash.load_otadata()
        _erase_incomplete_slots(flash, otadata)
        otadata = flash.load_otadata()

        slot = otadata["active_slot"]
        info = otadata["slots"][slot]
        log.log("BOOT", f"Boot #{boot_number}: active slot {slot} -> v{info['version']} [{info['state']}]")

        problem = _slot_problem(flash, slot, info)
        if problem:
            log.fail("BOOT", problem)
            _fall_back(flash, slot, problem)
            rolled_back = True
            events.append("ROLLBACK")
            continue

        header = parse_header(flash.read_slot(slot))

        if info["state"] == PENDING_VERIFY:
            otadata["boot_attempts"] += 1
            flash.save_otadata(otadata)  # saved BEFORE running: survives a crash
            attempts = otadata["boot_attempts"]

            if attempts > MAX_BOOT_ATTEMPTS:
                log.fail("BOOT", f"v{info['version']} never confirmed itself (boot attempt {attempts}) - crash/hang")
                mark_app_invalid_and_rollback(flash, "did not confirm after reboot")
                rolled_back = True
                events.append("ROLLBACK")
                continue

            log.log("BOOT", f"v{info['version']} is PENDING_VERIFY (boot attempt {attempts}) - starting self-test")
            try:
                passed = run_self_test(header)
            except FirmwareCrash as exc:
                log.fail("APP", f"CRASH: {exc}")
                log.warn("BOOT", "Watchdog reset - rebooting")
                events.append("CRASH")
                continue  # reboot; boot_attempts is already 1 so next boot rolls back

            if not passed:
                mark_app_invalid_and_rollback(flash, "self-test failed")
                rolled_back = True
                events.append("ROLLBACK")
                continue

            mark_app_valid(flash)

        message = run_application(header)
        final = flash.load_otadata()
        return BootResult(
            slot=slot,
            version=info["version"],
            state=final["slots"][slot]["state"],
            app_message=message,
            rolled_back=rolled_back,
            reboots=boot_number - 1,
            events=events,
        )

    raise DeviceBricked(f"gave up after {MAX_REBOOTS} reboots")
