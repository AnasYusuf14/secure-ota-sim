"""
The secure OTA update procedure that runs on the device.

The low-level functions mirror the ESP-IDF OTA API:

    ESP-IDF                                         here
    ----------------------------------------------  -------------------------------
    esp_ota_begin()                                 ota_begin()
    esp_ota_write()                                 ota_write()
    esp_ota_end()                                   ota_end()
    esp_ota_abort()                                 ota_abort()
    esp_ota_set_boot_partition()                    ota_set_boot_partition()
    esp_ota_mark_app_valid_cancel_rollback()        mark_app_valid()
    esp_ota_mark_app_invalid_rollback_and_reboot()  mark_app_invalid_and_rollback()

check_and_install() glues them together into the secure procedure.
THE ORDER OF THE STEPS MATTERS:

    1. download manifest
    2. verify manifest signature       -> nothing is trusted before this
    3. version check (anti-downgrade)  -> a valid signature is not enough
    4. size sanity check               -> before touching flash
    5. erase INACTIVE slot             -> the running firmware is never touched
    6. stream firmware in 4 KB chunks, hashing while writing
    7. compare hash with signed manifest hash
    8. set inactive slot as boot slot (PENDING_VERIFY), reboot
"""

from __future__ import annotations

import hashlib
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.client import HTTPException

from common import log
from common.manifest import ManifestError, parse_manifest, verify_manifest
from common.version import is_at_least, is_newer
from device.flash import (
    EMPTY,
    INVALID,
    PENDING_VERIFY,
    SLOT_SIZE,
    VALID,
    WRITING,
    DeviceBricked,
    Flash,
    other_slot,
)

CHUNK_SIZE = 4096
MAX_FIRMWARE_SIZE = SLOT_SIZE   # 1 MB: an image must fit into one slot
HTTP_TIMEOUT = 5                # seconds

# Status values of UpdateResult
INSTALLED = "INSTALLED"   # written + verified, device must reboot into it
REJECTED = "REJECTED"     # refused for a security reason
ABORTED = "ABORTED"       # stopped because of a transport problem

# Ignore any HTTP proxy configured on the laptop: we only talk to localhost.
_http = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class PowerLoss(BaseException):
    """Simulated power cut while writing flash.

    It derives from BaseException (like KeyboardInterrupt) on purpose, so that
    none of the `except Exception` clean-up code runs - when power is lost,
    the CPU simply stops and nothing gets a chance to tidy up.
    """


@dataclass
class UpdateResult:
    """What happened during one update attempt (plus timing measurements)."""

    status: str
    reason: str = ""
    version: str | None = None          # version offered by the server
    firmware_size: int = 0
    verify_ms: float | None = None      # time spent verifying the signature
    download_ms: float | None = None    # time spent downloading + writing flash
    total_ms: float | None = None       # whole procedure (without reboot)

    @property
    def installed(self) -> bool:
        """True if the new firmware was written and scheduled for boot."""
        return self.status == INSTALLED


@dataclass
class OtaHandle:
    """Book-keeping for an update being written (like esp_ota_handle_t)."""

    slot: str
    hasher: "hashlib._Hash"
    bytes_written: int = 0


# ---------------------------------------------------------------------------
# Low-level OTA API (ESP-IDF style)
# ---------------------------------------------------------------------------


def ota_begin(flash: Flash, slot: str) -> OtaHandle:
    """Prepare `slot` for a new image: erase it and mark it WRITING.

    Refuses to touch the active slot - overwriting the running firmware would
    leave nothing to fall back to.
    """
    otadata = flash.load_otadata()
    if slot == otadata["active_slot"]:
        raise RuntimeError("refusing to write to the ACTIVE slot")
    flash.erase_slot(slot)
    # Real ESP-IDF does not record "writing" in otadata - the bootloader simply
    # never looks at a slot otadata does not point to. We record it so the
    # simulated bootloader can report (and clean up) a half-written slot.
    flash.set_slot_info(slot, WRITING)
    return OtaHandle(slot=slot, hasher=hashlib.sha256())


def ota_write(flash: Flash, handle: OtaHandle, chunk: bytes) -> None:
    """Write one chunk into the slot and feed it into the running SHA-256."""
    flash.append_to_slot(handle.slot, chunk)
    handle.hasher.update(chunk)
    handle.bytes_written += len(chunk)


def ota_end(handle: OtaHandle, expected_size: int, expected_sha256: str) -> tuple[bool, str]:
    """Finish writing: check size and hash. Returns (ok, reason)."""
    if handle.bytes_written != expected_size:
        return False, f"size mismatch: got {handle.bytes_written} bytes, manifest says {expected_size}"
    digest = handle.hasher.hexdigest()
    if digest != expected_sha256:
        return False, f"hash mismatch: computed {digest[:16]}..., manifest says {expected_sha256[:16]}..."
    return True, "hash matches"


def ota_abort(flash: Flash, handle: OtaHandle) -> None:
    """Throw away a partially written / bad image: erase the slot and mark it EMPTY."""
    flash.erase_slot(handle.slot)
    flash.set_slot_info(handle.slot, EMPTY)


def ota_set_boot_partition(flash: Flash, slot: str, version: str, sha256: str) -> None:
    """Make `slot` the boot slot. Its image starts in state PENDING_VERIFY.

    The currently running slot is remembered as `previous_slot`, so the
    bootloader knows where to roll back to.
    """
    otadata = flash.load_otadata()
    otadata["previous_slot"] = otadata["active_slot"]
    otadata["active_slot"] = slot
    otadata["boot_attempts"] = 0
    otadata["slots"][slot] = {"state": PENDING_VERIFY, "version": version, "sha256": sha256}
    flash.save_otadata(otadata)
    log.log("OTA", f"Boot slot set to {slot} (v{version}, state {PENDING_VERIFY})")


def mark_app_valid(flash: Flash) -> None:
    """Called by the new firmware once its self-test passed.

    * the image becomes VALID (no more rollback)
    * the anti-rollback counter min_allowed_version is raised to this version,
      so older (possibly vulnerable) firmware can never be installed again.
    """
    otadata = flash.load_otadata()
    slot = otadata["active_slot"]
    version = otadata["slots"][slot]["version"]
    otadata["slots"][slot]["state"] = VALID
    otadata["boot_attempts"] = 0
    if is_newer(version, otadata["min_allowed_version"]):
        otadata["min_allowed_version"] = version
    flash.save_otadata(otadata)
    log.ok("BOOT", f"mark_app_valid(): v{version} in slot {slot} is now VALID")
    log.log("BOOT", f"Anti-rollback counter: min_allowed_version = {otadata['min_allowed_version']}")


def mark_app_invalid_and_rollback(flash: Flash, reason: str) -> str:
    """Mark the running (new) image INVALID and switch back to the previous slot.

    Returns the slot that will be booted next. Raises DeviceBricked if the
    previous slot is not VALID (should never happen thanks to A/B slots).
    """
    otadata = flash.load_otadata()
    bad_slot = otadata["active_slot"]
    bad_version = otadata["slots"][bad_slot]["version"]
    target = otadata.get("previous_slot") or other_slot(bad_slot)
    if otadata["slots"][target]["state"] != VALID:
        raise DeviceBricked(f"cannot roll back: slot {target} is {otadata['slots'][target]['state']}")

    otadata["slots"][bad_slot]["state"] = INVALID
    otadata["active_slot"] = target
    otadata["previous_slot"] = None
    otadata["boot_attempts"] = 0
    flash.save_otadata(otadata)
    log.fail("BOOT", f"ROLLBACK: v{bad_version} (slot {bad_slot}) marked INVALID - {reason}")
    log.warn(
        "BOOT",
        f"ROLLBACK: switching back to slot {target} (v{otadata['slots'][target]['version']}) and rebooting",
    )
    return target


# ---------------------------------------------------------------------------
# The secure update procedure
# ---------------------------------------------------------------------------


def _finish(result: UpdateResult, start: float, status: str, reason: str) -> UpdateResult:
    """Fill in the final status / total time and log the outcome."""
    result.status = status
    result.reason = reason
    result.total_ms = (time.perf_counter() - start) * 1000
    if status == INSTALLED:
        log.ok("OTA", f"{status}: {reason}")
    else:
        log.fail("OTA", f"{status}: {reason}")
    return result


def check_and_install(
    flash: Flash,
    server_url: str,
    trusted_public_key,
    power_loss_after: int | None = None,
) -> UpdateResult:
    """Run the full secure update procedure against `server_url`.

    Args:
        flash:              the device's flash.
        server_url:         e.g. "http://127.0.0.1:8000".
        trusted_public_key: the vendor public key embedded in the device.
        power_loss_after:   (simulation only) cut the power after this many
                            firmware bytes have been written -> raises PowerLoss.

    Returns an UpdateResult. If its status is INSTALLED the caller must reboot.
    """
    start = time.perf_counter()
    result = UpdateResult(status=REJECTED)
    otadata = flash.load_otadata()
    active = otadata["active_slot"]
    current_version = otadata["slots"][active]["version"]
    min_allowed = otadata["min_allowed_version"]
    log.log("OTA", f"Checking {server_url} for updates (running v{current_version} from slot {active})")

    # -- Step 1: download the manifest --------------------------------------
    try:
        with _http.open(f"{server_url}/manifest.json", timeout=HTTP_TIMEOUT) as response:
            raw_manifest = response.read(64 * 1024)  # a manifest is tiny; cap what we accept
    except (urllib.error.URLError, OSError, HTTPException) as exc:
        return _finish(result, start, ABORTED, f"could not download manifest ({exc})")

    try:
        manifest = parse_manifest(raw_manifest)
    except ManifestError as exc:
        return _finish(result, start, REJECTED, f"malformed manifest ({exc})")
    result.version = manifest["version"]
    result.firmware_size = manifest["size"]
    log.log("OTA", f"Manifest: {manifest['name']} v{manifest['version']}, {manifest['size']} bytes")

    # -- Step 2: verify the signature (nothing is trusted before this!) -----
    t0 = time.perf_counter()
    signature_ok = verify_manifest(manifest, trusted_public_key)
    result.verify_ms = (time.perf_counter() - t0) * 1000
    if not signature_ok:
        return _finish(result, start, REJECTED, "signature invalid - manifest not signed by the trusted key")
    log.ok("OTA", f"Signature verified ({result.verify_ms:.2f} ms)")

    # -- Step 3: version check (anti-downgrade / anti-replay) ---------------
    new_version = manifest["version"]
    if not is_newer(new_version, current_version):
        return _finish(
            result, start, REJECTED,
            f"v{new_version} is not newer than running v{current_version} (downgrade/replay)",
        )
    if not is_at_least(new_version, min_allowed):
        return _finish(
            result, start, REJECTED,
            f"v{new_version} is below min_allowed_version {min_allowed} (downgrade/replay)",
        )
    log.ok("OTA", f"Version check: {new_version} > {current_version} and >= {min_allowed}")

    # -- Step 4: size sanity check -------------------------------------------
    expected_size = manifest["size"]
    if not 0 < expected_size <= MAX_FIRMWARE_SIZE:
        return _finish(result, start, REJECTED, f"size {expected_size} does not fit in a slot ({MAX_FIRMWARE_SIZE})")
    log.ok("OTA", f"Size check: {expected_size} bytes fits in a {MAX_FIRMWARE_SIZE}-byte slot")

    # -- Step 5: erase the INACTIVE slot -------------------------------------
    target = other_slot(active)
    log.log("OTA", f"Writing to inactive slot {target} (active slot {active} is never touched)")
    handle = ota_begin(flash, target)

    # -- Step 6: stream the firmware in 4 KB chunks, hashing while writing ---
    t_download = time.perf_counter()
    next_progress = 25
    try:
        with _http.open(f"{server_url}/firmware.bin", timeout=HTTP_TIMEOUT) as response:
            while True:
                # Read at most one byte more than expected, to detect oversized data.
                want = min(CHUNK_SIZE, expected_size - handle.bytes_written + 1)
                chunk = response.read(want)
                if not chunk:
                    break
                if handle.bytes_written + len(chunk) > expected_size:
                    ota_abort(flash, handle)
                    return _finish(result, start, ABORTED, "server sent more data than the manifest size")
                ota_write(flash, handle, chunk)

                percent = handle.bytes_written * 100 // expected_size
                if percent >= next_progress:
                    log.log("OTA", f"Downloaded {handle.bytes_written}/{expected_size} bytes ({percent}%)")
                    next_progress = (percent // 25 + 1) * 25

                if power_loss_after is not None and handle.bytes_written >= power_loss_after:
                    log.warn("DEVICE", f"POWER LOSS after writing {handle.bytes_written} bytes!")
                    raise PowerLoss(f"power lost after {handle.bytes_written} bytes")
    except (urllib.error.URLError, OSError, HTTPException) as exc:
        ota_abort(flash, handle)
        return _finish(
            result, start, ABORTED,
            f"connection lost after {handle.bytes_written} bytes ({exc.__class__.__name__}); "
            f"inactive slot {target} erased, still running v{current_version}",
        )
    result.download_ms = (time.perf_counter() - t_download) * 1000

    if handle.bytes_written != expected_size:
        ota_abort(flash, handle)
        return _finish(
            result, start, ABORTED,
            f"incomplete download ({handle.bytes_written}/{expected_size} bytes); "
            f"inactive slot {target} erased, still running v{current_version}",
        )

    # -- Step 7: compare the computed hash with the SIGNED manifest hash -----
    ok, reason = ota_end(handle, expected_size, manifest["sha256"])
    if not ok:
        ota_abort(flash, handle)
        return _finish(result, start, REJECTED, f"{reason} - firmware modified, slot {target} erased")
    log.ok("OTA", f"SHA-256 verified: {manifest['sha256'][:16]}...")

    # -- Step 8: schedule the new image for the next boot --------------------
    ota_set_boot_partition(flash, target, new_version, manifest["sha256"])
    return _finish(result, start, INSTALLED, f"v{new_version} installed in slot {target}, rebooting")
