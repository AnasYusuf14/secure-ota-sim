# Secure OTA Firmware Update — Software Simulation

## Canlı demo (Streamlit)

```bash
cd ota-sim
./run_ui.sh          # macOS / Linux   (Windows: run_ui.bat)
```

The first run creates `.venv` and installs `requirements.txt`; then the browser opens at
<http://localhost:8501>. Manual equivalent: `pip install -r requirements.txt` followed by
`streamlit run ui/app.py`. The signing key is generated automatically on first start
(it is never shipped with the project).

---

An Embedded Systems course project: a **pure-software simulation** of a secure
Over-The-Air (OTA) firmware update system for a microcontroller, modeled on the
**ESP32 / ESP-IDF** OTA design.

It demonstrates:

- **Signed firmware.** Every release has a manifest signed with ECDSA P-256 / SHA-256.
  The device accepts only releases signed by the vendor key it received at the factory.
- **Version control (anti-downgrade).** Old releases are refused, even if they are
  genuinely signed. An anti-rollback counter, `min_allowed_version`, only ever goes up.
- **Automatic rollback.** A/B flash slots, plus a bootloader that switches back to the
  previous firmware if a new one fails its self-test or crashes.
- **Attack scenarios.** Man-in-the-middle tampering, a fake server, manifest forgery,
  downgrade/replay, an interrupted download and power loss. These support the written
  threat analysis.

No hardware is needed. It runs on any laptop with Python 3.10+ (Windows, Linux, macOS),
and the only runtime dependency is `cryptography` (`streamlit` + `pandas` are needed only for the web UI).

---

## How a real ESP32 maps onto this simulation

| Real device (ESP32 / ESP-IDF) | Simulation equivalent |
|---|---|
| Flash memory with `ota_0` / `ota_1` partitions | `device_flash/slot_a.bin`, `device_flash/slot_b.bin` |
| `otadata` partition (which slot boots, image state) | `device_flash/otadata.json` |
| NVS / eFuse secure version counter | `min_allowed_version` field in `otadata.json` |
| Bootloader with rollback | `device/bootloader.py` |
| Public key embedded in firmware | `device/trusted_key.pem` (copied at "factory" time) |
| `esp_ota_begin/write/end`, `esp_ota_set_boot_partition` | `ota_begin()`, `ota_write()`, `ota_end()`, `ota_set_boot_partition()` in `device/ota_client.py` |
| `esp_ota_mark_app_valid_cancel_rollback` | `mark_app_valid()` |
| `esp_ota_mark_app_invalid_rollback_and_reboot` | `mark_app_invalid_and_rollback()` |
| Image states `PENDING_VERIFY`, `VALID`, `INVALID` | same names in `otadata.json` |
| Offline signing machine | `tools/` scripts |
| Update server | `server/ota_server.py` (`http.server`, localhost) |
| Task watchdog reset after a crash | `FirmwareCrash`, then a reboot inside `bootloader.boot()` |

---

## How to run

```bash
cd ota-sim
pip install -r requirements.txt

python tools/keygen.py               # 1. create keys/private_key.pem + keys/public_key.pem
python demo/run_all_scenarios.py     # 2. run all 10 scenarios, write results/
pytest                               # 3. run the test suite
```

The demo:
1. builds and signs every sample firmware from `firmware_src/builds.json` into `releases/`;
2. factory-resets the device to v1.0.0;
3. runs scenarios 1–10 in order, starting and stopping its own server for each one;
4. prints a summary table and writes `results/results.md` (summary and timings) and
   `results/demo_log.txt` (the full log).

It exits with code 0 only if every scenario behaves as expected. If you skip
`keygen.py`, the demo creates a key for you.

### Manual step-by-step session

```bash
python tools/keygen.py
python tools/sign_release.py --version 1.0.0
python tools/build_firmware.py --version 1.1.0              # unsigned image in build/
python tools/sign_release.py --image build/SmartSensor-1.1.0.bin

python device/device.py factory-reset                       # flash 1.0.0, embed public key
python server/ota_server.py --release releases/1.1.0 --port 8000   # in a 2nd terminal
python device/device.py check-update --server http://127.0.0.1:8000
python device/device.py status

# server options for experiments
python server/ota_server.py --release releases/1.1.0 --tamper        # MITM
python server/ota_server.py --release releases/1.1.0 --cut-at 32768  # drop connection
```

Each attack also runs on its own, for example `python attacks/downgrade.py`. It sets up
the device, updates it to 1.1.0, then runs the attack.

---

## Project structure

```
ota-sim/
  common/       crypto_utils.py (SHA-256, ECDSA), manifest.py, version.py, log.py,
                firmware_image.py (image format), paths.py
  tools/        keygen.py, build_firmware.py, sign_release.py   <- offline signing machine
  firmware_src/ builds.json - the sample builds (version + boot behavior)
  server/       ota_server.py                                   <- untrusted update server
  device/       flash.py, bootloader.py, ota_client.py, device.py (CLI)
  attacks/      one script per attack scenario (2-6)
  demo/         run_all_scenarios.py, scenarios.py, harness.py
  ui/           app.py (Streamlit live demo), backend.py (UI logic, no Streamlit)
  results/      results.md + demo_log.txt (written by the demo)
  tests/        pytest suite
  keys/         generated on first run; *.pem git-ignored, never copied to server/ or releases/
```

---

## Formats

**Firmware image** (~64 KB): one JSON header line followed by random padding.

```
{"name": "SmartSensor", "version": "1.1.0", "build_date": "...", "behavior": "ok", "blink_ms": 500}\n<random bytes...>
```

`behavior` sets what happens on the first boot: `ok` (self-test passes),
`fail_selftest` (self-test returns False) or `crash` (an exception during boot).
Each version blinks its LED at a different rate, so you can tell versions apart in the log:
`SmartSensor v1.1.0 running — LED blink 500 ms`.

**Manifest** (`releases/<version>/manifest.json`):

```json
{"name": "SmartSensor", "version": "1.1.0", "size": 65536, "sha256": "<hex>", "signature": "<base64>"}
```

The signature is ECDSA P-256 / SHA-256 over the **canonical serialization** of all the
other fields: keys sorted, no whitespace, ASCII only. Version, size and hash are signed
together, so changing any one of them breaks the signature.

---

## The secure update procedure (`device/ota_client.py`)

The order of these steps matters:

1. Download `/manifest.json`.
2. **Verify the signature** with the trusted public key. Nothing in the manifest is
   trusted before this step.
3. **Version check.** The new version must be greater than the current version **and**
   at least `min_allowed_version`. Otherwise the update is rejected as a "downgrade/replay".
4. **Size check.** The image must fit in a 1 MB slot. This happens before any flash write.
5. Erase the **inactive** slot. The running slot is never written.
6. Stream `/firmware.bin` in 4 KB chunks, computing SHA-256 while writing. If the
   connection breaks or the size is wrong, the slot is erased, the update is aborted
   and the device keeps running the current firmware.
7. Compare the computed hash with the **signed** hash. If they differ, the slot is
   erased and the update is rejected.
8. Set the inactive slot as the boot slot in state `PENDING_VERIFY`, then reboot.

**Bootloader** (`device/bootloader.py`):

- It erases any half-written slot left by a power loss.
- It checks that the active image is bootable (its state and its SHA-256 against
  otadata). If not, it boots the other `VALID` slot.
- For a `PENDING_VERIFY` image, it increments `boot_attempts` and saves it *before*
  starting the firmware, then runs the self-test:
  - If the self-test passes, it calls `mark_app_valid()`. The image becomes `VALID` and
    `min_allowed_version` is raised to this version.
  - If the self-test fails, it calls `mark_app_invalid_and_rollback()`, which logs
    **ROLLBACK** and boots the previous slot.
  - If the firmware crashes, the watchdog resets the device. On the next boot,
    `boot_attempts > 1`, so the bootloader performs a **ROLLBACK**.

---

## Scenarios

| # | Scenario | Expected result |
|---|---|---|
| 1 | Normal update 1.0.0 → 1.1.0 | Accepted, boots 1.1.0, marked VALID |
| 2 | Firmware tampered in transit (MITM) | Rejected (hash mismatch), stays on 1.1.0 |
| 3 | Fake server, release signed with attacker's own key | Rejected (signature invalid) |
| 4 | Manifest version edited by attacker (1.1.0 → 9.9.9) | Rejected (signature invalid) |
| 5 | Downgrade: old but genuinely signed 1.0.0 / 0.9.0 | Rejected (downgrade/replay) |
| 6 | Interrupted download (connection cut at 50%) | Aborted, inactive slot erased, stays on current |
| 7 | Power loss mid-write, then reboot | Boots old valid firmware |
| 8 | Signed 1.2.0 that fails self-test | Installed, then automatic ROLLBACK to 1.1.0 |
| 9 | Signed 1.2.1 that crashes on boot | Automatic ROLLBACK |
| 10 | Fixed 1.3.0 | Accepted, VALID |

1. **Normal update.** The happy path. The device verifies the update, writes it to
   slot b, reboots, passes the self-test and marks 1.1.0 `VALID`. The anti-rollback
   counter becomes 1.1.0, and slot a still holds 1.0.0 as a fallback.
2. **Tampered in transit** (`attacks/tamper_in_transit.py`). A man-in-the-middle flips
   16 bytes of a genuine 1.3.0 image. The manifest is still validly signed, but the
   SHA-256 computed during the download does not match the signed hash. The slot is
   erased.
3. **Fake server** (`attacks/fake_server_wrong_key.py`). The attacker builds a "2.0.0"
   release and signs it correctly, but with their own key. The device trusts only the
   factory key, so the signature check fails before any firmware byte is downloaded.
4. **Manifest forgery** (`attacks/manifest_version_forgery.py`). The attacker changes
   `"version"` in a genuine manifest from 1.1.0 to 9.9.9. Because the signature covers
   the canonical form of all fields, it becomes invalid. This also stops an attacker
   from pushing the anti-rollback counter to 9.9.9, which would block every future
   genuine update.
5. **Downgrade/replay** (`attacks/downgrade.py`). The attacker replays old *official*
   releases 1.0.0 and 0.9.0. Their signatures are valid, which the log shows, so the
   version check is what stops them.
6. **Interrupted download** (`attacks/interrupted_download.py`). The server announces
   65536 bytes but drops the connection after 32768. The device sees the incomplete
   download, erases the inactive slot and keeps running 1.1.0.
7. **Power loss.** Power is cut after half the image is written. No cleanup code runs
   (`PowerLoss` is a `BaseException`). On power-up, otadata still points at the old
   `VALID` slot, so the device boots 1.1.0 and the bootloader erases the half-written
   slot.
8. **Self-test failure.** 1.2.0 is genuine and installs, but its self-test fails on the
   first boot. It is marked `INVALID` and the device rolls back to 1.1.0. The
   anti-rollback counter is *not* raised by a bad image.
9. **Crash on boot.** 1.2.1 crashes before it can confirm itself. The watchdog reboots
   the device, the bootloader sees `boot_attempts = 2` and rolls back.
10. **Fixed release.** 1.3.0 installs and passes its self-test. `min_allowed_version`
    becomes 1.3.0.

---

## Tests

`pytest` runs:

- unit tests for version comparison, canonical manifest serialization, signing and
  verification (`test_version.py`, `test_manifest.py`, `test_crypto.py`,
  `test_firmware_image.py`);
- one end-to-end test per scenario, plus the full demo sequence (`test_scenarios.py`);
- device rules (`test_device_internals.py`): the active slot is never written, the
  `min_allowed_version` counter is enforced, a corrupted slot falls back, a device with
  no valid slot reports itself bricked, oversize images are rejected, and the server
  exposes only two files.

Tests use temporary directories. They never touch `keys/`, `releases/` or `device_flash/`.

---

## Limitations (for the threat analysis)

- The update channel is plain HTTP. That is deliberate: security comes from end-to-end
  signatures, not from the transport. A real product would still add TLS for
  confidentiality and to make denial-of-service harder.
- `min_allowed_version` lives in a JSON file. On real hardware it would be stored in
  eFuses or protected NVS that an attacker with flash access cannot reset.
- The private key is an unencrypted PEM file. A real vendor would keep it in an HSM.
- Firmware is not encrypted, so anyone can read it. ESP32 flash encryption would
  address this.
- An attacker who blocks all updates (denial-of-service, or a freeze attack that keeps
  serving the current version) is not detected. Expiring manifests or a scheme like
  TUF would address that.
