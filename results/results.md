# OTA Simulation - Results

Generated 2026-11-18 08:41:11 on Darwin 24.6.0, Python 3.13.2.

## Summary

| # | Scenario | Expected | Actual | Result |
|---|---|---|---|---|
| 1 | Normal update 1.0.0 -> 1.1.0 | Accepted, boots 1.1.0, marked VALID | INSTALLED, booted 1.1.0 (VALID) | ✅ PASS |
| 2 | Firmware tampered in transit (MITM) | Rejected (hash mismatch), stays on 1.1.0 | REJECTED (hash mismatch), running 1.1.0 | ✅ PASS |
| 3 | Fake server, attacker-signed release | Rejected (signature invalid) | REJECTED (signature invalid), running 1.1.0 | ✅ PASS |
| 4 | Manifest version forged (1.1.0 -> 9.9.9) | Rejected (signature invalid) | REJECTED (signature invalid), running 1.1.0 | ✅ PASS |
| 5 | Downgrade: genuine old 1.0.0 / 0.9.0 | Rejected (downgrade/replay) | REJECTED (downgrade/replay) - 1.0.0: rejected, 0.9.0: rejected | ✅ PASS |
| 6 | Interrupted download (cut at 50%) | Aborted, inactive slot erased, stays on current | ABORTED, inactive slot erased, running 1.1.0 | ✅ PASS |
| 7 | Power loss mid-write, then reboot | Boots old valid firmware | booted 1.1.0 (VALID), partial slot erased | ✅ PASS |
| 8 | Signed 1.2.0 fails self-test | Installed, then automatic ROLLBACK to 1.1.0 | installed, ROLLBACK -> running 1.1.0, v1.2.0 INVALID | ✅ PASS |
| 9 | Signed 1.2.1 crashes on boot | Automatic ROLLBACK | installed, CRASH+ROLLBACK -> running 1.1.0, v1.2.1 INVALID | ✅ PASS |
| 10 | Fixed release 1.3.0 | Accepted, VALID | INSTALLED, booted 1.3.0 (VALID), min_allowed=1.3.0 | ✅ PASS |

**10/10 scenarios passed.**

## Measurements

Update time = from contacting the server until the device runs its final firmware
(download, verification, flash writes, reboot, self-test and any rollback).

| # | Scenario | Firmware size (bytes) | Signature verify (ms) | Total update time (ms) | Version after |
|---|---|---|---|---|---|
| 1 | Normal update 1.0.0 -> 1.1.0 | 65536 | 0.36 | 23.35 | 1.1.0 |
| 2 | Firmware tampered in transit (MITM) | 65536 | 0.36 | 18.45 | 1.1.0 |
| 3 | Fake server, attacker-signed release | 65536 | 0.39 | 3.71 | 1.1.0 |
| 4 | Manifest version forged (1.1.0 -> 9.9.9) | 65536 | 0.33 | 2.79 | 1.1.0 |
| 5 | Downgrade: genuine old 1.0.0 / 0.9.0 | 65536 | 0.41 | 8.01 | 1.1.0 |
| 6 | Interrupted download (cut at 50%) | 65536 | 0.50 | 13.58 | 1.1.0 |
| 7 | Power loss mid-write, then reboot | 65536 | - | 12.65 | 1.1.0 |
| 8 | Signed 1.2.0 fails self-test | 65536 | 0.40 | 22.73 | 1.1.0 |
| 9 | Signed 1.2.1 crashes on boot | 65536 | 0.26 | 24.34 | 1.1.0 |
| 10 | Fixed release 1.3.0 | 65536 | 0.31 | 19.47 | 1.3.0 |

## Signature verification benchmark

ECDSA P-256 / SHA-256 manifest verification, 200 rounds on the host CPU:

| mean (ms) | median (ms) | min (ms) | max (ms) |
|---|---|---|---|
| 0.176 | 0.189 | 0.107 | 0.329 |

Note: an ESP32 verifies a P-256 signature in roughly tens of milliseconds
(hardware-accelerated); laptop numbers only show relative cost.

Full log: `results/demo_log.txt`
