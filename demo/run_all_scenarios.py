"""
Run every scenario end-to-end and summarize the results.

    python demo/run_all_scenarios.py

What it does:
1. makes sure a signing key exists (keys/), builds + signs all sample releases
   listed in firmware_src/builds.json into releases/;
2. factory-resets the device to v1.0.0;
3. runs scenarios 1-10 in order, each with its own freshly started server;
4. prints a summary table and writes
       results/results.md    (summary + measurements)
       results/demo_log.txt  (the complete log, without colors)

Exit code is 0 only if every scenario behaved as expected.
"""

from __future__ import annotations

import platform
import statistics
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import log  # noqa: E402
from common.crypto_utils import load_private_key, load_public_key  # noqa: E402
from common.manifest import build_manifest, verify_manifest  # noqa: E402
from common.paths import RESULTS_DIR  # noqa: E402
from demo.harness import ScenarioResult, SimContext, create_context  # noqa: E402
from demo.scenarios import SCENARIOS  # noqa: E402

BENCHMARK_ROUNDS = 200


def _fmt_ms(value: float | None) -> str:
    """Format milliseconds for the tables ('-' when not measured)."""
    return "-" if value is None else f"{value:.2f}"


def benchmark_verification(ctx: SimContext) -> dict[str, float]:
    """Time ECDSA P-256 signature verification over many rounds (laptop CPU)."""
    private_key = load_private_key(ctx.private_key_path)
    public_key = load_public_key(ctx.public_key_path)
    manifest = build_manifest("SmartSensor", "1.0.0", b"x" * 65536, private_key)
    samples = []
    for _ in range(BENCHMARK_ROUNDS):
        t0 = time.perf_counter()
        verify_manifest(manifest, public_key)
        samples.append((time.perf_counter() - t0) * 1000)
    return {
        "rounds": BENCHMARK_ROUNDS,
        "mean": statistics.mean(samples),
        "median": statistics.median(samples),
        "min": min(samples),
        "max": max(samples),
    }


def print_summary(results: list[ScenarioResult]) -> None:
    """Print the summary table to the console (and the log file)."""
    header = f"{'#':>2}  {'Scenario':<44} {'Result':<6} {'Update ms':>10}  Actual"
    log.raw("")
    log.raw(header)
    log.raw("-" * len(header) + "-" * 40)
    for r in results:
        verdict = "PASS" if r.passed else "FAIL"
        log.raw(f"{r.number:>2}  {r.title[:44]:<44} {verdict:<6} {_fmt_ms(r.update_ms):>10}  {r.actual}")
    passed = sum(r.passed for r in results)
    log.raw("")
    (log.ok if passed == len(results) else log.fail)("DEMO", f"{passed}/{len(results)} scenarios PASSED")


def write_results_md(path: Path, results: list[ScenarioResult], bench: dict[str, float] | None) -> None:
    """Write results/results.md with the summary and measurement tables."""
    lines = [
        "# OTA Simulation - Results",
        "",
        f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} on "
        f"{platform.system()} {platform.release()}, Python {platform.python_version()}.",
        "",
        "## Summary",
        "",
        "| # | Scenario | Expected | Actual | Result |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        verdict = "✅ PASS" if r.passed else "❌ FAIL"
        lines.append(f"| {r.number} | {r.title} | {r.expected} | {r.actual} | {verdict} |")
    passed = sum(r.passed for r in results)
    lines += [
        "",
        f"**{passed}/{len(results)} scenarios passed.**",
        "",
        "## Measurements",
        "",
        "Update time = from contacting the server until the device runs its final firmware",
        "(download, verification, flash writes, reboot, self-test and any rollback).",
        "",
        "| # | Scenario | Firmware size (bytes) | Signature verify (ms) | Total update time (ms) | Version after |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r.number} | {r.title} | {r.firmware_size} | {_fmt_ms(r.verify_ms)} | "
            f"{_fmt_ms(r.update_ms)} | {r.version_after} |"
        )
    if bench:
        lines += [
            "",
            "## Signature verification benchmark",
            "",
            f"ECDSA P-256 / SHA-256 manifest verification, {bench['rounds']} rounds on the host CPU:",
            "",
            "| mean (ms) | median (ms) | min (ms) | max (ms) |",
            "|---|---|---|---|",
            f"| {bench['mean']:.3f} | {bench['median']:.3f} | {bench['min']:.3f} | {bench['max']:.3f} |",
            "",
            "Note: an ESP32 verifies a P-256 signature in roughly tens of milliseconds",
            "(hardware-accelerated); laptop numbers only show relative cost.",
        ]
    lines += ["", "Full log: `results/demo_log.txt`", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    """Run all scenarios and write the result files."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    sink = log.add_file_sink(RESULTS_DIR / "demo_log.txt")
    results: list[ScenarioResult] = []
    bench = None
    try:
        log.banner("Setup: keys, signed releases, factory-fresh device (v1.0.0)")
        ctx = create_context()

        for number, title, scenario in SCENARIOS:
            log.banner(f"Scenario {number}: {title}")
            try:
                result = scenario(ctx)
            except Exception as exc:  # keep going so the summary is always produced
                log.fail("DEMO", f"Scenario {number} raised {exc!r}")
                log.raw(traceback.format_exc())
                result = ScenarioResult(number, title, "-", f"ERROR: {exc!r}", passed=False)
            verdict = "PASS" if result.passed else "FAIL"
            (log.ok if result.passed else log.fail)("DEMO", f"Scenario {number} {verdict}: {result.actual}")
            results.append(result)

        log.banner("Summary")
        bench = benchmark_verification(ctx)
        log.log("DEMO", f"Signature verification benchmark: mean {bench['mean']:.3f} ms over {bench['rounds']} runs")
        print_summary(results)
        write_results_md(RESULTS_DIR / "results.md", results, bench)
        log.log("DEMO", f"Wrote {RESULTS_DIR / 'results.md'} and {RESULTS_DIR / 'demo_log.txt'}")
    finally:
        log.remove_file_sink(sink)
    return 0 if results and all(r.passed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
