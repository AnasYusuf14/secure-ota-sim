"""
Helper so every attack script can also be run on its own:

    python attacks/downgrade.py

It sets up a fresh device (v1.0.0), performs the normal update to v1.1.0
(the precondition of all attack scenarios), runs the attack and prints the verdict.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def run_standalone(attack: Callable) -> int:
    """Prepare the device on v1.1.0, run `attack(ctx)` and print PASS/FAIL."""
    from common import log
    from demo.harness import create_context
    from demo.scenarios import scenario_1_normal_update

    ctx = create_context()
    log.banner("Precondition: normal update 1.0.0 -> 1.1.0")
    scenario_1_normal_update(ctx)
    log.banner("Attack")
    result = attack(ctx)
    verdict = "PASS" if result.passed else "FAIL"
    (log.ok if result.passed else log.fail)("DEMO", f"[{verdict}] {result.title}: {result.actual}")
    return 0 if result.passed else 1
