"""
Tests for the live-demo UI backend (ui/backend.py) - no Streamlit needed.

Uses the same temporary keys/releases/flash as the other tests (conftest.py),
so the real project folders are never touched.
"""

from device.flash import INVALID
from device.ota_client import INSTALLED, REJECTED
from ui import backend


def _icons(record):
    return [icon for icon, _label in backend.update_steps(record)]


def test_ui_scenario_1_normal_update(ctx):
    """Fresh device: no preparation needed, all 8 steps pass, INSTALLED."""
    out = backend.run_scenario(ctx, 1)
    assert out.error is None, out.error
    assert out.passed is True
    assert out.prep_message is None
    assert out.word == INSTALLED
    assert _icons(out.attempts[0]) == ["✅"] * 8
    assert out.attempts[0].manifest["version"] == "1.1.0" and "signature" in out.attempts[0].manifest
    assert any("[OTA]" in line for line in out.log_lines)
    assert ctx.device.current_version == "1.1.0"


def test_ui_scenario_2_mitm_is_prepared_and_stopped_at_hash_check(ctx):
    """Device on 1.0.0 -> auto-prepared to 1.1.0, then MITM stopped at step 7."""
    out = backend.run_scenario(ctx, 2)
    assert out.error is None, out.error
    assert out.prep_message == "Cihaz önce 1.1.0’a hazırlandı"
    assert out.passed is True
    assert out.word == REJECTED and "hash mismatch" in out.raw_reason
    assert backend.failed_step(out.attempts[0]) == 7
    assert _icons(out.attempts[0]) == ["✅"] * 6 + ["❌", "⏭️"]
    assert ctx.device.current_version == "1.1.0"


def test_ui_scenario_5_downgrade_two_attempts_stopped_at_version_check(ctx):
    """Both replayed releases pass the signature but stop at step 3."""
    out = backend.run_scenario(ctx, 5)
    assert out.passed is True, out.result.actual
    assert len(out.attempts) == 2
    assert [a.manifest["version"] for a in out.attempts] == ["1.0.0", "0.9.0"]
    for attempt in out.attempts:
        assert attempt.word == REJECTED
        assert _icons(attempt) == ["✅", "✅", "❌"] + ["⏭️"] * 5
    assert "downgrade/replay" in out.raw_reason


def test_ui_scenario_8_selftest_fail_rollback(ctx):
    """1.2.0 installs (all 8 steps pass) but rolls back after the self-test."""
    out = backend.run_scenario(ctx, 8)
    assert out.passed is True, out.result.actual
    assert out.word == backend.ROLLBACK
    assert _icons(out.attempts[0]) == ["✅"] * 8
    assert out.attempts[0].boot.rolled_back
    status = ctx.device.status()
    assert ctx.device.current_version == "1.1.0"
    assert [s["state"] for s in status["slots"].values() if s["version"] == "1.2.0"] == [INVALID]


def test_ui_two_runs_in_a_row_and_manual_mode(ctx):
    """Repeating a scenario re-uses the prepared device; manual tamper is rejected."""
    assert backend.run_scenario(ctx, 2).passed
    again = backend.run_scenario(ctx, 2)
    assert again.passed and again.prep_message is None
    manual = backend.run_manual_update(ctx, "1.3.0", tamper=True)
    assert manual.error is None and manual.word == REJECTED
    cut = backend.run_manual_update(ctx, "1.3.0", cut_at=32768)
    assert cut.word == "ABORTED" and backend.failed_step(cut.attempts[0]) == 6
    ok = backend.run_manual_update(ctx, "1.3.0")
    assert ok.word == INSTALLED and ctx.device.current_version == "1.3.0"


def test_ui_run_all(ctx):
    """Run-all tab: 10/10 on one device."""
    outcomes = backend.run_all(ctx)
    assert [o.passed for o in outcomes] == [True] * 10
    rows = [backend.summary_row(o, n) for o, n in zip(outcomes, range(1, 11))]
    assert all(r["Sonuç"] == "✅" for r in rows)
    assert ctx.device.current_version == "1.3.0"
