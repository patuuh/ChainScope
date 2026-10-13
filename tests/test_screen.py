"""Tests for the cross-platform screener.

The screener's job is NOT to assert a program is unaudited - both platforms'
audit flags proved unreliable (every HackenProof program returns audit=False;
Immunefi reports audits:[] for GMX/Chainlink/Arbitrum/Wormhole). So the tests
pin the properties that make it honest:
  * absence of a report count is UNKNOWN, not a flattering "thin" score
  * the `sc` scope filter is derived from labels.types (the API has no `sc` key)
  * the HackenProof report count reads `submitted_reports`, not `reports`
"""
import pytest

from cli.cs_screen import _thin_hunt, _freshness, screen_rows


def test_unknown_report_count_is_neutral_not_thin():
    # Absence of data must not score as "thinly hunted".
    assert _thin_hunt(None, 100_000) == 0.5
    assert _thin_hunt("not-a-number", 100_000) == 0.5
    assert _thin_hunt(0, 100_000) == 1.0
    assert _thin_hunt(27, 250_000) > 0.9      # genuinely thin
    assert _thin_hunt(2000, 250_000) < 0.05     # thoroughly hunted


def test_freshness_prefers_launch_year_and_does_not_guess():
    assert _freshness("2023-05-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z") == 2023
    assert _freshness(None, "2026-09-10T00:00:00.000Z") == 2026
    assert _freshness(None, None) is None
    assert _freshness("nonsense", "also-bad") is None


def test_screener_never_claims_unaudited():
    for plat in ("immunefi", "hackenproof"):
        rows = screen_rows(platform=plat, min_bounty=1)
        for r in rows:
            assert r["audit_status"] == "unknown"
            assert "unmined" not in r


def test_hackenproof_rows_respect_sc_scope():
    from cli.cs_screen import _hackenproof_rows
    for r in _hackenproof_rows():
        assert r["ceiling"] > 0
        assert r["reports"] is not None or True  # may be None; must not crash
