"""Tests for the Intigriti module's field honesty.

Three real falsifications were fixed in this module, all of the kind that
quietly produce a confident wrong answer:

  1. EUR/GBP bounties multiplied by a hardcoded 1.05/1.25 and reported as USD.
     140 of 188 Intigriti programs quote EUR, so this mis-ranked most of the
     platform against USD-denominated thresholds on other platforms.
  2. `reports` hardcoded to 0 for every program - which fabricates a perfect
     thin-hunt signal platform-wide. This is strictly worse than the Starknet
     case (27 real reports that merely misled), because it was manufactured.
  3. `sc` hardcoded to False, implying "not a smart contract" where the API
     simply does not publish scope type.
"""
import pytest

from cli.cs_intigriti import _row


def _p(**kw):
    base = {"name": "X", "handle": "x", "companyHandle": "x", "programId": "id", "status": 3}
    base.update(kw)
    return base


def test_eur_bounty_is_not_converted_to_usd():
    r = _row(_p(maxBounty={"value": 4000.0, "currency": "EUR"}))
    assert r["max_bounty"] == 4000.0        # native value, untouched
    assert r["currency"] == "EUR"
    assert r["max_bounty_usd"] is None       # no invented rate


def test_usd_bounty_populates_usd_field():
    r = _row(_p(maxBounty={"value": 250000.0, "currency": "USD"}))
    assert r["max_bounty_usd"] == 250000.0
    assert r["currency"] == "USD"


def test_missing_bounty_is_zero_not_a_guess():
    r = _row(_p())
    assert r["max_bounty"] == 0.0
    assert r["currency"] is None
    assert r["max_bounty_usd"] is None


def test_reports_is_unknown_not_zero():
    """The dangerous one: 0 would read as 'nobody ever reported here'."""
    r = _row(_p())
    assert r["reports"] is None


def test_scope_type_is_unknown_not_false():
    r = _row(_p())
    assert r["sc"] is None


def test_audit_status_never_claims_unaudited():
    assert _row(_p())["audit_status"] == "unknown"


def test_row_carries_tac_and_status():
    r = _row(_p(status=3, tacRequired=True, twoFactorRequired=True))
    assert r["tac_required"] is True
    assert r["two_factor"] is True
    assert r["status"] == "Active"
    r2 = _row(_p(status=1))
    assert r2["status"] == "Paused"


def test_bounty_takes_currency_from_min_when_max_absent():
    r = _row(_p(minBounty={"value": 50.0, "currency": "GBP"}))
    assert r["currency"] == "GBP"
    assert r["min_bounty"] == 50.0
