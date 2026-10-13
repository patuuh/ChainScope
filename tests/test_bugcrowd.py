"""Tests for the Bugcrowd program module.

Bugcrowd's catalog is unusually thin on metadata, and the bugs that bit me
elsewhere this session were all about *inferring* fields that do not exist.
So these tests pin two things:

  1. reward parsing takes the UPPER bound across every shape Bugcrowd emits
  2. the module never claims coverage/rep/fee it cannot see

No network calls: `_load` is stubbed throughout.
"""
import pytest

from cli.cs_bugcrowd import _money, _row


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("$150 - $5,000", 5000.0),      # range -> ceiling, not the floor
        ("Up to $5,000", 5000.0),
        ("$5,000", 5000.0),
        ("Points - $3,000", 3000.0),
        ("$20 - $12,000", 12000.0),
        ("", 0.0),
        (None, 0.0),
        ("TBD", 0.0),
    ],
)
def test_money_takes_upper_bound(raw, expected):
    assert _money(raw) == expected


def test_money_accepts_numeric():
    assert _money(25000) == 25000.0
    assert _money(25000.0) == 25000.0


def test_row_normalises_catalog_entry():
    r = _row({
        "name": "Wyze Bug Bounty",
        "briefUrl": "/engagements/wyze",
        "rewardSummary": {"summary": "$50 - $5,000", "minReward": "$50", "maxReward": "$5,000"},
        "scopeRank": 1,
        "accessStatus": "open",
        "isBanned": False,
        "isDemo": False,
        "isPrivate": False,
        "serviceLevel": "Platform",
        "productEngagementType": {"label": "Bug Bounty"},
        "industryName": "Electronics",
    })
    assert r["slug"] == "wyze"
    assert r["project"] == "Wyze Bug Bounty"
    assert r["max_bounty"] == 5000.0
    assert r["min_bounty"] == 50.0
    assert r["scope_rank"] == 1
    assert r["url"] == "https://bugcrowd.com/engagements/wyze"


def test_row_never_invents_metadata_bugcrowd_does_not_publish():
    """The core anti-lesson: unknown, not a guess."""
    r = _row({"name": "X", "briefUrl": "/engagements/x", "rewardSummary": {}})
    assert r["rep_req"] is None      # Bugcrowd has no public rep gate
    assert r["fee"] is None          # no public fee field
    assert r["reports"] is None      # no public report count
    assert r["audit_status"] == "unknown"  # never assert "unaudited"
    assert r["poc"] is None


def test_row_handles_missing_summary():
    r = _row({"name": "Y", "briefUrl": "/engagements/y"})
    assert r["max_bounty"] == 0.0
    assert r["slug"] == "y"
