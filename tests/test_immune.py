"""Tests for the Immunefi program module (`cli/cs_immune.py`).

The parser targets Immunefi's React Server Component payload, which is an
escaped JS string literal rather than JSON. These tests pin the behaviours
that were hard-won against the live site:

  * unescaping the RSC payload back into ordinary JSON
  * reading scalars out of a payload whose prose fields are not valid JSON
  * the reentrancy-relevant invariant in ``_checkProof``-style contracts is NOT
    tested here; this module only reads program metadata, it never executes.

Network calls are stubbed throughout so the suite stays hermetic.
"""
import json

import pytest

from cli.cs_immune import (
    MAX_SUBMITTABLE_BOUNTY_USD,
    MIN_MEDIUM_PAYOUT_USD,
    severity_floor,
    submit_eligibility,
    _program_status,
    _keizo,
    _audits,
    _catalog,
    _program_block,
    _row,
    _scalars,
    _scope,
    _unescape,
)

# A trimmed but structurally faithful copy of a real Immunefi program payload,
# including the two hazards found in the wild: a raw tab inside a string
# description and an invalid escape sequence ("\\g") in prose.
_SAMPLE_PAGE = (
    '<script>self.__next_f.push([1,"'
    '6:[\\"$\\",\\"$L35\\",null,{\\"bounty\\":{'
    '\\"contentfulId\\":\\"abc123\\",'
    '\\"slug\\":\\"aera\\",'
    '\\"project\\":\\"Aera\\",'
    '\\"url\\":\\"/bug-bounty/aera/information/\\",'
    '\\"maxBounty\\":500000,'
    '\\"launchDate\\":\\"2023-11-20T12:00:00.000Z\\",'
    '\\"updatedDate\\":\\"2026-09-18T15:24:46.333Z\\",'
    '\\"kyc\\":true,'
    '\\"networkType\\":\\"mainnet\\",'
    '\\"proofOfConceptType\\":\\"required\\",'
    '\\"primacy\\":\\"primacy_of_rules\\",'
    '\\"pausedAt\\":null,'
    '\\"audits\\":['
    '{\\"id\\":\\"1\\",\\"url\\":\\"https://cantina.io/x\\",\\"date\\":\\"2025-06-25\\",'
    '\\"auditor\\":\\"Cantina Competition\\"},'
    '{\\"id\\":\\"2\\",\\"url\\":\\"https://github.com/o/r/blob/main/a.pdf\\",\\"date\\":\\"2023-09-22\\",'
    '\\"auditor\\":\\"Spearbit\\"}'
    '],'
    '\\"assets\\":['
    '{\\"addedAt\\":\\"2026-09-18T15:24:46.186Z\\",\\"description\\":\\"\\\\tgtBTC (Ethereum) - MultiDepositorVault\\"},'
    '{\\"addedAt\\":\\"2025-08-13T00:00:00.000Z\\",\\"description\\":\\"OUSD Vault\\"}'
    '],'
    '\\"knownIssues\\":[]'
    '}}]\\n"])'
    "</script>"
)


def test_unescape_converts_rsc_escapes():
    text = _unescape('\\"bounty\\":{\\"slug\\":\\"aera\\"}')
    assert '"bounty":{"slug":"aera"}' in text


def test_unescape_preserves_json_escapes_inside_strings():
    # A valid \" inside a string value must survive, not be collapsed.
    text = _unescape('\\"url\\":\\"https://x/y\\"')
    assert '"url":"https://x/y"' in text


def test_scalars_reads_string_number_bool():
    seg = (
        '{"slug":"aera","project":"Aera","maxBounty":500000,'
        '"kyc":true,"pausedAt":null,"reductionPercentage":100}'
    )
    assert _scalars(seg, "slug") == "aera"
    assert _scalars(seg, "project") == "Aera"
    assert _scalars(seg, "maxBounty") == 500000
    assert _scalars(seg, "kyc") is True
    assert _scalars(seg, "pausedAt") is None
    assert _scalars(seg, "reductionPercentage") == 100


def test_scalars_missing_key_is_none():
    assert _scalars('{"a":1}', "nonexistent") is None


def test_scalars_does_not_match_key_inside_prose():
    # "maxBounty" appears only as prose, not as a key, so it must not be read.
    seg = '{"description":"the maxBounty field is discussed","maxBounty":42}'
    assert _scalars(seg, "maxBounty") == 42


def test_program_block_parses_real_shape():
    obj = _program_block(_SAMPLE_PAGE, "aera")
    assert obj is not None
    assert obj["slug"] == "aera"
    assert obj["project"] == "Aera"
    assert obj["maxBounty"] == 500000
    assert obj["kyc"] is True
    assert obj["proofOfConceptType"] == "required"
    assert obj["primacy"] == "primacy_of_rules"
    assert obj["networkType"] == "mainnet"


def test_program_block_tolerates_invalid_escapes_in_prose():
    # The sample embeds a raw tab and "\\g" in a description. Strict json.loads
    # on the whole object fails; field extraction must still succeed.
    assert len(_program_block(_SAMPLE_PAGE, "aera")["slug"]) > 0


def test_program_block_extracts_audits():
    audits = _program_block(_SAMPLE_PAGE, "aera")["audits"]
    assert len(audits) == 2
    assert audits[0]["auditor"] == "Cantina Competition"
    assert audits[0]["date"] == "2025-06-25"
    assert audits[1]["auditor"] == "Spearbit"


def test_program_block_counts_empty_known_issues_as_zero():
    assert _program_block(_SAMPLE_PAGE, "aera")["knownIssues"] == 0


def test_program_block_returns_none_without_bounty_marker():
    assert _program_block('<html>nothing here</html>', "aera") is None


def test_row_normalises_fields():
    obj = _program_block(_SAMPLE_PAGE, "aera")
    row = _row({**obj, "_slug": "aera"})
    assert row["slug"] == "aera"
    assert row["max_bounty"] == 500000.0
    assert row["kyc"] is True
    assert row["poc"] is True
    assert row["audits"] == 2
    assert row["known_issues"] == 0
    assert row["updated_date"] == "2026-09-18"
    assert "aera" in row["url"]


def test_scope_maps_explorer_hosts_to_chain_ids(monkeypatch):
    page = (
        '<a href="https://etherscan.io/address/0x3bd9248048df95Db4fBD748C6CD99C1bAa40bAD0">x</a>'
        '<a href="https://basescan.org/address/0x000000000001CdB57E58Fa75Fe420a0f4D6640D5">y</a>'
        '<a href="https://github.com/aera-finance/contracts">repo</a>'
    )
    monkeypatch.setattr("cli.cs_immune._get", lambda url, timeout=45: page)
    scope = _scope("aera")
    chains = {a["chain"] for a in scope["addresses"]}
    assert "1" in chains          # etherscan -> mainnet
    assert "8453" in chains       # basescan -> base
    assert len(scope["addresses"]) == 2
    assert any("aera-finance" in r for r in scope["repos"])


def test_scope_deduplicates_same_address_across_explorers(monkeypatch):
    # Same address, different case, listed on two explorers: one entry, and the
    # first host seen wins (mainnet before base, per document order).
    page = (
        '<a href="https://etherscan.io/address/0x3bd9248048df95Db4fBD748C6CD99C1bAa40bAD0">a</a>'
        '<a href="https://basescan.org/address/0x3BD9248048DF95DB4FBD748C6CD99C1BAA40BAD0">b</a>'
    )
    monkeypatch.setattr("cli.cs_immune._get", lambda url, timeout=45: page)
    addrs = _scope("aera")["addresses"]
    assert len(addrs) == 1
    assert addrs[0]["chain"] == "1"


def test_scope_skips_non_blockchain_hosts(monkeypatch):
    page = (
        '<a href="https://immunefi.com/token/0x3bd9248048df95Db4fBD748C6CD99C1bAa40bAD0">x</a>'
        '<a href="https://app.originprotocol.com/address/0xE75D77B1865Ae93c7eaa3040B038D7aA7BC02F70">y</a>'
    )
    monkeypatch.setattr("cli.cs_immune._get", lambda url, timeout=45: page)
    assert _scope("aera")["addresses"] == []


def test_catalog_drops_navigation_slugs(monkeypatch):
    page = (
        '/bug-bounty/aera/ /bug-bounty/aave/ /bug-bounty/list/ '
        '/bug-bounty/information/ /bug-bounty/some-program/'
    )
    monkeypatch.setattr("cli.cs_immune._get", lambda url, timeout=45: page)
    slugs = _catalog()
    assert "aera" in slugs and "some-program" in slugs
    assert "list" not in slugs
    assert "information" not in slugs


# --- reward-tier parsing (regressions found 2026-09-30) -----------------------

def test_tiers_parses_up_to_format():
    from cli.cs_immune import _tiers
    seg = '{"level":"Critical","payout":"Up to USD $2,000,000"},{"level":"High","payout":"USD $100,000"}'
    t = _tiers(seg)
    assert t["Critical"]["payout"] == 2_000_000
    assert t["High"]["payout"] == 100_000


def test_tiers_takes_upper_bound_of_a_range():
    # Lombard publishes ranges; taking the floor would under-report 5x.
    from cli.cs_immune import _tiers
    seg = '{"level":"Critical","payout":"USD $50,000 - USD $250,000"}'
    t = _tiers(seg)
    assert t["Critical"]["floor"] == 50_000
    assert t["Critical"]["payout"] == 250_000


def test_tiers_prefers_later_list_over_legacy():
    # legacy list is listed first and is stale; last-wins is correct.
    from cli.cs_immune import _tiers
    seg = (
        '{"level":"Critical","payout":"USD $15,000 to USD $30,000"}'
        '{"level":"Critical","payout":"USD $50,000 - USD $250,000"}'
    )
    t = _tiers(seg)
    assert t["Critical"]["payout"] == 250_000


def test_row_ceiling_is_maxbounty_not_stale_tier_array():
    # Regression (2026-09-30): Celer's payload carries a stale
    # `smartcontract_rewards` array claiming 2,000,000 while the live program
    # page says Critical = 200,000, which is what maxBounty reports. Trusting
    # the tier array over-reported the ceiling 10x and mis-ranked the target.
    from cli.cs_immune import _row
    row = _row({
        "_slug": "x", "maxBounty": 200_000, "primacy": "primacy_of_rules",
        "audits": [], "knownIssues": "[]", "updatedDate": "2026-09-09T00:00:00.000Z",
        "_seg": '"smartcontract_rewards":[{"level":"Critical","payout":"Up to USD $2,000,000"}]',
    })
    assert row["max_bounty"] == 200_000        # authoritative field wins
    assert row["critical_payout_stale"] is True # implausible tier claim rejected


def test_row_keeps_plausible_tier_claim():
    from cli.cs_immune import _row
    row = _row({
        "_slug": "x", "maxBounty": 100_000, "primacy": "primacy_of_rules",
        "audits": [], "knownIssues": "[]", "updatedDate": "2026-09-09T00:00:00.000Z",
        "_seg": '{"level":"Critical","payout":"Up to USD $250,000"}',
    })
    assert row["max_bounty"] == 100_000
    assert row["critical_payout"] == 250_000   # within 4x, kept as cross-check


def test_row_exposes_per_tier_primacy():
    from cli.cs_immune import _row
    row = _row({
        "_slug": "x", "maxBounty": 1, "primacy": "primacy_of_rules",
        "audits": [], "knownIssues": "[]", "updatedDate": "2026-09-09T00:00:00.000Z",
        "_seg": (
            '{"level":"Critical","payout":"Up to USD $10,000"}'
            '"primacy":"primacy_of_impact","severity":"Critical"'
        ),
    })
    assert row["primacy_default"] == "primacy_of_rules"   # program default
    assert row["primacy_critical"] == "primacy_of_impact"  # tier override


# --- audit-evidence detection (2026-09-30) ---------------------------------
# The `audits[]` field records only whether a program populated a field, not
# whether it was reviewed. These pin the replacement signal.

def test_audit_evidence_detects_named_firm():
    from cli.cs_immune import _audit_evidence
    ev = _audit_evidence("", "the Paladin report is at github.com/x/audit-reports")
    assert ev["audit_evidence"] is True
    assert "paladin" in ev["audit_firms"]


def test_audit_evidence_detects_audit_url():
    from cli.cs_immune import _audit_evidence
    ev = _audit_evidence("", "see https://github.com/org/security-reports")
    assert ev["audit_evidence"] is True


def test_audit_evidence_absent_for_clean_page():
    from cli.cs_immune import _audit_evidence
    ev = _audit_evidence("", "a bridge with no external references at all")
    assert ev["audit_evidence"] is False
    assert ev["audit_firms"] == []


def test_audit_evidence_guardian_needs_audit_context():
    # Celer's product is the "State Guardian Network" - Guardian is an audit firm
    # too, so the bare word must not count.
    from cli.cs_immune import _audit_evidence
    ev = _audit_evidence("", "the State Guardian Network secures the bridge")
    assert "guardian" not in ev["audit_firms"]
    ev2 = _audit_evidence("", "Guardian audit report published by the team")
    assert "guardian" in ev2["audit_firms"]


def test_cache_version_invalidates_stale_row_shape(monkeypatch, tmp_path):
    # Regression (2026-09-30): the cache stored program dicts that predate the
    # `_seg`/`_raw` inputs added for audit evidence. On reload those keys are
    # absent, so evidence silently scored False and --verify-audits stopped
    # filtering. Cached rows from a different shape must be discarded.
    import json
    from cli import cs_immune as m
    cache = tmp_path / "c.json"
    cache.write_text(json.dumps({"programs": [{"_slug": "x", "maxBounty": 1}]}))
    monkeypatch.setattr(m, "_CACHE", cache)
    monkeypatch.setattr(m, "_catalog", lambda: [])
    # stale (no version key) -> nothing is treated as cached
    assert m._load(refresh=False) == []
    # current version -> reused
    cache.write_text(json.dumps({"version": m._CACHE_VERSION, "programs": [{"_slug": "x", "maxBounty": 1}]}))
    assert [p["_slug"] for p in m._load(refresh=False)] == ["x"]


# --------------------------------------------------------------------------- #
# program liveness
# --------------------------------------------------------------------------- #
# Scope reachability is not liveness. A paused program still lists repos and
# addresses and still fetches cleanly, so `scope` and `meta` look healthy for a
# program nobody is reporting to. Stakewise, Mux and Vesper each reached the
# front of a triage before being caught this way.

_PAUSED_BADGE = (
    '<svg width="48" height="48" viewBox="0 0 48 48"><path d="M0 24a24 24 0 1 1 48 0"></path></svg>'
    "Paused</span></div><div class=\"container\">"
)
_LIVE_PAGE = (
    '\\"pausedAt\\":null,\\"pausedMessage\\":null,\\"kyc\\":true,'
    '\\"launchDate\\":\\"2023-10-18T09:00:00.000Z\\",\\"endDate\\":null,'
)
_NULL_PAUSED_AT = '\\"pausedAt\\":null,'
_PAUSED_PAYLOAD = '\\"pausedAt\\":\\"2026-02-01T10:00:00.000Z\\",\\"pausedMessage\\":\\"paused\\"'


def test_status_detects_paused_badge():
    st = _program_status(_PAUSED_BADGE)
    assert st["status"] == "PAUSED"
    assert st["badge"] is True


def test_status_detects_paused_timestamp_in_payload():
    """Badge-less pages still carry a pausedAt timestamp, double-escaped."""
    mutated = _LIVE_PAGE.replace(_NULL_PAUSED_AT, _PAUSED_PAYLOAD)
    st = _program_status(mutated)
    assert st["status"] == "PAUSED"


def test_status_live_page_is_not_paused():
    assert _program_status(_LIVE_PAGE)["status"] == "LIVE"


def test_live_page_containing_pausedat_null_is_not_paused():
    """The trap: AAVE's live page contains the literal `pausedAt`, so a naive
    search for the word marks a live program paused."""
    page = _LIVE_PAGE
    assert "pausedAt" in page
    assert _program_status(page)["status"] == "LIVE"


def test_status_empty_page_is_unknown_not_live():
    """A failed read must not be reported as live - that is how a paused
    program gets targeted."""
    assert _program_status("")["status"] == "UNKNOWN"


def test_paused_program_cannot_rank():
    p = {"_slug": "mux", "status": {"status": "PAUSED"}, "maxBounty": 5_000_000,
         "updated": "2026-09-01", "bounty": {"maxBounty": 5_000_000, "primacy": "primacy_of_impact",
                                             "poc": "1", "kyc": "0", "assets": []}}
    row = _keizo(p, 1.0)
    assert row["keizo"] == 0.0
    assert row["signals"]["live"] is False
    assert row["status_code"] == "PAUSED"


def test_unknown_status_is_capped():
    p = {"_slug": "x", "status": {"status": "UNKNOWN"}, "maxBounty": 5_000_000,
         "updated": "2026-09-01", "bounty": {"maxBounty": 5_000_000, "primacy": "primacy_of_impact",
                                             "poc": "1", "kyc": "0", "assets": []}}
    assert _keizo(p, 1.0)["keizo"] <= 0.05


# --------------------------------------------------------------------------- #
# submission eligibility: $0 fee, pool <= $100k, and live
# --------------------------------------------------------------------------- #
# Two were lost to this before it was enforced: Sherlock 122 charges $250 to file
# a report (a real finding, unsubmittable), and Stacks carried a $250k pool we
# were never going to chase - and was Rust besides.

def _elig(**kw):
    base = {"status_code": "LIVE", "max_bounty": 40_000.0, "submission_fee_usd": 0}
    base.update(kw)
    return submit_eligibility(base)


def test_submittable_when_live_under_ceiling_and_free():
    e = _elig()
    assert e["submittable"] is True
    assert e["reasons"] == []


def test_paused_is_not_submittable():
    e = _elig(status_code="PAUSED")
    assert e["submittable"] is False
    assert "PAUSED" in e["reasons"]


def test_submission_fee_blocks():
    e = _elig(submission_fee_usd=250)
    assert e["submittable"] is False
    assert any("SUBMISSION_FEE" in r for r in e["reasons"])


def test_pool_over_ceiling_blocks():
    e = _elig(max_bounty=MAX_SUBMITTABLE_BOUNTY_USD * 10)
    assert e["submittable"] is False
    assert any("POOL_OVER" in r for r in e["reasons"])


def test_pool_exactly_at_ceiling_is_allowed():
    assert _elig(max_bounty=MAX_SUBMITTABLE_BOUNTY_USD)["submittable"] is True


def test_unknown_pool_is_not_submittable():
    """An unpriced program is not assumed affordable."""
    assert _elig(max_bounty=None)["submittable"] is False


def test_keizo_zeroes_ineligible_programs():
    p = {"_slug": "big", "status": {"status": "LIVE"}, "maxBounty": MAX_SUBMITTABLE_BOUNTY_USD * 5,
         "updated": "2026-09-01",
         "bounty": {"maxBounty": 250_000, "primacy": "primacy_of_impact",
                    "poc": "1", "kyc": "0", "assets": []}}
    row = _keizo(p, 1.0)
    assert row["keizo"] == 0.0
    assert row["submittable"] is False
    assert any("POOL_OVER" in r for r in row["submit_reasons"])


def test_keizo_keeps_score_for_eligible_program():
    p = {"_slug": "ok", "status": {"status": "LIVE"}, "maxBounty": 40_000,
         "updated": "2026-09-01",
         "bounty": {"maxBounty": 40_000, "primacy": "primacy_of_impact",
                    "poc": "1", "kyc": "0", "assets": []}}
    row = _keizo(p, 1.0)
    assert row["keizo"] > 0
    assert row["submittable"] is True


# --------------------------------------------------------------------------- #
# severity floor: where a Medium pays under $10k, only a Critical is worth it
# --------------------------------------------------------------------------- #

def test_severity_floor_crit_when_medium_cheap():
    r = severity_floor(MAX_SUBMITTABLE_BOUNTY_USD, 2_500.0)
    assert r["floor"] == "CRIT"
    assert "2,500" in r["reason"]
    assert r["crit_worth_chasing"] is True


def test_severity_floor_high_when_medium_pays_well():
    assert severity_floor(500_000.0, 40_000.0)["floor"] == "HIGH"


def test_severity_floor_unknown_without_tier_data():
    """A missing payout is not evidence of a small one."""
    r = severity_floor(None, None)
    assert r["floor"] == "UNKNOWN"
    assert r["crit_worth_chasing"] is False


def test_severity_floor_at_exactly_10k_is_high():
    assert severity_floor(MAX_SUBMITTABLE_BOUNTY_USD, MIN_MEDIUM_PAYOUT_USD)["floor"] == "HIGH"


def test_small_critical_is_not_worth_chasing():
    r = severity_floor(20_000.0, 1_000.0)
    assert r["floor"] == "CRIT"
    assert r["crit_worth_chashing"] if False else r["crit_worth_chasing"] is False


def test_ceiling_uses_critical_tier_not_maxbounty():
    """Regression: bobanetwork reports maxBounty under $100k but its Critical tier
    is $1,000,000. Comparing against maxBounty waves a real $1M target through on
    the wrong reasoning, and would block it outright if the tiers ever lined up
    the other way. The ceiling basis must be the top tier."""
    e = submit_eligibility({"status_code": "LIVE", "submission_fee_usd": 0,
                            "max_bounty": 100_000.0,
                            "critical_payout": MAX_SUBMITTABLE_BOUNTY_USD * 2})
    assert e["submittable"] is False
    assert e["ceiling_basis"] == MAX_SUBMITTABLE_BOUNTY_USD * 2
    assert any("POOL_OVER" in r for r in e["reasons"])
