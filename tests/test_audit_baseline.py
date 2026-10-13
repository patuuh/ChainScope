"""Tests for the external audit-corpus baseline (core/cs_audit_baseline.py).

Offline: the GitHub tree fetch is exercised through the ``opener`` seam, so no
test touches the network.
"""

from __future__ import annotations

import json

import pytest

from core.cs_audit_baseline import (
    baseline,
    corpus_for,
    fetch_entries,
    matches_scope,
    parse_pdf_name,
    summarise,
)

_FIXTURE_TREE = {
    "tree": [
        {"type": "blob", "path": "Statemind Lido CSM v3 and CM v2 Audit Report 06-2026.pdf"},
        {"type": "blob", "path": "Certora Lido CSM v3 and CM v2 Audit Report - 06-2026.pdf"},
        {"type": "blob", "path": "MixBytes Lido CSM Security Audit Report 07-2025.pdf"},
        {"type": "blob", "path": "Code4rena CSM V2 Audit Report 08-2025.pdf"},
        {"type": "blob", "path": "Composable Security Lido Oracle V7_1 Audit Report.pdf"},
        {"type": "blob", "path": "Statemind Dual Governance Audit Report 10-2024.pdf"},
        {"type": "tree", "path": "some/dir"},
        {"type": "blob", "path": "README.md"},
    ]
}


def _opener(url: str, timeout: float) -> str:
    assert timeout > 0
    return json.dumps(_FIXTURE_TREE)


class TestParsePdfName:
    def test_firm_date_and_scope(self) -> None:
        e = parse_pdf_name("Statemind Lido CSM v3 and CM v2 Audit Report 06-2026.pdf")
        assert e.firm == "Statemind"
        assert e.date == "2026-06"
        assert e.scope == "Lido CSM v3 and CM v2"

    def test_multi_word_firm_wins_over_prefix(self) -> None:
        e = parse_pdf_name("Composable Security Lido Oracle V7 Audit Report.pdf")
        assert e.firm == "Composable Security"
        assert e.scope.startswith("Lido Oracle")

    def test_sigma_prime_with_version_noise(self) -> None:
        e = parse_pdf_name("Sigma Prime - Lido - dc4bc Security Assessment Report - v2.2 03-2023.pdf")
        assert e.firm == "Sigma Prime"
        assert e.date == "2023-03"

    def test_two_digit_year_normalised(self) -> None:
        e = parse_pdf_name("MixBytes Lido CSM Security Audit Report 10-24.pdf")
        assert e.date == "2024-10"

    def test_version_identifiers_survive(self) -> None:
        e = parse_pdf_name("Composable Security Lido Oracle V5_2 06-25.pdf")
        assert e.scope == "Lido Oracle V5_2"
        assert e.date == "2025-06"

    def test_underscore_delimited_convention(self) -> None:
        e = parse_pdf_name("MixBytes_Lido_CSM_Security_Audit_Report_07-2025.pdf")
        assert e.firm == "MixBytes"
        assert e.date == "2025-07"
        assert "CSM" in e.scope

    def test_unparseable_never_raises_and_is_kept(self) -> None:
        e = parse_pdf_name("mystery.pdf")
        assert e.firm == ""
        assert e.date == ""
        assert e.path == "mystery.pdf"

    def test_impossible_month_rejected(self) -> None:
        e = parse_pdf_name("MixBytes Something 13-2026 Report.pdf")
        assert e.date == ""


class TestFetchEntries:
    def test_only_pdfs_listed_newest_first(self) -> None:
        entries = fetch_entries("lidofinance/audits", opener=_opener)
        assert len(entries) == 6  # 6 pdfs; tree and .md excluded
        assert all(e.path.lower().endswith(".pdf") for e in entries)
        dates = [e.date for e in entries]
        assert dates == sorted(dates, reverse=True)

    def test_urls_built(self) -> None:
        entries = fetch_entries("lidofinance/audits", opener=_opener)
        assert entries[0].url.startswith("https://github.com/lidofinance/audits/blob/main/")

    def test_bad_payload_raises(self) -> None:
        def opener(url: str, timeout: float) -> str:
            return json.dumps({"message": "Not Found"})

        with pytest.raises(RuntimeError):
            fetch_entries("nope/nope", opener=opener)


class TestScopeMatching:
    def test_multi_term_query(self) -> None:
        e = parse_pdf_name("Statemind Lido CSM v3 and CM v2 Audit Report 06-2026.pdf")
        assert matches_scope(e, "CSM v3")
        assert not matches_scope(e, "dual governance")

    def test_empty_query_matches_everything(self) -> None:
        e = parse_pdf_name("anything.pdf")
        assert matches_scope(e, "")


class TestBaseline:
    def test_registered_program_resolves_corpus(self) -> None:
        assert corpus_for("lido") == "lidofinance/audits"
        assert corpus_for("Lido") == "lidofinance/audits"

    def test_unregistered_program_is_not_ok(self) -> None:
        result = baseline("some-unknown-program")
        assert result["ok"] is False
        assert result["total_reports"] == 0

    def test_scope_filter_and_multi_firm_verdict(self) -> None:
        result = baseline("lido", scope_query="CSM", opener=_opener)
        assert result["ok"] is True
        assert result["total_reports"] == 6
        # CSM entries: Statemind+Certora CSM v3/CM v2, MixBytes CSM, Code4rena CSM V2
        assert len(result["matching"]) == 4
        assert set(result["firms"]) == {"Statemind", "Certora", "MixBytes", "Code4rena"}
        assert "likely ineligible" in result["verdict"]

    def test_since_filters_by_date(self) -> None:
        result = baseline("lido", scope_query="CSM", since="2026-01", opener=_opener)
        assert all(r["date"] >= "2026-01" for r in result["matching"])
        assert len(result["matching"]) == 2  # the two 06-2026 reports

    def test_explicit_repo_overrides_registry(self) -> None:
        result = baseline("whatever", repo="acme/audits", opener=_opener)
        assert result["repo"] == "acme/audits"
        assert result["ok"] is True

    def test_no_match_says_so(self) -> None:
        result = baseline("lido", scope_query="nonexistentscope", opener=_opener)
        assert result["matching"] == []
        assert "no report" in result["verdict"]


class TestSummarise:
    def test_renders_rows_and_verdict(self) -> None:
        out = summarise(baseline("lido", scope_query="CSM", opener=_opener))
        assert "lidofinance/audits" in out
        assert "Statemind" in out
        assert "verdict" in out

    def test_unavailable_is_readable(self) -> None:
        assert "unavailable" in summarise(baseline("nope-nope"))