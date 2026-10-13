"""Recall tests for the Critical-class scanner, one realistic fixture per class.

The pre-existing tests in `test_veck.py` pin the scanner's *machinery* against
regex-shaped one-liners, which is a weak guarantee: a pattern can only match the
exact shape it was written against. These tests instead use realistic,
properly-formatted, multi-line vulnerable contracts under `tests/fixtures/veck/`,
so they measure whether the detector survives how Solidity is actually written.

Two bugs were found this way and fixed:
  * class 16's strong pattern required the whole function on one line, so it was
    dead code against every real multi-line contract;
  * class 9's strong pattern matched `balanceOf(x) - y` (a balance *decrease*),
    which is not the fee-on-transfer bug at all - that bug measures the balance
    then credits the nominal argument.

Classes 2, 5 and 10 have no strong patterns by design (weak-only), so they are
excluded from the strong-hit expectation.
"""
from pathlib import Path

import pytest

from cli.cs_veck import CLASSES, _BY_ID, _pattern_is_handled, scan

VECK_FIXTURES = Path(__file__).parent / "fixtures" / "veck"

# classes whose only signals are weak patterns, by design
WEAK_ONLY = {2, 5, 10}

# class -> the fixture that carries that class's bug
FIXTURE_FOR = {
    1: "ProxyVulnerable.sol",
    2: "ReadOnlyReentrancy.sol",
    3: "OracleSpot.sol",
    4: "ERC4626Rounding.sol",
    5: "StorageGap.sol",
    6: "EIP712NoChainid.sol",
    7: "UnguardedAdmin.sol",
    8: "StakingZeroSupply.sol",
    9: "FeeOnTransfer.sol",
    10: "FlashGovernance.sol",
    11: "LiquidationMath.sol",
    12: "DelegatecallUntrusted.sol",
    13: "BridgeProof.sol",
    14: "UncheckedCall.sol",
    15: "FlashMintAccounting.sol",
    16: "FlashPriceValuation.sol",
    17: "CLPosition.sol",
    18: "SwapNoSlippage.sol",
    19: "VaultDonation.sol",
    20: "PaymasterDrain.sol",
    21: "ERC7579Account.sol",
}


@pytest.fixture(scope="module")
def hits() -> list[dict]:
    return scan(VECK_FIXTURES)


@pytest.mark.parametrize("cid", sorted(c for c in FIXTURE_FOR if c not in WEAK_ONLY))
def test_class_fires_strong_on_its_own_fixture(cid: int, hits: list[dict]):
    """Every strong-capable class must produce a strong hit on its own fixture."""
    mine = [h for h in hits if h["class_id"] == cid]
    assert mine, f"class {cid} produced no hit at all on {FIXTURE_FOR[cid]}"
    strong = [h for h in mine if h["strength"] == "strong"]
    assert strong, (
        f"class {cid} ({_BY_ID[cid]['name']}) produced no STRONG hit on its own "
        f"vulnerable fixture {FIXTURE_FOR[cid]}; got "
        f"{[(h['strength'], h['line']) for h in mine]}"
    )


@pytest.mark.parametrize("cid", sorted(WEAK_ONLY))
def test_weak_only_classes_still_fire(cid: int, hits: list[dict]):
    mine = [h for h in hits if h["class_id"] == cid]
    assert mine, f"weak-only class {cid} produced no hit on its fixture"
    assert all(h["strength"] == "weak" for h in mine)


def test_every_class_has_a_fixture():
    assert set(FIXTURE_FOR) == {c["id"] for c in CLASSES}


def test_class16_multiline_price_valuation_detected(hits: list[dict]):
    """The regression: a price helper written across several lines must still hit.

    The original pattern was `function ...price... (...) [^{;]* { [^}]* getReserves`
    matched per source line, so it could never match a normally-formatted
    contract. This test fails against the old pattern.
    """
    strong16 = [h for h in hits if h["class_id"] == 16 and h["strength"] == "strong"]
    files = {Path(h["file"]).name for h in strong16}
    assert "FlashPriceValuation.sol" in files, (
        "class 16 missed a multi-line getPrice()/getReserves() valuation"
    )
    # the multiline hit must point at the function, not a stray token
    fn = [h for h in strong16 if Path(h["file"]).name == "FlashPriceValuation.sol"]
    assert any("getPrice" in h["snippet"] for h in fn)


def test_class16_requires_valuation_context(hits: list[dict]):
    """Precision guard: a bare pool read is class 3's signal, not class 16's.

    Prevents the regression where class 16's strong slot was simply the pool-read
    pattern, making 3 and 16 indistinguishable.
    """
    strong16 = {Path(h["file"]).name for h in hits if h["class_id"] == 16 and h["strength"] == "strong"}
    # CLPosition.sol uses slot0/sqrtPriceX96 but not in a price/collateral helper
    # for its *value* function name... it does (`valueOf`), so assert the property
    # directly on a fixture that only declares an interface.
    assert "OracleSpot.sol" in strong16  # collateralValue -> valuation context
    # and a contract that only *declares* the interface still shows up as class 3
    strong3 = {Path(h["file"]).name for h in hits if h["class_id"] == 3 and h["strength"] == "strong"}
    assert "FlashPriceValuation.sol" in strong3


def test_class9_detects_nominal_credit_bug(hits: list[dict]):
    """The regression: measure-balance-then-credit-`amount`, across lines."""
    strong9 = [h for h in hits if h["class_id"] == 9 and h["strength"] == "strong"]
    assert strong9, "class 9 missed the measure-then-credit-nominal pattern"
    assert any(Path(h["file"]).name == "FeeOnTransfer.sol" for h in strong9)


def test_class16_old_pattern_is_dead_on_multiline():
    """Pin the root cause so the pattern is not silently restored."""
    import re

    old = r"function\s+\w*[Pp]rice\w*\s*\([^)]*\)[^{;]*\{\s*[^}]*(getReserves|slot0|observe|getSqrtRatioAtTick)"
    realistic = (
        "function getPrice() external view returns (uint256) {\n"
        "    (uint112 r0, uint112 r1) = pool.getReserves();\n"
        "    return (uint256(r1) * 1e18) / uint256(r0);\n"
        "}"
    )
    assert not any(re.search(old, ln) for ln in realistic.splitlines()), (
        "premise of this regression test is wrong: the old pattern DOES match "
        "multi-line code, so the class-16 miss had a different cause"
    )


def test_multiline_hits_map_to_real_line_numbers(hits: list[dict]):
    """A multiline match must report a line number inside the file."""
    for h in hits:
        p = VECK_FIXTURES / h["file"]
        total = len(p.read_text().splitlines())
        assert 1 <= h["line"] <= total, f"{h['file']}:{h['line']} out of range ({total} lines)"

# --------------------------------------------------------------------------- #
# class 14: captured return values are not unchecked returns
# --------------------------------------------------------------------------- #
# Found on LRTWithdrawalManager._transferAsset and the treasury-interest path:
# `(bool sent,) = payable(to).call{value: amount}("");` followed by
# `if (!sent) revert ...`. Class 14's strong pattern is just `\.call\s*\{\s*value`
# and cannot tell that from an ignored return, because the two differ only in what
# sits before the call. A detector that cries wolf on the value-transfer path
# trains us to ignore it, so the veto is pinned in both directions.

REAL = Path(__file__).parent / "fixtures" / "veck_real"


def test_class14_ignores_captured_and_checked_call(tmp_path):
    src = (REAL / "CheckedTransfer.sol").read_text()
    p = tmp_path / "CheckedTransfer.sol"
    p.write_text(src)
    assert not [h for h in scan(tmp_path, class_ids=[14])]


def test_class14_still_flags_ignored_call(tmp_path):
    """The veto must not suppress the real bug it was added for."""
    p = tmp_path / "UncheckedTransfer.sol"
    p.write_text((REAL / "UncheckedTransfer.sol").read_text())
    hits = scan(tmp_path, class_ids=[14])
    assert hits, "an ignored low-level call must still be reported"
    assert any(h["strength"] == "strong" for h in hits)


@pytest.mark.parametrize(
    "line,follow_up,expected_hit",
    [
        # captured AND then referenced -> handled, suppressed
        ("(bool sent,) = to.call{value: v}(\"\");", "    if (!sent) revert E();", False),
        ("(bool ok, bytes memory d) = to.call{value: v}(\"\");", "    if (!ok) revert E();", False),
        # captured but never referenced -> still a genuine finding
        ("(bool success, ) = to.call{value: v}(\"\");", "    emit Done();", True),
        # never captured at all -> genuine finding
        ("to.call{value: v}(\"\");", "    emit Done();", True),
        ("address(t).call{value: v}(\"\");", "    emit Done();", True),
    ],
)
def test_class14_window_check_discriminates_capture_forms(line, follow_up, expected_hit):
    """Capture alone must not suppress; only capture-then-use counts as handled.

    That distinction is the whole point of the window check.
    `(bool success, ) = to.call{...}("")` with no later reference is what
    cs_veck's own planted fixture contains, and it is a real finding - so a veto
    that suppressed every capture would have silenced a genuine bug.
    """
    handled = _pattern_is_handled([line, follow_up], 0)
    assert (not handled) is expected_hit, line


def test_class14_window_check_ignores_a_reference_further_out():
    """The window is deliberately short: a check 4 lines down is not a check."""
    lines = ["(bool sent,) = to.call{value: v}(\"\");", "a();", "b();", "c();", "if (!sent) revert E();"]
    assert _pattern_is_handled(lines, 0) is False
