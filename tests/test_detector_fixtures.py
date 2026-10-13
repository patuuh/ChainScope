"""Validation fixtures for the non-deployment detectors.

Same purpose as test_detector_validation.py: each detector gets a **known positive**
(ground truth says it must fire) and **known negatives** (ground truth says it must
stay silent), so a detector that drifts fails the build instead of producing another
plausible wrong number.

Ordered by how much damage each caused:

* class 20 / class 11 - reported 273 and 137 "strong" hits that were entirely
  canonical identifier names. M5's deletion was the same failure at its worst: 101
  getters.
* R1 - three of its own tests passed vacuously before the helper was caught
  scanning the wrong class.
* M1 / M3 - four precision iterations before either behaved.
* R2 - a fixture that passed while testing the wrong thing.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest

from cli.cs_move import scan as move_scan
from cli.cs_rust import scan as rust_scan
from cli.cs_veck import scan as veck_scan


def _scan(tmp_path, scanner, code: str, classes: list[int] | None = None, name: str = "T.move"):
    """Scan a single-file source through a detector.

    The detectors take a Path and rglob it, so a string is not enough - an early
    version of this file passed a StringIO and every assertion passed vacuously
    because nothing was ever scanned. That is the fourth time this session a test
    that looked green was testing nothing.
    """
    (tmp_path / name).write_text(code)
    return scanner(tmp_path, classes) if classes else scanner(tmp_path)


# =====================================================================  M1
# dynamic field written under a caller-supplied key.

M1_POSITIVE = """
contract Vault {
    import_dummy;
    public fun record(pool: &mut Pool, k: String, value: u64) {
        dynamic_field::add(&mut pool.id, k, value);
    }
}
"""

M1_NEGATIVE_DERIVED_KEY = """
contract Vault {
    struct Key has copy, drop, store { tag: u64 }
    public fun record(pool: &mut Pool) {
        dynamic_field::add(&mut pool.id, Key { tag: 7 }, 1);
    }
}
"""

M1_NEGATIVE_FRESH_PARENT = """
contract Vault {
    public fun create(k: String, v: u64, ctx: &mut TxContext) {
        let mut self = Vault { id: object::new(ctx) };
        dynamic_field::add(&mut self.id, k, v);
    }
}
"""

M1_NEGATIVE_READONLY = """
contract Reader {
    public fun peek(pool: &mut Pool, k: String): u64 {
        dynamic_field::exists_(&pool.id, k)
    }
}
"""


# =====================================================================  M3
# capability handed out without freezing.

M3_POSITIVE = """
module m::bad {
    use sui::package::UpgradeCap;
    use sui::transfer;
    public fun grant_upgrade_cap(cap: UpgradeCap, to: address) {
        transfer::public_transfer(cap, to);
    }
}
"""

M3_NEGATIVE_FROZEN = """
module m::good {
    use sui::package::UpgradeCap;
    use sui::transfer;
    public fun lock(cap: UpgradeCap) {
        transfer::public_transfer(cap, @0x0);
        cap.into_immutable();
    }
}
"""

M3_NEGATIVE_NO_CAP = """
module m::unrelated {
    use sui::transfer;
    public fun move_coin(coin: Coin<SUI>, to: address) {
        transfer::public_transfer(coin, to);
    }
}
"""


# =====================================================================  R1
# debug_assert standing in for an enforcement.

R1_POSITIVE = """
// Solana/Anchor syntax: cs_rust scans Rust `fn`, not Solidity `function`.
mod c {
pub fn ensure_sync(id: u64) {
        let tracked = Supply::get(id);
        let total = Supply::total(id);
        debug_assert_eq!(tracked, total, "out of sync");
    }
}
"""

R1_NEGATIVE_ENSURED = """
mod c {
    pub fn ensure_sync(id: u64) {
        let tracked = Supply::get(id);
        let total = Supply::total(id);
        ensure!(tracked == total, Errors::OutOfSync);
        debug_assert_eq!(tracked, total, "out of sync");
    }
}
"""

R1_NEGATIVE_UNREACHABLE_ARM = """
mod c {
    pub fn handle(x: u64) {
        if x > 0 {{ doThing(); }} else {{
            debug_assert!(false, "unreachable");
        }}
    }
}
"""

R1_NEGATIVE_SATURATING_GUARD = """
mod c {
    pub fn rate(uint b) {
        debug_assert!(b > 0, "Block difference cannot be zero");
        let r = x.saturating_div(b);
    }
}
"""


# =====================================================================  R2
# share price from a raw balance.

R2_POSITIVE = """
mod v {
    fn shares() -> u256 {
        let supply = total_supply();
        let assets = self.balance();
        assets.checked_div(supply).unwrap_or_default()
    }
}
"""

R2_NEGATIVE_VIRTUAL_OFFSET = """
mod v {
    uint256 constant VIRTUAL_SHARES = 1;
    uint256 constant VIRTUAL_VALUE = 1;
    fn shares() -> u256 {
        let supply = total_supply() + VIRTUAL_SHARES;
        let assets = token.balanceOf(address(this)) + VIRTUAL_VALUE;
        assets.checked_div(supply).unwrap_or_default()
    }
}
"""

R2_NEGATIVE_FIRST_DEPOSITOR_GUARD = """
mod v {
    fn shares() -> u256 {
        let supply = total_supply();
        if (supply == 0) { return amount; }
        let assets = self.balance();
        assets.checked_div(supply).unwrap_or_default()
    }
}
"""


# =====================================================================  class 20
# ERC-4337 paymaster gas accounting.

C20_POSITIVE = """
contract GaslessPaymaster {
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint128 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        return (abi.encode(userOpHash), 0);
    }
}
"""

C20_NEGATIVE_OWN_ENTRYPOINT = """
import { IEntryPoint } from "./IEntryPoint.sol";
contract RoycoEntryPoint is IRoycoEntryPoint {
    struct RoycoEntryPointState { uint256 x; }
    function register(bytes32 id, address who) external { state[id] = who; }
}
"""

C20_NEGATIVE_POSTOP_LOCAL_VARIABLE = """
contract RoycoDayAccountant {
    function sync() external {
        SyncedAccountingState memory postOp = kernel.syncTrancheAccounting();
        require(postOp.liquidityUtilizationWAD <= WAD);
    }
}
"""


# =====================================================================  class 11
# liquidation math / health factor.

C11_POSITIVE = """
contract L {
    function healthFactor(uint256 supply, uint256 borrow) public view returns (uint256) {
        return (supply / borrow) * 1e18;
    }
    function liquidateBorrow(address user, uint256 amount) external {
        uint256 hf = healthFactor(balance, debtOf(user));
        require(hf < 1e18, "healthy");
        seize(user, amount);
    }
}
"""

C11_NEGATIVE_IDENTIFIERS_ONLY = """
interface ILendingPool {
    /// @return healthFactor the current health factor of the user
    function getUserAccountData(address user)
        external view returns (uint256 healthFactor, uint256, uint256, uint256);
}
contract L {
    uint256 internal healthFactor;
    function set(uint256 hf) external { healthFactor = hf; }
}
"""


# ==========================================================================
#  M1
# ==========================================================================


def test_m1_fires_on_caller_supplied_key(tmp_path):
    assert _scan(tmp_path, move_scan, M1_POSITIVE, ["M1"]), "known positive missed"


@pytest.mark.parametrize("code,label", [
    (M1_NEGATIVE_DERIVED_KEY, "internally derived key"),
    (M1_NEGATIVE_FRESH_PARENT, "freshly created parent"),
    (M1_NEGATIVE_READONLY, "read-only exists_ call"),
])
def test_m1_stays_silent_on_safe_shapes(code, label, tmp_path):
    assert not _scan(tmp_path, move_scan, code, ["M1"]), f"false positive: {label}"


# ==========================================================================
#  M3
# ==========================================================================


def test_m3_fires_on_unfrozen_cap_handover(tmp_path):
    assert _scan(tmp_path, move_scan, M3_POSITIVE, ["M3"]), "known positive missed"


@pytest.mark.parametrize("code,label", [
    (M3_NEGATIVE_FROZEN, "frozen cap"),
    (M3_NEGATIVE_NO_CAP, "unrelated transfer"),
])
def test_m3_stays_silent_on_safe_shapes(code, label, tmp_path):
    assert not _scan(tmp_path, move_scan, code, ["M3"]), f"false positive: {label}"


# ==========================================================================
#  R1
# ==========================================================================


def test_r1_fires_when_debug_assert_is_the_only_enforcement(tmp_path):
    assert _scan(tmp_path, rust_scan, R1_POSITIVE, name="T.rs"), "known positive missed"


@pytest.mark.parametrize("code,label", [
    (R1_NEGATIVE_ENSURED, "enforced by ensure! before the assert"),
    (R1_NEGATIVE_UNREACHABLE_ARM, "unreachable arm"),
    (R1_NEGATIVE_SATURATING_GUARD, "guard on saturating arithmetic"),
])
def test_r1_stays_silent_or_low(code, label, tmp_path):
    hits = _scan(tmp_path, rust_scan, code, name="T.rs")
    strong = [h for h in hits if h["severity_hint"] == "high"]
    assert not strong, f"false positive (high): {label}"


# ==========================================================================
#  R2
# ==========================================================================


def test_r2_fires_on_raw_balance_share_math(tmp_path):
    assert _scan(tmp_path, rust_scan, R2_POSITIVE, name="T.rs"), "known positive missed"


@pytest.mark.parametrize("code,label", [
    (R2_NEGATIVE_VIRTUAL_OFFSET, "virtual offset present"),
    (R2_NEGATIVE_FIRST_DEPOSITOR_GUARD, "first-depositor guard present"),
])
def test_r2_stays_silent_when_mitigated(code, label, tmp_path):
    assert not _scan(tmp_path, rust_scan, code, name="T.rs"), f"false positive: {label}"


# ==========================================================================
#  class 20 / class 11 — the bare-identifier regressions
# ==========================================================================


def test_class20_fires_on_a_real_paymaster(tmp_path):
    assert _scan(tmp_path, veck_scan, C20_POSITIVE, [20], name="T.sol"), "known positive missed"


@pytest.mark.parametrize("code,label", [
    (C20_NEGATIVE_OWN_ENTRYPOINT, "project's own EntryPoint contract"),
    (C20_NEGATIVE_POSTOP_LOCAL_VARIABLE, "local variable named postOp"),
])
def test_class20_stays_silent_on_identifier_collisions(code, label, tmp_path):
    assert not _scan(tmp_path, veck_scan, code, [20], name="T.sol"), f"false positive: {label}"


def test_class11_fires_on_real_liquidation_math(tmp_path):
    assert _scan(tmp_path, veck_scan, C11_POSITIVE, [11], name="T.sol"), "known positive missed"


def test_class11_identifier_only_is_weak_not_strong(tmp_path):
    """`healthFactor` is a name, so it may MATCH — but it must not count as evidence.

    The class was demoted precisely because 137 "strong" hits were Aave's
    canonical identifier. Navigation is still useful and intended; the fix was to
    stop it counting, not to stop it matching.
    """
    hits = _scan(tmp_path, veck_scan, C11_NEGATIVE_IDENTIFIERS_ONLY, [11], name="T.sol")
    assert [h for h in hits if h["strength"] == "strong"] == [], (
        "class 11 regressed to counting an identifier as evidence"
    )


# ==========================================================================
#  selector constants — regression pins
# ==========================================================================


def test_class20_patterns_are_anchored_not_bare(tmp_path):
    """Regression: a bare `EntryPoint` pattern produced 252 false positives."""
    from cli.cs_veck import _BY_ID
    strong = " ".join(_BY_ID[20]["strong"])
    assert not re.search(r'"\(?\\b?EntryPoint\)?\\??"', strong) or "EntryPoint\\s" in strong, (
        "class 20 regressed to a bare EntryPoint match"
    )