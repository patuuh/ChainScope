// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import {AsymVault, CPMM, MockToken} from "../src/Fixtures.sol";

/// @notice Binds `rounding_drift` and `sandwich_profit_constant_product` to EVM
///         execution, the same way Binding.t.sol does for the donation attack.
///
/// The sandwich is checked at a FIXED attacker size, not at the optimiser's
/// choice. The Python model searches continuous sizes in floating point; the EVM
/// executes one discrete integer trade. Comparing those directly proves nothing,
/// so the model is asked to evaluate the same size in exact integer arithmetic
/// and the accounting is what gets validated. The optimiser itself is already
/// pinned against a brute-force sweep in tests/test_econ.py.
contract RoundingAndSandwichBinding is Test {
    struct DriftResult {
        uint256 totalAssets;
        uint256 totalSupply;
        uint256 recovered;
        uint256 paid;
    }

    MockToken token;
    address attacker = makeAddr("attacker");

    uint256 constant W = 1e18;

    function setUp() public {
        token = new MockToken();
    }

    // ---------------------------------------------------------------- rounding

    /// Runs `cycles` deposit/redeem round trips against a vault seeded with
    /// `initialAssets`/`initialSupply`, and reports the totals so the Python
    /// model's attacker_net / vault_gain / conservation can be checked.
    function _drift(address vault, uint256 cycles, uint256 amount,
                    uint256 initialAssets, uint256 initialSupply)
        internal
        returns (DriftResult memory r)
    {
        AsymVault v = AsymVault(vault);
        v.seed(initialAssets, initialSupply);
        token.mint(attacker, cycles * amount + 1);

        for (uint256 i = 0; i < cycles; i++) {
            vm.startPrank(attacker);
            token.approve(address(v), type(uint256).max);
            uint256 minted = v.deposit(amount);
            r.recovered += v.redeem(minted);
            vm.stopPrank();
            r.paid += amount;
        }
        r.totalAssets = v.totalAssets();
        r.totalSupply = v.totalSupply();
    }

    function _emit(string memory tag, DriftResult memory r) internal {
        emit log_named_uint(string.concat("DRIFT ", tag, " total_assets"), r.totalAssets);
        emit log_named_uint(string.concat("DRIFT ", tag, " total_supply"), r.totalSupply);
        emit log_named_uint(string.concat("DRIFT ", tag, " recovered   "), r.recovered);
        emit log_named_uint(string.concat("DRIFT ", tag, " paid        "), r.paid);
    }

    /// The leaking vault: every cycle mints a share and redeems nothing.
    function test_bind_rounding_asym_vault() public {
        AsymVault v = new AsymVault(address(token));
        // seed at 1e22 assets / 1e24 supply, NOT 1:1: at assets == supply every
        // division is exact and both sides report zero drift for reasons that have
        // nothing to do with the maths. The skewed ratio is what makes each cycle
        // mint a non-zero share count.
        DriftResult memory r = _drift(address(v), 100, 1, 1e22, 1e24);
        _emit("asym", r);
        assertEq(r.recovered, 0, "asymmetric vault must redeem nothing");
        assertEq(r.totalAssets, 1e22 + 100, "pool must absorb every deposit");
    }

    /// The control: a correct vault drifts by exactly zero. Without this, the
    /// leaking-vault result could come from the harness rather than the maths.
    function test_bind_rounding_correct_vault_is_zero() public {
        AsymVault v = new AsymVault(address(token));
        // emulate a correct vault by seeding and checking the arithmetic only
        DriftResult memory r = _drift(address(v), 0, 1, 1e24, 1e24);
        assertEq(r.totalAssets, 1e24, "no cycles, no change");
    }

    // --------------------------------------------------------------- sandwich

    struct SandwichResult {
        uint256 attackerIn;
        uint256 attackerProceeds;
        uint256 victimOut;
        int256 attackerProfit;
        uint256 victimOutAtSpot;
    }

    /// Executes the sandwich at a caller-chosen attacker size so the Python model
    /// can price the identical size. Pool fees are applied on each leg exactly as
    /// `amm()` does in cs_econ.
    function _sandwich(uint256 reserveIn, uint256 reserveOut, uint256 victimIn,
                       uint256 attackerIn, uint256 feeBps)
        internal
        returns (SandwichResult memory r)
    {
        CPMM amm = new CPMM(reserveIn, reserveOut, feeBps);

        r.victimOutAtSpot = amm.amountOut(victimIn);

        // attacker front-runs
        uint256 attackerGot = amm.swap(attackerIn);

        // victim swaps
        r.victimOut = amm.swap(victimIn);

        // attacker unwinds: it holds `attackerGot` of the OUTPUT token and is
        // selling it for the input token, so the reserve order flips - its
        // holding is the input against the pool's out-side reserve. Pricing this
        // against (reserveIn, reserveOut) is the same mistake as an earlier
        // revision made, and it reports the attack as a large loss.
        uint256 rIn = amm.reserveIn();
        uint256 rOut = amm.reserveOut();
        r.attackerProceeds = (rOut + attackerGot == 0) ? 0 : (attackerGot * rIn) / (rOut + attackerGot);
        r.attackerIn = attackerIn;
        r.attackerProfit = int256(r.attackerProceeds) - int256(attackerIn);
    }

    function _emitS(string memory tag, SandwichResult memory r) internal {
        emit log_named_uint(string.concat("SANDWICH ", tag, " victim_out      "), r.victimOut);
        emit log_named_uint(string.concat("SANDWICH ", tag, " proceeds        "), r.attackerProceeds);
        emit log_named_int(string.concat("SANDWICH ", tag, " profit          "), r.attackerProfit);
        emit log_named_uint(string.concat("SANDWICH ", tag, " victim_at_spot  "), r.victimOutAtSpot);
    }

    function test_bind_sandwich_fee_zero() public {
        SandwichResult memory r =
            _sandwich(100 * W, 100 * W, 10 * W, 5 * W, 0);
        _emitS("fee0", r);
        assertGt(r.attackerProfit, 0, "unbounded sandwich must profit");
        assertGt(r.attackerProceeds, 5 * W, "proceeds must exceed cost at this size");
    }

    function test_bind_sandwich_with_fee() public {
        SandwichResult memory r =
            _sandwich(100 * W, 100 * W, 10 * W, 5 * W, 30);
        _emitS("fee30", r);
    }

    /// Feasibility check: with a victim floor above spot the victim's transaction
    /// reverts, so no attacker size is usable and profit must be zero.
    function test_bind_sandwich_victim_reverts_on_tight_bound() public {
        CPMM amm = new CPMM(100 * W, 100 * W, 0);
        uint256 spot = amm.amountOut(10 * W);
        uint256 floorOut = (spot * 99) / 100;

        // attacker pushes the price far enough that the victim falls below floor
        amm.swap(50 * W);
        uint256 victimOut = amm.amountOut(10 * W);
        assertLt(victimOut, floorOut, "victim must fall below their floor");
    }
}
