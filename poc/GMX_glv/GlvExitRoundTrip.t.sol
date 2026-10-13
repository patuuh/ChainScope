// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import { GlvUtils } from "../contracts/glv/GlvUtils.sol";
import { Precision } from "../contracts/utils/Precision.sol";

// Exposes the GLV deposit and exit conversions so the round-trip can be exercised.
contract GlvExitHarness {
    function usdToGlvTokenAmount(uint256 usdValue, uint256 glvValue, uint256 glvSupply)
        external
        pure
        returns (uint256)
    {
        return GlvUtils.usdToGlvTokenAmount(usdValue, glvValue, glvSupply);
    }

    function glvTokenAmountToUsd(uint256 glvTokenAmount, uint256 glvValue, uint256 glvSupply)
        external
        pure
        returns (uint256)
    {
        return GlvUtils.glvTokenAmountToUsd(glvTokenAmount, glvValue, glvSupply);
    }
}

/**
 * Hunt campaign: GLV EXIT path — GlvWithdrawalUtils._getMarketTokenAmount.
 *
 * Deposit rounding favours the vault, so a bug there is self-harming. Withdraw
 * rounding is the direction that can steal, which is why this covers the exit.
 *
 * The exit path (GlvWithdrawalUtils.sol:291-322) is two conversions, both via
 * Precision.mulDiv -> OZ Math.mulDiv, which rounds DOWN:
 *   glvTokenAmountToUsd  = mulDiv(glvValue, glvTokenAmount, glvSupply)
 *   usdToMarketTokenAmount = mulDiv(...) with market poolValue / marketTokenSupply
 * and it calls getGlvValue(..., maximize = false) where the deposit path passes
 * true — a deliberate asymmetry against the withdrawer.
 *
 * Properties:
 *  X1 exit rounds down       withdrawing X GLV returns at most the pro-rata USD
 *  X2 round-trip no profit   deposit d -> withdraw -> usd out <= d, at constant ratio
 *  X3 exit never over-returns vs. full-supply withdrawal
 *  X4 zero supply reverts    (EmptyGlvTokenSupply), pinned
 */
contract GlvExitRoundTripHuntTest is Test {
    GlvExitHarness internal h;

    function setUp() public {
        h = new GlvExitHarness();
    }

    /// One full deposit -> withdraw cycle at an unchanged glvValue/glvSupply ratio.
    function _roundTrip(uint256 d, uint256 glvValue, uint256 glvSupply)
        internal
        view
        returns (uint256 minted, uint256 usdOut)
    {
        minted = h.usdToGlvTokenAmount(d, glvValue, glvSupply);
        if (minted == 0) { return (0, 0); }
        // the deposit added value and supply proportionally
        uint256 glvValueAfter = glvValue + d;
        uint256 glvSupplyAfter = glvSupply + minted;
        usdOut = h.glvTokenAmountToUsd(minted, glvValueAfter, glvSupplyAfter);
    }

    // ---------------------------------------------------------------- X2
    function testFuzz_roundTrip_neverProfits(uint128 d_, uint128 val_, uint128 sup_) public {
        if (d_ == 0) { return; }
        uint256 d = bound(uint256(d_), 1, 1e30);
        uint256 val = bound(uint256(val_), 1e10, 1e30);
        uint256 sup = bound(uint256(sup_), 1e10, 1e30);

        (uint256 minted, uint256 usdOut) = _roundTrip(d, val, sup);
        if (minted == 0) { return; }

        assertLe(usdOut, d, "X2: round trip returned more USD than was deposited");
    }

    /// Repeating the cycle must never accumulate value: each pass is <= the deposit.
    function testFuzz_repeatedRoundTrips_doNotAccumulate(uint128 d_, uint128 val_, uint128 sup_, uint8 n) public {
        if (d_ == 0) { return; }
        uint256 d = bound(uint256(d_), 1, 1e24);
        uint256 val = bound(uint256(val_), 1e10, 1e30);
        uint256 sup = bound(uint256(sup_), 1e10, 1e30);
        uint256 rounds = bound(uint256(n), 1, 8);

        uint256 prevVal = val;
        uint256 prevSup = sup;
        for (uint256 i = 0; i < rounds; i++) {
            (uint256 minted, uint256 usdOut) = _roundTrip(d, prevVal, prevSup);
            if (minted == 0) { return; }
            assertLe(usdOut, d, "X2: a later round trip extracted more than one deposit");
            prevVal += d;
            prevSup += minted;
        }
    }

    // ---------------------------------------------------------------- X1
    function testFuzz_exitRoundsDown(uint128 g_, uint128 val_, uint128 sup_) public {
        uint256 g = bound(uint256(g_), 0, 1e30);
        uint256 val = bound(uint256(val_), 1, 1e30);
        uint256 sup = bound(uint256(sup_), 1, 1e30);
        if (g == 0) { return; }

        uint256 usd = h.glvTokenAmountToUsd(g, val, sup);
        assertLe(usd * sup, val * g, "X1: exit rounded UP against the vault");
    }

    // ---------------------------------------------------------------- X3
    /// A withdrawal of the entire supply can never exceed the entire vault value.
    function testFuzz_fullSupplyWithdrawal_neverExceedsVault(uint128 val_, uint128 sup_) public {
        uint256 val = bound(uint256(val_), 1, 1e30);
        uint256 sup = bound(uint256(sup_), 1, 1e30);
        uint256 usd = h.glvTokenAmountToUsd(sup, val, sup);
        assertLe(usd, val, "X3: full-supply withdrawal exceeded vault value");
    }

    // ---------------------------------------------------------------- X4
    function test_zeroSupplyWithdrawal_reverts() public {
        vm.expectRevert();
        h.glvTokenAmountToUsd(1e18, 1e18, 0);
    }
}
