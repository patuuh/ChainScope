// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import { Precision } from "../contracts/utils/Precision.sol";

/// Mirrors of the FeeDistributor split internals. Inputs are passed as structs
/// because the originals take 4-7 parameters, which trips solc's stack limit in a
/// harness that adds its own locals.
contract FeeSplitHarness {
    struct Split {
        uint256 totalWntBalance;
        uint256 feesV1UsdInWnt;
        uint256 feesV2UsdInWnt;
        uint256 keeperCostsV2;
        uint256 chainlinkFactor;
    }
    struct Final {
        uint256 totalWntBalance;
        uint256 keeperCostsV1;
        uint256 keeperCostsV2;
        uint256 wntForChainlink;
        uint256 wntForTreasury;
        uint256 wntForReferralRewards;
        uint256 maxWntFromTreasury;
    }

    /// Exposed so tests can compute a slice the same way the contract does.
    function mulDiv(uint256 v, uint256 n, uint256 d) external pure returns (uint256) {
        return Precision.mulDiv(v, n, d);
    }
    function applyFactor(uint256 v, uint256 f) external pure returns (uint256) {
        return Precision.applyFactor(v, f);
    }

    /// FeeDistributor._calculateChainlinkAndTreasuryAmounts:639-659
    function chainlinkAndTreasury(Split memory s)
        external
        pure
        returns (uint256 wntForChainlink, uint256 wntForTreasury)
    {
        uint256 chainlinkTreasuryWntAmount =
            Precision.mulDiv(s.totalWntBalance, s.feesV2UsdInWnt, s.feesV1UsdInWnt + s.feesV2UsdInWnt);
        wntForChainlink = Precision.applyFactor(chainlinkTreasuryWntAmount, s.chainlinkFactor);
        wntForTreasury = chainlinkTreasuryWntAmount - wntForChainlink - s.keeperCostsV2;
    }

    /// FeeDistributor._finalizeWntForTreasury:542-579
    function finalizeWntForTreasury(Final memory f)
        external
        pure
        returns (uint256 treasuryAfter, bool pulledFromTreasury, uint256 pulled)
    {
        uint256 wntBeforeV1 =
            f.totalWntBalance - f.keeperCostsV2 - f.wntForChainlink - f.wntForTreasury;
        uint256 keeperAndReferralCostsV1 = f.keeperCostsV1 + f.wntForReferralRewards;
        if (keeperAndReferralCostsV1 > wntBeforeV1) {
            uint256 additionalWntForV1Costs = keeperAndReferralCostsV1 - wntBeforeV1;
            if (additionalWntForV1Costs > f.wntForTreasury) {
                uint256 additionalWntFromTreasury = additionalWntForV1Costs - f.wntForTreasury;
                if (additionalWntFromTreasury > f.maxWntFromTreasury) {
                    revert("MaxWntFromTreasuryExceeded");
                }
                return (0, true, additionalWntFromTreasury);
            }
            treasuryAfter = f.wntForTreasury - additionalWntForV1Costs;
        } else {
            treasuryAfter = f.wntForTreasury + (wntBeforeV1 - keeperAndReferralCostsV1);
        }
    }
}

/**
 * Hunt campaign: FeeDistributor's split arithmetic - keeper / Chainlink / treasury /
 * referral, which had 57 hit-count and zero executed runs.
 *
 * All of it routes through Precision.mulDiv -> OZ Math.mulDiv (rounds DOWN) and
 * Precision.applyFactor (= mulDiv by FLOAT_PRECISION, also down). For a fee splitter
 * the question is conservation: parts handed out must never exceed what came in, and
 * any shortfall must land in the treasury rather than vanishing.
 *
 * Inputs are packed into one struct per test - solc's stack limit bites with four
 * uint128 params plus locals, and threading them through a struct is the standard fix
 * rather than trimming variables one at a time.
 *
 * Properties:
 *  F1 split never exceeds the balance it divides
 *  F2 keeper + chainlink + treasury <= balance, always
 *  F3 v2-dominant fees: the split still conserves
 *  F4 finalize is monotonic: more keeper cost never increases the treasury take
 *  F5 treasury pull respects the cap, and reverts past it
 *  F6 remainder accounting: unspent balance accrues to treasury, not lost
 */
contract FeeSplitHuntTest is Test {
    FeeSplitHarness internal h;
    uint256 internal constant FP = 1e30;

    struct P2 { uint128 bal; uint128 v1; uint128 v2; uint128 kc2; uint32 cl; }
    struct P4 { uint128 bal; uint128 k1a; uint128 k1b; uint32 cl; }
    struct P5 { uint128 bal; uint128 k1; uint128 ref; uint8 cap; }

    function setUp() public { h = new FeeSplitHarness(); }

    function _b(uint128 v, uint256 lo, uint256 hi) internal pure returns (uint256) {
        return bound(uint256(v), lo, hi);
    }

    // ---------------------------------------------------------------- F1 / F2
    /// Conservation is only meaningful when keeperCostsV2 fits inside the v2 fee
    /// slice. FeeDistributor.sol:656 computes
    ///   wntForTreasury = chainlinkTreasuryWntAmount - wntForChainlink - keeperCostsV2
    /// with no prior guard, so an undersized slice reverts the whole distribution.
    /// That is real contract behaviour - pinned by
    /// test_undersizedV2Slice_reverts - not something to assert around.
    function testFuzz_splitConserves_and_partsFit(P2 memory p) public {
        uint256 bal = _b(p.bal, 1e6, 1e30);
        uint256 v1 = _b(p.v1, 1, 1e27);
        uint256 v2 = _b(p.v2, 1, 1e27);
        uint256 kc2 = _b(p.kc2, 0, bal / 8);
        uint256 clF = _b(p.cl, 0, FP);

        uint256 slice = h.mulDiv(bal, v2, v1 + v2);
        if (slice < kc2 + h.applyFactor(slice, clF)) { return; }

        (uint256 cl, uint256 tr) = h.chainlinkAndTreasury(
            FeeSplitHarness.Split(bal, v1, v2, kc2, clF)
        );
        assertLe(cl, bal, "F1: chainlink allocation exceeded the balance");
        assertLe(tr, bal, "F1: treasury allocation exceeded the balance");
        assertLe(cl + tr + kc2, bal, "F2: keeper+chainlink+treasury exceeded the balance");
    }

    /// Documents the unguarded subtraction at FeeDistributor.sol:656. Reverting is
    /// safe - no misallocation - but it is a liveness edge on a keeper trigger, and
    /// the contract's own _finalizeWntForTreasury logic exists precisely to absorb
    /// shortfalls; it simply never gets the chance to run.
    function test_undersizedV2Slice_reverts() public {
        (bool ok,) = address(h).staticcall(
            abi.encodeCall(
                FeeSplitHarness.chainlinkAndTreasury,
                (FeeSplitHarness.Split(4985, 21272, 18, 12, 10000))
            )
        );
        assertFalse(ok, "expected the unguarded subtraction to revert");
    }

    // ---------------------------------------------------------------- F3
    function testFuzz_v2DominantSplitConserves(P4 memory p) public {
        uint256 bal = _b(p.bal, 1e6, 1e30);
        (uint256 cl, uint256 tr) = h.chainlinkAndTreasury(
            FeeSplitHarness.Split(bal, 1, 1e27, 0, _b(p.cl, 0, FP))
        );
        assertLe(cl + tr, bal, "F3: parts exceeded balance with v2-dominant fees");
    }

    // ---------------------------------------------------------------- F4
    function testFuzz_finalizeIsMonotonicInKeeperCost(P4 memory p) public {
        uint256 bal = _b(p.bal, 1e9, 1e30);
        (uint256 a, uint256 b) = (_b(p.k1a, 0, bal / 4), _b(p.k1b, 0, bal / 4));
        (uint256 kLow, uint256 kHigh) = a <= b ? (a, b) : (b, a);
        (uint256 cl, uint256 tr) = h.chainlinkAndTreasury(
            FeeSplitHarness.Split(bal, 1e25, 1e25, 0, _b(p.cl, 0, FP))
        );
        if (cl + tr == 0) { return; }
        (uint256 tLow,,) = h.finalizeWntForTreasury(
            FeeSplitHarness.Final(bal, kLow, 0, cl, tr, 0, bal)
        );
        (uint256 tHigh,,) = h.finalizeWntForTreasury(
            FeeSplitHarness.Final(bal, kHigh, 0, cl, tr, 0, bal)
        );
        // Direction matters: more keeper cost is paid OUT of the treasury, so the
        // treasury's take must not increase. An earlier version asserted
        // assertGe(tHigh, tLow) - inverted - and the fuzzer failed it on the first
        // input by correctly showing tHigh < tLow.
        assertLe(tHigh, tLow, "F4: raising keeper cost increased the treasury take");
    }

    // ---------------------------------------------------------------- F5
    function testFuzz_pullFromTreasury_respectsCap(P5 memory p) public {
        uint256 bal = _b(p.bal, 1e9, 1e30);
        (, bool pulled, uint256 amount) = h.finalizeWntForTreasury(
            FeeSplitHarness.Final(bal, _b(p.k1, 1, bal / 2), 0, 0, 0, _b(p.ref, 1, bal / 2), _b(p.cap, 0, bal))
        );
        if (pulled) {
            assertLe(amount, _b(p.cap, 0, bal), "F5: pulled beyond the cap without reverting");
        } else {
            assertEq(amount, 0, "F5: reported a pull with zero amount");
        }
    }

    function test_pullBeyondCap_reverts() public {
        vm.expectRevert();
        h.finalizeWntForTreasury(FeeSplitHarness.Final(1e18, 1e18, 0, 0, 0, 1e18, 1));
    }

    // ---------------------------------------------------------------- F6
    function testFuzz_unspentBalanceAccruesToTreasury(P2 memory p) public {
        uint256 bal = _b(p.bal, 1e9, 1e30);
        (uint256 cl, uint256 tr) = h.chainlinkAndTreasury(
            FeeSplitHarness.Split(bal, 1e25, 1e25, 0, _b(p.cl, 0, FP))
        );
        if (cl + tr == 0) { return; }
        (uint256 trFinal,,) = h.finalizeWntForTreasury(
            FeeSplitHarness.Final(bal, 0, 0, cl, tr, 0, bal)
        );
        assertEq(trFinal, bal - cl, "F6: balance was neither allocated nor retained");
    }
}
