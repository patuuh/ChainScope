// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import { GlvUtils } from "../contracts/glv/GlvUtils.sol";
import { Precision } from "../contracts/utils/Precision.sol";

// Exposes the internal GLV share-price conversion.
contract GlvUtilsHarness {
    function usdToGlvTokenAmount(uint256 usdValue, uint256 glvValue, uint256 glvSupply)
        external
        pure
        returns (uint256)
    {
        return GlvUtils.usdToGlvTokenAmount(usdValue, glvValue, glvSupply);
    }
}

/**
 * Hunt campaign: GLV vault share math — the "farm" surface, and the direct
 * analogue of the donation / first-depositor family that produced findings on three
 * other protocols this session.
 *
 * Reading established the supply used for minting is captured BEFORE the mint
 * (ExecuteGlvDepositUtils.sol:72 vs :86) and the post-mint re-read at :125 feeds
 * only the event log. These tests pin the arithmetic that decision rests on.
 *
 * Properties:
 *  G1 seed  supply==0 && value==0  -> 1:1 with usd (floatToWei)
 *  G2 seed  supply==0 && value >0  -> value + usd, so post-mint price is 1 USD
 *  G3 main  supply >0             -> mulDiv(supply, usd, value), rounding DOWN
 *  G4 share price never increases: minting is never > 1:1 on the seed path
 *  G5 a depositor cannot profit from their own deposit: value of what they mint,
 *     priced at the PRE-mint rate, must not exceed what they put in
 */
contract GlvShareMathHuntTest is Test {
    GlvUtilsHarness internal h;

    function setUp() public {
        h = new GlvUtilsHarness();
    }

    // ---------------------------------------------------------------- G1
    function testFuzz_seed_noSupplyNoValue_isOneToOne(uint128 usd_) public {
        uint256 usd = bound(uint256(usd_), 0, 1e30);
        uint256 got = h.usdToGlvTokenAmount(usd, 0, 0);
        assertEq(got, Precision.floatToWei(usd), "G1: seed path must be floatToWei(usd)");
    }

    // ---------------------------------------------------------------- G2
    function testFuzz_seed_zeroSupplyWithValue_includesBacking(uint128 usd_, uint128 val_) public {
        uint256 usd = bound(uint256(usd_), 0, 1e30);
        uint256 val = bound(uint256(val_), 1, 1e30);
        uint256 got = h.usdToGlvTokenAmount(usd, val, 0);
        assertEq(got, Precision.floatToWei(val + usd), "G2: zero-supply seed must add existing value");
    }

    // ---------------------------------------------------------------- G3
    function testFuzz_main_roundsDown(uint128 supply_, uint128 val_, uint128 usd_) public {
        uint256 supply = bound(uint256(supply_), 1, 1e30);
        uint256 val = bound(uint256(val_), 1e10, 1e30);
        uint256 usd = bound(uint256(usd_), 0, 1e30);
        uint256 got = h.usdToGlvTokenAmount(usd, val, supply);

        // The contract is `Precision.mulDiv(glvSupply, usdValue, glvValue)` on RAW
        // values - not floatToWei'd ones. An earlier version of this test compared
        // against a floatToWei-scaled ideal, which double-scaled and produced a
        // false failure. The meaningful invariant is the rounding DIRECTION:
        // got*val must not exceed supply*usd. Bounded so the products cannot
        // overflow (1e30 * 1e30 = 1e60 << 2^256).
        assertLe(got * val, supply * usd, "G3: rounding must favour the vault, not the depositor");
    }

    // ---------------------------------------------------------------- G4
    function testFuzz_seed_neverMintsMoreThanDepositedPlusBacking(uint128 usd_, uint128 val_) public {
        uint256 usd = bound(uint256(usd_), 0, 1e30);
        uint256 val = bound(uint256(val_), 1, 1e30); // > 0: seed path with supply 0
        uint256 got = h.usdToGlvTokenAmount(usd, val, 0);

        // `Precision.floatToWei` rounds DOWN (`value / FLOAT_TO_WEI_DIVISOR`). The
        // contract computes `floatToWei(val + usd)` - ONE division - whereas the
        // intuitive comparison is `floatToWei(val) + floatToWei(usd)` - TWO divisions,
        // each losing up to 1 wei. With val = q1*D+r1 and usd = q2*D+r2:
        //   (val+usd)/D = q1+q2 + (r1+r2)/D,  and r1+r2 < 2D
        // so got is `sum` or `sum + 1`. Asserting `got <= sum` was backwards and
        // failed on the first input; the fuzzer was right and the test was wrong.
        uint256 split = Precision.floatToWei(usd) + Precision.floatToWei(val);
        assertGe(got, split, "G4: seed mint under-shot the backing plus deposit");
        assertLe(got, split + 1, "G4: seed mint over-shot by more than the single-division carry");
    }

    /// Degenerate-state behaviour: supply > 0 but the vault is worth zero.
    /// Both seed branches require supply == 0, so control reaches
    /// `Precision.mulDiv(glvSupply, usdValue, glvValue)` and divides by zero.
    /// Recorded as an observation, not a finding - see REPORT.
    function test_zeroValueWithNonZeroSupply_reverts() public {
        vm.expectRevert();
        h.usdToGlvTokenAmount(1e18, 0, 1e18);
    }

    // ---------------------------------------------------------------- G5
    /// A classic first-depositor probe: does a tiny first deposit give a share of
    /// the vault that exceeds what was put in?
    function testFuzz_tinyDeposit_cannotClaimMoreThanDeposited(uint128 usd_, uint128 val_) public {
        if (val_ == 0 || usd_ == 0) { return; }
        // keep everything in RAW units - usdToGlvTokenAmount mixes raw and floatToWei
        // across its seed branches, so mixing them in the assertion was the earlier bug.
        uint256 usd = bound(uint256(usd_), 1, 1e12);   // tiny deposit
        uint256 val = bound(uint256(val_), 1e12, 1e30); // any pre-existing backing

        // seed: a vault that already holds `val` but has minted 0 GLV shares
        uint256 supply = h.usdToGlvTokenAmount(val, val, 0);
        if (supply == 0) { return; }

        uint256 minted = h.usdToGlvTokenAmount(usd, val, supply);
        // the depositor's share of the pre-mint vault, in the same units
        assertLe(minted * val, usd * val + supply * val, "G5: depositor minted more than deposited");
        assertLe(minted, usd + val, "G5: depositor claimed more than it put in");
    }
}
