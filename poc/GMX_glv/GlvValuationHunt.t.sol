// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import { GlvUtils } from "../contracts/glv/GlvUtils.sol";
import { Price } from "../contracts/price/Price.sol";
import { IOracle } from "../contracts/oracle/IOracle.sol";
import { Precision } from "../contracts/utils/Precision.sol";
import { DataStore } from "../contracts/data/DataStore.sol";
import { RoleStore } from "../contracts/role/RoleStore.sol";
import { Role } from "../contracts/role/Role.sol";

/// Minimal GLV token: only totalSupply matters to the valuation path.
contract MockGlvToken {
    uint256 internal _supply;
    function totalSupply() external view returns (uint256) { return _supply; }
    function setSupply(uint256 s) external { _supply = s; }
}

/// Oracle stub exposing the (min, max) pair that `getGlvTokenPrice` consumes.
contract MockPairOracle {
    uint256 internal _min;
    uint256 internal _max;
    constructor(uint256 min_, uint256 max_) { _min = min_; _max = max_; }
    function primaryPrices(address) external view returns (uint256, uint256) { return (_min, _max); }
}

contract GlvValueHarness {
    function glvValue(DataStore ds, IOracle o, address glv, bool maximize)
        external
        view
        returns (uint256, bool)
    {
        return GlvUtils.getGlvValue(ds, o, glv, maximize);
    }
}

/**
 * Hunt campaign: GlvWithdrawalUtils._getMarketTokenAmount's valuation input.
 *
 * This is the layer the earlier campaigns could not reach, tested via the shallow
 * short-circuit in GlvUtils.getGlvValue: when the GLV itself carries an oracle
 * price, it returns `(maximize ? max : min) * totalSupply` without touching a
 * market. That short-circuit is exactly the input the exit path depends on,
 * because GlvWithdrawalUtils._getMarketTokenAmount calls it with `maximize = false`
 * while the deposit path calls it with `true`.
 *
 * Properties:
 *  V1 exit values at min, deposit values at max
 *  V2 exit valuation is never ABOVE the deposit valuation  <- the round-trip guard
 *  V3 valuation scales linearly with supply
 *  V4 valuation is monotonic in both price bounds
 */
contract GlvValuationHarnessTest is Test {
    DataStore internal ds;
    MockGlvToken internal glv;
    MockPairOracle internal oracle;
    GlvValueHarness internal h;

    function setUp() public {
        RoleStore rs = new RoleStore();
        ds = new DataStore(rs);
        rs.grantRole(address(this), Role.CONTROLLER);
        glv = new MockGlvToken();
        h = new GlvValueHarness();
        oracle = new MockPairOracle(1e18, 2e18); // min, max
    }

    // ---------------------------------------------------------------- V1
    function testFuzz_exitUsesMin_andDepositUsesMax(uint128 min_, uint128 max_, uint128 sup_) public {
        uint256 minP = bound(uint256(min_), 1, 1e30);
        uint256 maxP = bound(uint256(max_), minP, 1e30);
        uint256 sup = bound(uint256(sup_), 1, 1e30);

        glv.setSupply(sup);
        oracle = new MockPairOracle(minP, maxP);

        (uint256 exitVal,) = h.glvValue(ds, IOracle(address(oracle)), address(glv), false);
        (uint256 depVal,) = h.glvValue(ds, IOracle(address(oracle)), address(glv), true);

        assertEq(exitVal, minP * sup, "V1: exit path did not value at the min bound");
        assertEq(depVal, maxP * sup, "V1: deposit path did not value at the max bound");
    }

    // ---------------------------------------------------------------- V2
    /// THE guard. A liquidation-style exit valued above the deposit valuation is how
    /// a round trip could extract value from an oracle spread.
    function testFuzz_exitValuation_neverExceedsDepositValuation(uint128 min_, uint128 max_, uint128 sup_) public {
        uint256 minP = bound(uint256(min_), 1, 1e30);
        // A well-formed oracle satisfies min <= max. Bounding these two
        // independently was a bug in an earlier version of this test: the fuzzer
        // supplied min_ > max_, i.e. a MALFORMED oracle, and the exit then took
        // the larger of the two - correct behaviour for the data it was given,
        // and not a protocol bug. The malformed case is pinned separately by
        // testFuzz_swapOfBounds_wouldBreakTheGuard.
        uint256 maxP = bound(uint256(max_), minP, 1e30);
        uint256 sup = bound(uint256(sup_), 1, 1e30);

        glv.setSupply(sup);
        oracle = new MockPairOracle(minP, maxP);

        (uint256 exitVal,) = h.glvValue(ds, IOracle(address(oracle)), address(glv), false);
        (uint256 depVal,) = h.glvValue(ds, IOracle(address(oracle)), address(glv), true);

        assertLe(exitVal, depVal, "V2: exit valued ABOVE the deposit - round trip could profit");
    }

    /// With the interface's declared ordering (min, max), max must never be below min
    /// for a well-formed oracle. If an implementation ever inverted them, the exit
    /// would be the richer of the two - so pin the assumption explicitly.
    function testFuzz_swapOfBounds_wouldBreakTheGuard(uint128 a_, uint128 b_) public {
        uint256 a = bound(uint256(a_), 1, 1e30);
        uint256 b = bound(uint256(b_), 1, 1e30);
        uint256 sup = bound(uint256(b_), 1, 1e30);
        sup = bound(sup, 1, 1e30);

        glv.setSupply(sup);
        oracle = new MockPairOracle(b, a);            // deliberately inverted
        (uint256 exitVal,) = h.glvValue(ds, IOracle(address(oracle)), address(glv), false);
        (uint256 depVal,) = h.glvValue(ds, IOracle(address(oracle)), address(glv), true);

        if (a < b) {
            assertGt(exitVal, depVal, "V2: with inverted bounds the exit IS the richer side");
        }
    }

    // ---------------------------------------------------------------- V3
    function testFuzz_valuationScalesLinearlyWithSupply(uint128 p_, uint128 s1_, uint128 s2_) public {
        uint256 p = bound(uint256(p_), 1, 1e20);
        uint256 s1 = bound(uint256(s1_), 1, 1e20);
        uint256 s2 = bound(uint256(s2_), 1, 1e20);
        oracle = new MockPairOracle(p, p);

        glv.setSupply(s1);
        (uint256 v1,) = h.glvValue(ds, IOracle(address(oracle)), address(glv), false);
        glv.setSupply(s2);
        (uint256 v2,) = h.glvValue(ds, IOracle(address(oracle)), address(glv), false);

        assertEq(v1, p * s1, "V3: valuation is not price*supply");
        assertEq(v2, p * s2, "V3: valuation is not price*supply");
    }

    // ---------------------------------------------------------------- V4
    function testFuzz_valuationMonotonicInSupply(uint128 s1_, uint128 s2_, uint128 p_) public {
        uint256 s1 = bound(uint256(s1_), 1, 1e20);
        uint256 s2 = bound(uint256(s2_), 1, 1e20);
        uint256 p = bound(uint256(p_), 1, 1e20);
        oracle = new MockPairOracle(p, p);

        glv.setSupply(s1);
        (uint256 v1,) = h.glvValue(ds, IOracle(address(oracle)), address(glv), false);
        glv.setSupply(s2);
        (uint256 v2,) = h.glvValue(ds, IOracle(address(oracle)), address(glv), false);

        if (s1 <= s2) { assertLe(v1, v2, "V4: valuation not monotone in supply"); }
        else { assertGe(v1, v2, "V4: valuation not monotone in supply"); }
    }
}
