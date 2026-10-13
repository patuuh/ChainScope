// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import { DataStore } from "../contracts/data/DataStore.sol";
import { RoleStore } from "../contracts/role/RoleStore.sol";
import { Role } from "../contracts/role/Role.sol";
import { Keys } from "../contracts/data/Keys.sol";
import { MarketUtils } from "../contracts/market/MarketUtils.sol";
import { Precision } from "../contracts/utils/Precision.sol";

// Exposes the internal position-impact-pool math so it can be exercised directly
// against the REAL DataStore rather than a stub.
contract MarketUtilsHarness {
    function pendingDistribution(DataStore ds, address market)
        external
        view
        returns (uint256, uint256)
    {
        return MarketUtils.getPendingPositionImpactPoolDistributionAmount(ds, market);
    }

    function secondsSinceDistributed(DataStore ds, address market) external view returns (uint256) {
        return MarketUtils.getSecondsSincePositionImpactPoolDistributed(ds, market);
    }
}

/**
 * Hunt campaign: position impact pool — the "amount application" layer that prior
 * PricingUtils / swap-impact fuzzing never reached (those covered price impact, not
 * the distribution accrual and its floor).
 *
 * Invariants under test, each derived from reading `MarketUtils.sol:2920`:
 *   A floor      distribution can never take the pool below minPositionImpactPoolAmount
 *   B underflow  `pool - min` cannot wrap, in any ordering of the inputs
 *   C cap        distribution <= pool - min, always
 *   D monotone   more elapsed time never yields less distribution
 *   E zero       pool == 0, rate == 0, or pool <= min all yield exactly zero
 *   F fresh      a market that never distributed reports 0 seconds elapsed
 */
contract ImpactPoolHuntTest is Test {
    DataStore internal ds;
    MarketUtilsHarness internal h;
    RoleStore internal rs;

    address internal constant MARKET = address(0xABCD);
    uint256 internal constant FP = 1e30; // GMX Precision.FLOAT_PRECISION

    function setUp() public {
        rs = new RoleStore();
        ds = new DataStore(rs);
        // DataStore.setUint is onlyController - grant it to this contract
        rs.grantRole(address(this), Role.CONTROLLER);
        h = new MarketUtilsHarness();
        // pin the clock so secondsSinceDistributed is deterministic
        vm.warp(1_700_000_000);
    }

    function _seed(uint256 pool, uint256 minAmt, uint256 rate, uint256 distributedAt) internal {
        ds.setUint(Keys.positionImpactPoolAmountKey(MARKET), pool);
        ds.setUint(Keys.minPositionImpactPoolAmountKey(MARKET), minAmt);
        ds.setUint(Keys.positionImpactPoolDistributionRateKey(MARKET), rate);
        ds.setUint(Keys.positionImpactPoolDistributedAtKey(MARKET), distributedAt);
    }

    // ---------------------------------------------------------------- A
    function testFuzz_floorNeverBreached(uint128 pool_, uint128 min_, uint32 rate_, uint32 elapsed_) public {
        uint256 pool = bound(uint256(pool_), 0, 1e33);
        uint256 minAmt = bound(uint256(min_), 0, 1e33);
        uint256 rate = bound(uint256(rate_), 0, 1e30);
        uint256 elapsed = bound(uint256(elapsed_), 0, block.timestamp - 1);
        _seed(pool, minAmt, rate, block.timestamp - elapsed);

        (uint256 dist,) = h.pendingDistribution(ds, MARKET);
        uint256 remaining = pool - dist;

        if (pool > minAmt) {
            assertGe(remaining, minAmt, "A: distribution breached the configured floor");
        } else {
            // pool is ALREADY under its minimum - the vault must distribute nothing
            // rather than drain an under-water pool. Fuzzing caught this: an
            // unconditional 'remaining >= min' assertion is unsatisfiable here.
            assertEq(dist, 0, "A: distributed from a pool already below its minimum");
            assertEq(remaining, pool, "A: pool changed despite zero distribution");
        }
        assertLe(dist, pool, "A: distribution exceeded the pool itself");
    }

    // ---------------------------------------------------------------- B
    function testFuzz_noUnderflowAnyOrdering(uint128 pool_, uint128 min_) public {
        uint256 pool = bound(uint256(pool_), 0, type(uint128).max);
        uint256 minAmt = bound(uint256(min_), 0, type(uint128).max);
        _seed(pool, minAmt, FP, block.timestamp);

        (uint256 dist,) = h.pendingDistribution(ds, MARKET);
        // if pool < min the early return must give 0 rather than wrapping a subtraction
        if (pool <= minAmt) {
            assertEq(dist, 0, "B: distributed despite pool <= min (subtraction would wrap)");
        } else {
            assertLe(dist, pool - minAmt, "B: distributed more than pool - min");
        }
    }

    // ---------------------------------------------------------------- C
    function testFuzz_cappedAtPoolMinusMin(uint128 pool_, uint128 min_, uint32 elapsed_) public {
        uint256 pool = bound(uint256(pool_), 1, 1e33);
        uint256 minAmt = bound(uint256(min_), 0, pool);
        uint256 elapsed = bound(uint256(elapsed_), 0, block.timestamp - 1);
        _seed(pool, minAmt, FP, block.timestamp - elapsed);

        (uint256 dist,) = h.pendingDistribution(ds, MARKET);
        assertLe(dist, pool - minAmt, "C: not capped at pool - min");
    }

    // ---------------------------------------------------------------- D
    function testFuzz_monotoneInElapsed(uint128 pool_, uint128 min_, uint32 e1, uint32 e2) public {
        uint256 pool = bound(uint256(pool_), 1, 1e30);
        uint256 minAmt = bound(uint256(min_), 0, pool);
        uint256 a = bound(uint256(e1), 0, block.timestamp - 1);
        uint256 b = bound(uint256(e2), 0, block.timestamp - 1);
        // order the two elapsed times, otherwise the assertion is meaningless:
        // fuzzing supplies a and b independently, so dA > dB is legitimately common.
        if (a > b) { (a, b) = (b, a); }

        _seed(pool, minAmt, FP, block.timestamp - a);
        (uint256 dA,) = h.pendingDistribution(ds, MARKET);
        _seed(pool, minAmt, FP, block.timestamp - b);
        (uint256 dB,) = h.pendingDistribution(ds, MARKET);

        assertLe(dA, dB, "D: less elapsed time produced more distribution");
    }

    // ---------------------------------------------------------------- E
    function test_zeroCasesReturnZero(uint128 pool_, uint128 min_, uint32 rate_) public {
        uint256 pool = bound(uint256(pool_), 0, 1e33);
        uint256 minAmt = bound(uint256(min_), 0, 1e33);
        uint256 rate = bound(uint256(rate_), 0, 1e30);
        _seed(pool, minAmt, rate, block.timestamp - 1000);

        (uint256 dist,) = h.pendingDistribution(ds, MARKET);
        // whichever zero condition holds, distribution must be exactly zero
        if (pool == 0 || rate == 0 || pool <= minAmt) {
            assertEq(dist, 0, "E: expected zero distribution");
        }
    }

    // ---------------------------------------------------------------- F
    function testFuzz_freshMarketReportsZeroElapsed() public {
        _seed(1e24, 0, FP, 0);
        assertEq(h.secondsSinceDistributed(ds, MARKET), 0, "F: never-distributed market reported elapsed time");
    }

    function testFuzz_elapsedMatchesClock(uint128 pool_, uint32 elapsed_) public {
        uint256 pool = bound(uint256(pool_), 1, 1e24);
        uint256 elapsed = bound(uint256(elapsed_), 1, block.timestamp - 1);
        _seed(pool, 0, FP, block.timestamp - elapsed);
        assertEq(h.secondsSinceDistributed(ds, MARKET), elapsed, "F: elapsed mismatch");
    }
}
