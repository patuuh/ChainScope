// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import {ShortfallClassifier} from "../src/ShortfallClassifier.sol";

/// @notice Proves the classifier discriminates, with no fork and no network.
///
/// The fork harness can only report what the classifier tells it. If the
/// classifier cannot tell a fee from drift, every live result it produces is
/// ambiguous - and the previous drift sweep did exactly that, reporting a real
/// 0.001% exit fee as an unexplained loss because nothing distinguished the two.
/// These cases pin the decision logic itself, using the actual probe sizes
/// (1e15 and 1e18) the fork harness measures at.
contract ClassifyControlsTest is Test {
    uint256 constant TOL = 20;

    function _rate(uint256 shortfall, uint256 amount) internal pure returns (uint256) {
        return (shortfall * 1e9) / amount;
    }

    /// A flat 0.001% fee: the shortfall scales with the deposit, so both rates
    /// match and this is a fee.
    function test_classifies_proportional_shortfall_as_fee() public pure {
        uint256 smallShort = 1e15 / 100_000; // 0.001%
        uint256 largeShort = 1e18 / 100_000;
        (ShortfallClassifier.Kind kind, uint256 rate) =
            ShortfallClassifier.classify(int256(smallShort), int256(largeShort), TOL);
        assertEq(uint256(kind), uint256(ShortfallClassifier.Kind.EXIT_FEE));
        assertEq(rate, _rate(largeShort, 1e18));
        assertEq(rate, 10_000, "0.001% is 10,000 parts per billion");
    }

    /// A fixed 1-wei loss per cycle: the shortfall does not scale with the
    /// deposit, so this is drift. The reported rate truncates to 0 at dust sizes
    /// - 1 wei at 1e18 is 1e-18, far below one part per billion. That truncation
    /// is exactly why the decision is made by cross-multiplication and not by
    /// comparing rates.
    function test_classifies_flat_shortfall_as_drift() public pure {
        (ShortfallClassifier.Kind kind, uint256 rate) =
            ShortfallClassifier.classify(1, 1, TOL);
        assertEq(uint256(kind), uint256(ShortfallClassifier.Kind.ROUNDING_DRIFT));
        assertEq(rate, 0, "a wei-scale shortfall is below reporting resolution");
    }

    /// A shortfall that is neither perfectly flat nor proportional must not be
    /// forced into a bucket. A 10x rate difference is well outside tolerance.
    function test_classifies_mixed_shortfall_as_drift() public pure {
        // small: 1% of 1e15 ; large: 0.01% of 1e18 -> 100x apart
        uint256 smallShort = 1e15 / 100;
        uint256 largeShort = 1e18 / 10_000;
        (ShortfallClassifier.Kind kind, ) =
            ShortfallClassifier.classify(int256(smallShort), int256(largeShort), TOL);
        assertEq(uint256(kind), uint256(ShortfallClassifier.Kind.ROUNDING_DRIFT));
    }

    function test_zero_shortfall_is_no_shortfall() public pure {
        (ShortfallClassifier.Kind kind, uint256 rate) = ShortfallClassifier.classify(0, 0, TOL);
        assertEq(uint256(kind), uint256(ShortfallClassifier.Kind.NO_SHORTFALL));
        assertEq(rate, 0);
    }

    /// A vault reporting MORE than it transferred is not a fee and not drift.
    /// Folding it into either bucket would misreport a broken vault as healthy.
    function test_negative_shortfall_is_not_classified() public pure {
        (ShortfallClassifier.Kind kind, ) = ShortfallClassifier.classify(-5, -5, TOL);
        assertEq(uint256(kind), uint256(ShortfallClassifier.Kind.NO_SHORTFALL));
    }
}
