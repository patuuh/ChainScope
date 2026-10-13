// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

library ShortfallClassifier {
    /// @notice Decides whether a round-trip shortfall is a designed exit fee or
    ///         a rounding bug.
    ///
    /// Both make a deposit/redeem cycle come up short, and at a single amount
    /// they are indistinguishable. A fee is charged as a proportion of the
    /// deposit, so the shortfall scales with it. Rounding loss is a roughly
    /// fixed number of wei per cycle, so it does not.
    ///
    /// Measuring two sizes and comparing the ratio is the only way to tell them
    /// apart. That logic lives here, separate from the fork plumbing, so it can
    /// be proved against synthetic fee and drift inputs without a network.
    enum Kind {
        NO_SHORTFALL,
        EXIT_FEE,
        ROUNDING_DRIFT
    }

    /// @param smallShort shortfall in wei for the smaller deposit
    /// @param largeShort shortfall in wei for the larger deposit
    /// @param tolerancePct how far the two rates may differ and still be
    ///        treated as proportional
    function classify(int256 smallShort, int256 largeShort, uint256 tolerancePct)
        internal
        pure
        returns (Kind kind, uint256 largeRatePpb)
    {
        // A vault that transferred more than it reported is a different
        // condition entirely; do not fold it into the fee/drift question.
        if (smallShort == 0 && largeShort == 0) {
            return (Kind.NO_SHORTFALL, 0);
        }
        if (smallShort <= 0 || largeShort <= 0) {
            return (Kind.NO_SHORTFALL, 0);
        }
        // 1e15 and 1e18 are the two probe sizes the fork harness measures at.
        //
        // Compare by CROSS-MULTIPLICATION, not by computing a rate in
        // parts-per-billion: at a 1-wei shortfall both rates divide to zero, the
        // comparison sees two equal zeros and calls it a fee. That is the wrong
        // answer for the case it matters most - a fixed wei rounding loss is
        // precisely what drift looks like, and it is what gets missed.
        //
        // proportional <=>  smallShort/1e15 ~= largeShort/1e18
        //                <=>  smallShort * 1e18 ~= largeShort * 1e15
        uint256 lhs = uint256(smallShort) * 1e18;
        uint256 rhs = uint256(largeShort) * 1e15;
        uint256 spread = lhs > rhs ? lhs - rhs : rhs - lhs;
        uint256 scale = lhs > rhs ? lhs : rhs;
        bool proportional = scale == 0 || (spread * 100) / scale <= tolerancePct;

        // rate is only for reporting; it may legitimately be zero at dust sizes
        largeRatePpb = (uint256(largeShort) * 1e9) / 1e18;
        return (proportional ? Kind.EXIT_FEE : Kind.ROUNDING_DRIFT, largeRatePpb);
    }
}
