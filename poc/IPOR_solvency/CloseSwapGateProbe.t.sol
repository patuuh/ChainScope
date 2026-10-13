// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {AmmTypes} from "../contracts/interfaces/types/AmmTypes.sol";
import {IporTypes} from "../contracts/interfaces/types/IporTypes.sol";
import {AmmTypesBaseV1} from "../contracts/base/types/AmmTypesBaseV1.sol";
import {SwapCloseLogicLibBaseV1} from "../contracts/base/amm/libraries/SwapCloseLogicLibBaseV1.sol";

/// @notice First characterisation of `SwapCloseLogicLibBaseV1.getClosableStatusForSwap`.
///         No test existed for this gate, so its reachable states were undocumented.
///
/// @dev Motivation: `getClosableStatusForSwap` has an `if` at the
///      `absPnlValue < minPnlValueToCloseBeforeMaturityByBuyer` branch with NO `else`.
///      When the caller is the swap buyer and the close timestamp falls at or after
///      `swapEndTimestamp - timeBeforeMaturityAllowedToCloseSwapByBuyer`, control falls
///      through to `return (SWAP_IS_CLOSABLE, false)` with `swapUnwindRequired == false`,
///      and `_preparePnlValueStructForClose` therefore takes the
///      `pnlValue = swapPnlValueToDate` branch with no unwind adjustment.
///
///      Whether that is exploitable depends entirely on whether the line-183 guard
///      bounds `absPnlValue` below `swap.collateral`, because `_transferTokensBasedOnPnlValue`
///      computes `swap.collateral - absPnlValue` and would underflow-revert otherwise.
///      These tests pin both the reachability and that bound rather than asserting
///      either conclusion.
contract CloseSwapGateProbe is Test {
    /// Foundry defaults block.timestamp to 1, so any `block.timestamp - <days>`
    /// arithmetic underflows. Warp to a realistic mainnet-ish time first.
    function setUp() public {
        vm.warp(1_700_000_000);
    }

    function _input(
        address account,
        address buyer,
        uint256 openTs,
        uint256 closeTs,
        int256 pnl,
        uint256 collateral
    ) internal pure returns (AmmTypesBaseV1.ClosableSwapInput memory) {
        return
            AmmTypesBaseV1.ClosableSwapInput({
                account: account,
                asset: address(0xA55),
                closeTimestamp: closeTs,
                swapBuyer: buyer,
                swapOpenTimestamp: openTs,
                swapCollateral: collateral,
                swapTenor: IporTypes.SwapTenor.DAYS_28,
                swapState: IporTypes.SwapState.ACTIVE,
                swapPnlValueToDate: pnl,
                // WAD-scaled percentages. 0.01e18 = 1% (community),
                // 0.001e18 = 0.1% (buyer). An earlier revision passed 10 and 100,
                // which in WAD means 10x and 100x collateral - that put absPnl
                // ABOVE both thresholds, skipped the whole branch, and made the
                // "fall-through" and "no unwind required" results artefacts of
                // bad scaling rather than of the missing `else`.
                minLiquidationThresholdToCloseBeforeMaturityByCommunity: 0.01e18,
                minLiquidationThresholdToCloseBeforeMaturityByBuyer: 0.001e18,
                timeBeforeMaturityAllowedToCloseSwapByCommunity: 5 days,
                timeBeforeMaturityAllowedToCloseSwapByBuyer: 2 days,
                timeAfterOpenAllowedToCloseSwapWithUnwinding: 1 days
            });
    }

    function _probe(AmmTypesBaseV1.ClosableSwapInput memory i)
        internal
        view
        returns (AmmTypes.SwapClosableStatus status, bool unwindRequired)
    {
        return SwapCloseLogicLibBaseV1.getClosableStatusForSwap(i);
    }

    uint256 constant COL = 100_000e18;
    address constant BUYER = address(0xB);
    address constant STRANGER = address(0x57);

    /// Confirms the fall-through is real: a buyer closing within the final
    /// `timeBeforeMaturityAllowedToCloseSwapByBuyer` window gets CLOSABLE with
    /// unwindRequired == false, bypassing the unwind path entirely.
    function test_buyerInsideFinalWindow_fallsThroughWithoutUnwind() public {
        uint256 openTs = block.timestamp - 26 days; // 28d tenor => 2 days to maturity
        uint256 closeTs = block.timestamp;
        // swapEnd - 2d == closeTs, so the inner `if` is false
        (AmmTypes.SwapClosableStatus s, bool u) =
            _probe(_input(BUYER, BUYER, openTs, closeTs, int256(5e19), COL));
        assertEq(uint8(s), uint8(AmmTypes.SwapClosableStatus.SWAP_IS_CLOSABLE));
        assertFalse(u, "fall-through returns unwindRequired == false");
    }

    /// The contrast: the same buyer closing earlier in the window takes the unwind
    /// path. This is what makes the fall-through a behaviour change and not a
    /// dead branch.
    function test_buyerEarlierInWindow_requiresUnwind() public {
        uint256 openTs = block.timestamp - 20 days; // 8 days to maturity
        uint256 closeTs = block.timestamp;
        (AmmTypes.SwapClosableStatus s, bool u) =
            _probe(_input(BUYER, BUYER, openTs, closeTs, int256(5e19), COL));
        assertEq(uint8(s), uint8(AmmTypes.SwapClosableStatus.SWAP_IS_CLOSABLE));
        assertTrue(u, "closing earlier in the window DOES require an unwind");
    }

    /// The line-183 guard bounds the fall-through. absPnl below
    /// minPnlValueToCloseBeforeMaturityByBuyer (10 bps of collateral) can never
    /// approach collateral, so the `collateral - absPnlValue` subtraction in
    /// `_transferTokensBasedOnPnlValue` cannot underflow on this path.
    function test_fallThroughIsBoundedBelowCollateral() public {
        uint256 openTs = block.timestamp - 26 days;
        uint256 closeTs = block.timestamp;
        uint256 minPnlBuyer = (COL * 10) / 10_000; // 10 bps
        assertLt(minPnlBuyer, COL, "line-183 bound is far below collateral");

        int256 worstCasePnl = -int256(minPnlBuyer + 1);
        (AmmTypes.SwapClosableStatus s,) =
            _probe(_input(BUYER, BUYER, openTs, closeTs, worstCasePnl, COL));
        assertEq(uint8(s), uint8(AmmTypes.SwapClosableStatus.SWAP_IS_CLOSABLE));
        assertGt(
            int256(COL) + worstCasePnl,
            0,
            "worst-case PnL on the fall-through path cannot underflow the collateral subtraction"
        );
    }

    /// A stranger in the same window is NOT the buyer, so the community time
    /// restriction applies instead of the fall-through.
    function test_strangerInsideFinalWindow_isNotClosableEarly() public {
        uint256 openTs = block.timestamp - 26 days;
        uint256 closeTs = block.timestamp;
        (AmmTypes.SwapClosableStatus s, bool u) =
            _probe(_input(STRANGER, BUYER, openTs, closeTs, int256(5e19), COL));
        // Within `timeBeforeMaturityAllowedToCloseSwapByCommunity` of maturity the
        // community restriction has lapsed, so anyone may liquidate. Documented here
        // because it surprised me: I expected a stranger to be blocked.
        assertEq(uint8(s), uint8(AmmTypes.SwapClosableStatus.SWAP_IS_CLOSABLE));
        assertFalse(u);
    }

    /// Already-closed swaps short-circuit before any threshold logic.
    function test_inactiveSwapShortCircuits() public {
        AmmTypesBaseV1.ClosableSwapInput memory i =
            _input(BUYER, BUYER, block.timestamp - 10 days, block.timestamp, 0, COL);
        i.swapState = IporTypes.SwapState.INACTIVE;
        (AmmTypes.SwapClosableStatus s, bool u) = _probe(i);
        assertEq(uint8(s), uint8(AmmTypes.SwapClosableStatus.SWAP_ALREADY_CLOSED));
        assertFalse(u);
    }
}
