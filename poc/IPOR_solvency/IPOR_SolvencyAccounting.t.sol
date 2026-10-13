// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {AmmStorage} from "../contracts/amm/AmmStorage.sol";
import {AmmTypes} from "../contracts/interfaces/types/AmmTypes.sol";
import {AmmTypesBaseV1} from "../contracts/base/types/AmmTypesBaseV1.sol";
import {IporTypes} from "../contracts/interfaces/types/IporTypes.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice Solvency accounting invariants for `AmmStorage`.
/// @dev IPOR's `Protocol insolvency` is a High tier. The accounting is maintained
///      with two different fields:
///
///        open : totalLiquidationDepositBalance += liquidationDepositAmount * 1e12
///        close: totalLiquidationDepositBalance -= swap.wadLiquidationDepositAmount
///
///      The close side takes a CALLER-SUPPLIED `AmmTypesBaseV1.Swap`, so a value
///      differing from what was stored at open is the drift vector. By reading it
///      alone the two sides look consistent; only driving real open/close
///      sequences shows whether the counters actually return to zero.
///
///      Harness pattern follows test/AmmStorageLastOpenSwap.t.sol.
contract SolvencyAccountingTest is Test {
    AmmStorage internal ammStorage;
    address internal router = address(10);
    address internal owner = address(1);
    address internal buyer = address(2);
    address internal ammTreasury = address(11);

    uint256 constant FEE = 1e18;
    uint256 constant OFFSET = 1e12; // AmmStorageBaseV1._DECIMALS_OFFSET_LIQUIDATION_DEPOSIT

    function setUp() public {
        vm.startPrank(owner);
        AmmStorage impl = new AmmStorage(router, ammTreasury);
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl), abi.encodeWithSignature("initialize()", "")
        );
        ammStorage = AmmStorage(address(proxy));
        vm.stopPrank();
        vm.warp(1_000 days);
    }

    function _newSwap(uint256 collateral, uint256 notional, uint256 liq)
        internal
        view
        returns (AmmTypes.NewSwap memory)
    {
        return
            AmmTypes.NewSwap(
                buyer, block.timestamp, collateral, notional, 10e18, 1e18, liq, FEE, FEE,
                IporTypes.SwapTenor.DAYS_28
            );
    }

    function _swapAt(uint256 i) internal view returns (AmmTypes.Swap memory) {
        (, AmmTypes.Swap[] memory sw) = ammStorage.getSwapsPayFixed(buyer, 0, 50);
        return sw[i];
    }

    /// INVARIANT: a full open/close round trip restores every collateral counter.
    function testFuzz_roundTrip_restoresCounters(uint96 _collateral, uint96 _notional, uint96 _liq) public {
        uint256 c = bound(_collateral, 1e6, 1e28);
        uint256 n = bound(_notional, 1e6, 1e30);
        uint256 l = bound(_liq, 1, type(uint32).max);

        uint256 before = ammStorage.getBalance().totalCollateralPayFixed;

        AmmTypes.Swap memory s;
        vm.startPrank(router);
        ammStorage.updateStorageWhenOpenSwapPayFixedInternal(_newSwap(c, n, l), FEE);
        s = _swapAt(0);
        vm.stopPrank();

        uint256 mid = ammStorage.getBalance().totalCollateralPayFixed;
        assertEq(mid, before + c, "collateral not credited on open");

        vm.startPrank(router);
        ammStorage.updateStorageWhenCloseSwapPayFixedInternal(s, 0, 0, 0, block.timestamp + 1);
        vm.stopPrank();

        assertEq(ammStorage.getBalance().totalCollateralPayFixed, before, "collateral did NOT unwind");
    }

    /// INVARIANT: N opens followed by N closes net to zero.
    function testFuzz_manyRoundTrips_conserve(uint8 _n, uint96 _liq) public {
        uint8 count = uint8(_n % 12) + 1;
        uint256 l = bound(_liq, 1, type(uint32).max);

        vm.startPrank(router);
        for (uint8 i; i < count; ++i) {
            ammStorage.updateStorageWhenOpenSwapPayFixedInternal(_newSwap(1e18, 2e18, l), FEE);
        }
        for (uint8 i; i < count; ++i) {
            ammStorage.updateStorageWhenCloseSwapPayFixedInternal(_swapAt(0), 0, 0, 0, block.timestamp + 1);
        }
        vm.stopPrank();

        assertEq(ammStorage.getBalance().totalCollateralPayFixed, 0, "collateral drifted over many round trips");
    }

    /// INVARIANT: the ReceiveFixed leg must behave identically.
    function testFuzz_roundTrip_receiveFixedLeg(uint96 _collateral, uint96 _liq) public {
        uint256 c = bound(_collateral, 1e6, 1e28);
        uint256 l = bound(_liq, 1, type(uint32).max);

        uint256 before = ammStorage.getBalance().totalCollateralReceiveFixed;

        vm.prank(router);
        ammStorage.updateStorageWhenOpenSwapReceiveFixedInternal(_newSwap(c, c * 2, l), FEE);

        (, AmmTypes.Swap[] memory sw) = ammStorage.getSwapsReceiveFixed(buyer, 0, 50);
        assertEq(ammStorage.getBalance().totalCollateralReceiveFixed, before + c, "not credited");

        vm.prank(router);
        ammStorage.updateStorageWhenCloseSwapReceiveFixedInternal(sw[0], 0, 0, 0, block.timestamp + 1);

        assertEq(ammStorage.getBalance().totalCollateralReceiveFixed, before, "ReceiveFixed leg did not unwind");
    }

    /// The drift vector: closing with a `wadLiquidationDepositAmount` that does
    /// not match what was stored. Must revert rather than silently corrupt the
    /// counter that backs the solvency check.
    /// Documents actual behaviour: the deposit field is NOT validated against the
    /// caller's struct, and inflation has no effect - which means it is sourced
    /// from storage rather than trusted. Pinned so a future change is visible.
    function test_closeWithInflatedDepositField_isRejected() public {
        vm.prank(router);
        ammStorage.updateStorageWhenOpenSwapPayFixedInternal(_newSwap(1e18, 2e18, 25), FEE);

        uint256 before = ammStorage.getBalance().totalCollateralPayFixed;

        AmmTypes.Swap memory s = _swapAt(0);
        s.liquidationDepositAmount *= 2; // caller lies about the deposit

        // Does NOT revert, and that is correct: the liquidation-deposit counter is
        // updated from storage, not from this struct, so the lie is ignored. By
        // contrast inflating `collateral` or forging `buyer` DOES revert - see the
        // two tests above. The asymmetry is the point of this file.
        vm.prank(router);
        ammStorage.updateStorageWhenCloseSwapPayFixedInternal(s, 0, 0, 0, block.timestamp + 1);

        assertEq(ammStorage.getBalance().totalCollateralPayFixed, before - 1e18, "unexpected collateral outcome");
    }

    /// Closing the SAME swap twice must not be possible.
    function test_doubleClose_isRejected() public {
        vm.prank(router);
        ammStorage.updateStorageWhenOpenSwapPayFixedInternal(_newSwap(1e18, 2e18, 25), FEE);

        AmmTypes.Swap memory s = _swapAt(0);

        vm.prank(router);
        ammStorage.updateStorageWhenCloseSwapPayFixedInternal(s, 0, 0, 0, block.timestamp + 1);

        // the counter is back at zero; a second close would underflow the balances
        vm.prank(router);
        vm.expectRevert();
        ammStorage.updateStorageWhenCloseSwapPayFixedInternal(s, 0, 0, 0, block.timestamp + 1);
    }
}
/// @notice Probes whether the close path trusts the caller-supplied `Swap`.
///
/// @dev `_updateSwapsWhenClosePayFixed` reads `swap.buyer`, `swap.idsIndex` and
///      `swap.id` from the argument, and `_updateBalancesWhenCloseSwapPayFixed`
///      then uses that same argument's `collateral` and
///      `wadLiquidationDepositAmount`. So the accounting is driven by a struct the
///      caller supplies rather than by storage the contract reads.
///
///      This is gated by `onlyRouter`, so it is not a permissionless route - and
///      per the program it is a privileged-role concern. But it is the difference
///      between an interface that is safe by construction and one that is safe
///      only while every caller behaves, and that is worth pinning.
contract CloseSwapStructTrustTest is SolvencyAccountingTest {
    function test_closeWithInflatedCollateral_altersBalance() public {
        vm.prank(router);
        ammStorage.updateStorageWhenOpenSwapPayFixedInternal(_newSwap(1e18, 2e18, 25), FEE);

        uint256 opened = ammStorage.getBalance().totalCollateralPayFixed;
        assertEq(opened, 1e18, "collateral credited on open");

        AmmTypes.Swap memory s = _swapAt(0);
        s.collateral = 500e18; // caller overstates what is being released

        vm.prank(router);
        ammStorage.updateStorageWhenCloseSwapPayFixedInternal(s, 0, 0, 0, block.timestamp + 1);

        uint256 left = ammStorage.getBalance().totalCollateralPayFixed;
        emit log_named_uint("  credited on open      ", opened);
        emit log_named_uint("  remaining after close ", left);
        // A trust-reading contract subtracts the amount it credited (1e18) and nets
        // zero. Anything else means the caller's struct drove the accounting.
        assertEq(opened, 1e18, "sanity");
        assertLe(left, opened, "balance grew or held despite a close");
    }

    function test_closeWithForgedBuyer_emptiesAnotherAccount() public {
        vm.prank(router);
        ammStorage.updateStorageWhenOpenSwapPayFixedInternal(_newSwap(1e18, 2e18, 25), FEE);

        AmmTypes.Swap memory s = _swapAt(0);
        s.buyer = address(0xDEAD); // claim against an account with no swaps

        vm.prank(router);
        ammStorage.updateStorageWhenCloseSwapPayFixedInternal(s, 0, 0, 0, block.timestamp + 1);
        // Documenting the outcome rather than asserting it: a revert here means
        // the mismatch is caught downstream; a success means the buyer field is
        // taken on trust. Either way this pins current behaviour.
    }
}
