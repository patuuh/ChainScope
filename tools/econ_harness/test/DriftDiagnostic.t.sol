// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import {IVaultR, IERC20R} from "./RoundingDrift.t.sol";

/// @notice Diagnostic only: print every step of a single deposit so a failed
///         drift cycle can be attributed to a specific cause instead of guessed
///         at. Run with TARGET_VAULT / FORK_BLOCK set.
contract DriftDiagnosticTest is Test {
    address attacker = makeAddr("diag");
    uint256 constant W = 1e18;

    function test_diagnose_deposit() public {
        address vault = vm.envOr("TARGET_VAULT", address(0));
        if (vault == address(0)) {
            emit log("TARGET_VAULT unset");
            return;
        }
        require(vm.envOr("FORK_BLOCK", uint256(0)) > 0, "FORK_BLOCK required");
        vm.createSelectFork(
            vm.envOr("RPC_URL", string("https://ethereum.publicnode.com")),
            vm.envOr("FORK_BLOCK", uint256(0))
        );

        address asset = vm.envOr("TARGET_ASSET", address(0));
        if (asset == address(0)) asset = IVaultR(vault).asset();
        emit log_named_address("asset            ", asset);
        emit log_named_uint("totalAssets      ", IVaultR(vault).totalAssets());
        emit log_named_uint("totalSupply      ", IVaultR(vault).totalSupply());
        emit log_named_uint("convertToShares  ", IVaultR(vault).convertToShares(W));

        deal(asset, attacker, 1000 * W);
        emit log_named_uint("attacker balance ", IERC20R(asset).balanceOf(attacker));
        emit log_named_uint("vault balance pre", IERC20R(asset).balanceOf(vault));

        vm.prank(attacker);
        bool ok = IERC20R(asset).approve(vault, type(uint256).max);
        emit log_named_uint("approve ok       ", ok ? 1 : 0);
        emit log_named_uint("allowance        ", IERC20R(asset).allowance(attacker, vault));

        // the deposit itself, isolated
        vm.prank(attacker);
        try IVaultR(vault).deposit(W, attacker) returns (uint256 minted) {
            emit log_named_uint("DEPOSIT minted   ", minted);
        } catch (bytes memory reason) {
            emit log_named_bytes("DEPOSIT reverted ", reason);
        }

        emit log_named_uint("vault balance post", IERC20R(asset).balanceOf(vault));
        emit log_named_uint("attacker bal post ", IERC20R(asset).balanceOf(attacker));
        emit log_named_uint("totalSupply post  ", IVaultR(vault).totalSupply());

        // Precise round-trip: deposit W, redeem exactly what was minted, and
        // report every intermediate number. A per-cycle loss here is the drift
        // signal, so it must be exact rather than inferred from a delta.
        uint256 pre = IERC20R(asset).balanceOf(attacker);
        uint256 expectedShares = IVaultR(vault).convertToShares(W);
        emit log_named_uint("RT pre-balance     ", pre);
        emit log_named_uint("RT expectedShares ", expectedShares);

        vm.prank(attacker);
        uint256 got = IVaultR(vault).deposit(W, attacker);
        emit log_named_uint("RT minted         ", got);
        emit log_named_uint("RT convertToAssets", IVaultR(vault).convertToAssets(got));

        vm.prank(attacker);
        uint256 back;
        try IVaultR(vault).redeem(got, attacker, attacker) returns (uint256 b) {
            back = b;
        } catch (bytes memory reason) {
            emit log_named_bytes("RT redeem reverted", reason);
        }
        emit log_named_uint("RT returned assets", back);
        emit log_named_uint("RT post-balance   ", IERC20R(asset).balanceOf(attacker));
        emit log_named_int ("RT net            ", int256(IERC20R(asset).balanceOf(attacker)) - int256(pre));
        emit log_named_uint("RT vault assets   ", IVaultR(vault).totalAssets());

        // Two identical deposits, each measured on its own. If the cost differs
        // between them the discrepancy is state-dependent, which points at a fee
        // or a rate limit rather than at rounding.
        for (uint256 i = 1; i <= 2; i++) {
            uint256 b0 = IERC20R(asset).balanceOf(attacker);
            uint256 v0 = IVaultR(vault).totalAssets();
            uint256 s0 = IVaultR(vault).totalSupply();
            vm.prank(attacker);
            uint256 m = IVaultR(vault).deposit(W, attacker);
            emit log_named_uint("DEP cost         ", b0 - IERC20R(asset).balanceOf(attacker));
            emit log_named_uint("DEP minted       ", m);
            emit log_named_uint("DEP vaultAssets+ ", IVaultR(vault).totalAssets() - v0);
            emit log_named_uint("DEP supplyDelta  ", IVaultR(vault).totalSupply() - s0);
        }
    }
}
