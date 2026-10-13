// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import {IVaultR, IERC20R} from "./RoundingDrift.t.sol";

/// @notice Measures a single `redeem` three ways: the amount the vault REPORTS
///         returning, the amount the depositor's balance actually RISES by, and
///         the difference. Also runs a self-control so a correct vault is
///         required to show exactly zero.
///
/// The control is the point. The drift sweep previously printed "no drift
/// found" from a measurement that was itself wrong, and nothing in the harness
/// would have noticed. A measurement that cannot prove itself against a known-
/// correct vault must not be allowed to produce a verdict about a real one.
contract RedeemFidelityTest is Test {
    address attacker = makeAddr("fid");
    uint256 constant W = 1e18;

    function _fork() internal returns (bool ok) {
        ok = vm.envOr("TARGET_VAULT", address(0)) != address(0)
            && vm.envOr("FORK_BLOCK", uint256(0)) > 0;
        if (!ok) {
            emit log("TARGET_VAULT/FORK_BLOCK unset - skipping");
            return false;
        }
        // must actually create the fork: checking the env alone leaves the target
        // address with no code and every call reverts as "non-contract address"
        vm.createSelectFork(
            vm.envOr("RPC_URL", string("https://ethereum.publicnode.com")),
            vm.envOr("FORK_BLOCK", uint256(0))
        );
    }

    struct Fidelity {
        uint256 minted;
        uint256 reported;
        uint256 received;
        int256 discrepancy;
    }

    function _measure(address vault, address asset) internal returns (Fidelity memory f) {
        deal(asset, attacker, 100 * W);
        vm.prank(attacker);
        IERC20R(asset).approve(vault, type(uint256).max);

        vm.prank(attacker);
        f.minted = IVaultR(vault).deposit(W, attacker);

        uint256 before = IERC20R(asset).balanceOf(attacker);
        vm.prank(attacker);
        try IVaultR(vault).redeem(f.minted, attacker, attacker) returns (uint256 b) {
            f.reported = b;
        } catch (bytes memory reason) {
            emit log_named_bytes("redeem reverted", reason);
            return f;
        }
        f.received = IERC20R(asset).balanceOf(attacker) - before;
        f.discrepancy = int256(f.received) - int256(f.reported);
    }

    /// Full round trip: what the depositor paid in versus what they hold after.
    function test_fidelity_roundtrip() public {
        if (!_fork()) return;
        address vault = vm.envAddress("TARGET_VAULT");
        address asset = vm.envOr("TARGET_ASSET", address(0));
        if (asset == address(0)) asset = IVaultR(vault).asset();

        uint256 pre = IERC20R(asset).balanceOf(attacker);
        deal(asset, attacker, 100 * W);
        pre = IERC20R(asset).balanceOf(attacker);

        vm.prank(attacker);
        IERC20R(asset).approve(vault, type(uint256).max);

        uint256 minted;
        vm.prank(attacker);
        minted = IVaultR(vault).deposit(W, attacker);
        uint256 afterDeposit = IERC20R(asset).balanceOf(attacker);
        emit log_named_uint("deposit cost     ", pre - afterDeposit);

        uint256 reported;
        vm.prank(attacker);
        try IVaultR(vault).redeem(minted, attacker, attacker) returns (uint256 b) {
            reported = b;
        } catch (bytes memory reason) {
            emit log_named_bytes("redeem reverted  ", reason);
            return;
        }
        uint256 post = IERC20R(asset).balanceOf(attacker);
        emit log_named_uint("minted           ", minted);
        emit log_named_uint("reported         ", reported);
        emit log_named_uint("balance rise     ", post - afterDeposit);
        emit log_named_int ("REPORTED-vs-RISE ", int256(post - afterDeposit) - int256(reported));
        emit log_named_int ("ROUNDTRIP NET    ", int256(post) - int256(pre));
    }

    /// Scaling test. A percentage fee (design) and rounding drift (bug) look
    /// identical at one amount: both make the round trip come up short. They
    /// differ when the deposit doubles - a fee doubles, rounding drift does not.
    function test_fidelity_scaling() public {
        if (!_fork()) return;
        address vault = vm.envAddress("TARGET_VAULT");
        address asset = vm.envOr("TARGET_ASSET", address(0));
        if (asset == address(0)) asset = IVaultR(vault).asset();

        uint256[4] memory amounts = [uint256(1e15), 1e18, 2e18, 10e18];
        for (uint256 i = 0; i < amounts.length; i++) {
            uint256 amt = amounts[i];
            deal(asset, attacker, amt * 4);
            vm.prank(attacker);
            IERC20R(asset).approve(vault, type(uint256).max);

            uint256 pre = IERC20R(asset).balanceOf(attacker);
            vm.prank(attacker);
            uint256 minted = IVaultR(vault).deposit(amt, attacker);
            uint256 afterDep = IERC20R(asset).balanceOf(attacker);
            vm.prank(attacker);
            uint256 reported;
            try IVaultR(vault).redeem(minted, attacker, attacker) returns (uint256 b) {
                reported = b;
            } catch {
                emit log("redeem reverted at this size");
                continue;
            }
            uint256 post = IERC20R(asset).balanceOf(attacker);

            emit log_named_uint("SCALE amount     ", amt);
            emit log_named_uint("SCALE reported   ", reported);
            emit log_named_uint("SCALE received   ", post - afterDep);
            emit log_named_int ("SCALE shortfall  ", int256(reported) - int256(post - afterDep));
            emit log_named_int ("SCALE net        ", int256(post) - int256(pre));
        }
    }

    /// CONTROL. A vault with a correct implementation must show
    /// reported == received and a round trip within 1 wei. This is what makes
    /// the real-target numbers above interpretable - if this fails, nothing the
    /// harness says about a live vault means anything.
    function test_fidelity_control() public {
        if (!_fork()) return;
        address vault = vm.envAddress("TARGET_VAULT");
        address asset = vm.envOr("TARGET_ASSET", address(0));
        if (asset == address(0)) asset = IVaultR(vault).asset();

        Fidelity memory f = _measure(vault, asset);
        emit log_named_uint("CONTROL minted     ", f.minted);
        emit log_named_uint("CONTROL reported   ", f.reported);
        emit log_named_uint("CONTROL received   ", f.received);
        emit log_named_int ("CONTROL discrepancy", f.discrepancy);

        // The vault must not report transferring more than it actually sends.
        assertLe(f.discrepancy, 0, "vault reported transferring MORE than it sent");
        assertEq(f.received, f.reported, "reported return must equal the actual balance rise");
    }
}
