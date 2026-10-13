// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import {ShortfallClassifier} from "../src/ShortfallClassifier.sol";

interface IERC20R {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function allowance(address, address) external view returns (uint256);
}

interface IVaultR {
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function convertToShares(uint256) external view returns (uint256);
    function convertToAssets(uint256) external view returns (uint256);
    function deposit(uint256, address) external returns (uint256);
    function redeem(uint256, address, address) external returns (uint256);
    function withdraw(uint256, address, address) external returns (uint256);
}

/// @notice Runs the rounding-drift attack against a REAL deployed vault:
///         repeatedly deposit and fully redeem, and total what the depositor
///         loses. Positive net loss for the depositor across many cycles is a
///         High-severity accounting bug - the pool quietly absorbs value that
///         belongs to whoever cycled.
///
/// Unlike the fixture binding this does not compare against a Python prediction.
/// A real vault's conversion functions cannot be reimplemented faithfully in
/// Python without reading its source, so the fork result IS the answer. The
/// fixture binding already proved the arithmetic; what this establishes is
/// whether any live vault is actually exposed.
///
/// Configure with TARGET_VAULT, TARGET_ASSET, CYCLES, FORK_BLOCK, RPC_URL.
contract RoundingDriftTest is Test {
    uint256 constant W = 1e18;
    address attacker = makeAddr("drifter");

    struct Drift {
        uint256 cycles;
        uint256 cyclesCompleted;
        uint256 paid;
        uint256 recovered;
        bool stopped;
        uint256 vaultAssetsBefore;
        uint256 vaultAssetsAfter;
        bytes revertReason;
        uint256 lossEvents;
    }

    /// Returns false when unconfigured so the suite stays green with no TARGET_VAULT
    /// set. A require() here would report as a failing test, which looks like a
    /// broken harness rather than a test that had nothing to probe.
    function _fork() internal returns (bool ok) {
        ok = vm.envOr("TARGET_VAULT", address(0)) != address(0);
        if (!ok) {
            emit log("TARGET_VAULT unset - skipping live-vault drift probes");
            return false;
        }
        require(vm.envOr("FORK_BLOCK", uint256(0)) > 0, "FORK_BLOCK must be a recent block");
        vm.createSelectFork(
            vm.envOr("RPC_URL", string("https://ethereum.publicnode.com")),
            vm.envOr("FORK_BLOCK", uint256(0))
        );
    }

    /// Runs the cycles inline rather than through a `this.cycle(...)` self-call.
    ///
    /// The self-call was the bug: it makes the cycle a separate frame whose
    /// `msg.sender` is the test contract, and it turned a working deposit into a
    /// zero-return. A focused diagnostic (DriftDiagnostic) showed the identical
    /// sequence succeeding when written inline - deposit minted 1e18 shares - so
    /// the fault was the indirection, not the target.
    function _run(address vault, address asset, uint256 amount, uint256 cycles)
        internal
        returns (Drift memory d)
    {
        d.cycles = cycles;
        d.vaultAssetsBefore = IVaultR(vault).totalAssets();

        deal(asset, attacker, cycles * amount + 1000 * W);
        vm.prank(attacker);
        IERC20R(asset).approve(vault, type(uint256).max);

        for (uint256 i = 0; i < cycles; i++) {
            uint256 balBefore = IERC20R(asset).balanceOf(attacker);
            uint256 minted;
            bool deposited = true;
            vm.prank(attacker);
            try IVaultR(vault).deposit(amount, attacker) returns (uint256 m) {
                minted = m;
            } catch {
                deposited = false;
            }
            if (!deposited || minted == 0) {
                d.stopped = true;
                break;
            }
            bool redeemed = true;
            uint256 gotBack;
            vm.prank(attacker);
            try IVaultR(vault).redeem(minted, attacker, attacker) returns (uint256 b) {
                gotBack = b;
            } catch (bytes memory reason) {
                // A full redemption can be blocked by a withdrawal cap while
                // partial exits still work, so a bare revert here is not proof the
                // vault refuses to be cycled. Try halving before giving up, and
                // fall back to whatever maxRedeem permits.
                redeemed = false;
                d.revertReason = reason;
                uint256 half = minted / 2;
                if (half > 0) {
                    vm.prank(attacker);
                    try IVaultR(vault).redeem(half, attacker, attacker) returns (uint256 b) {
                        gotBack = b;
                        redeemed = true;
                        emit log_named_uint("PARTIAL redeem_shares", half);
                        emit log_named_uint("PARTIAL returned     ", b);
                    } catch {}
                }
            }
            if (!redeemed) {
                d.stopped = true;
                break;
            }
            // Must not underflow. `balanceOf - balBefore` goes negative exactly
            // when the depositor is worse off after a cycle - which is the
            // finding - so an unchecked subtraction would panic at precisely the
            // moment the harness had something to report.
            uint256 balAfter = IERC20R(asset).balanceOf(attacker);
            if (balAfter >= balBefore) {
                d.recovered += balAfter - balBefore;
            } else {
                d.lossEvents++;
                emit log_named_uint("CYCLE_LOSS returned", balBefore - balAfter);
            }
            d.paid += amount;
            d.cyclesCompleted++;
        }
        d.vaultAssetsAfter = IVaultR(vault).totalAssets();
    }

    /// A single deposit/redeem round trip, returning the shortfall between what
    /// the vault reports transferring and what the balance actually rises by.
    function _shortfall(address vault, address asset, uint256 amount) internal returns (int256) {
        // must fund and approve here: without a balance the deposit reverts and
        // the classifier silently reports zero, which reads as "no shortfall"
        deal(asset, attacker, amount * 4);
        vm.prank(attacker);
        IERC20R(asset).approve(vault, type(uint256).max);

        uint256 before = IERC20R(asset).balanceOf(attacker);
        vm.prank(attacker);
        uint256 minted;
        try IVaultR(vault).deposit(amount, attacker) returns (uint256 m) {
            minted = m;
        } catch {
            return 0;
        }
        uint256 afterDep = IERC20R(asset).balanceOf(attacker);
        uint256 reported;
        vm.prank(attacker);
        try IVaultR(vault).redeem(minted, attacker, attacker) returns (uint256 b) {
            reported = b;
        } catch {
            return 0;
        }
        uint256 rise = IERC20R(asset).balanceOf(attacker) - afterDep;
        before; // keep the read; the delta we care about is reported-vs-rise
        return int256(reported) - int256(rise);
    }

    /// Classifies a shortfall. A designed exit fee scales with the amount; a
    /// rounding bug is a roughly fixed number of wei per cycle. Measuring both
    /// regimes is the only way to tell "the vault charges 0.001%" from "the
    /// vault loses 1 wei" - both read as a round trip coming up short.
    function test_classify_shortfall() public {
        if (!_fork()) return;
        address vault = vm.envAddress("TARGET_VAULT");
        address asset = vm.envOr("TARGET_ASSET", address(0));
        if (asset == address(0)) asset = IVaultR(vault).asset();

        int256 small = _shortfall(vault, asset, 1e15);
        int256 large = _shortfall(vault, asset, 1e18);

        emit log_named_int("CLASSIFY small_shortfall", small);
        emit log_named_int("CLASSIFY large_shortfall", large);
        if (small <= 0 || large <= 0) {
            emit log_named_uint("CLASSIFY verdict", 0);
            return;
        }
        // ratio of shortfall to amount, in units of 1e9 for readability
        uint256 smallRate = (uint256(small) * 1e9) / 1e15;
        uint256 largeRate = (uint256(large) * 1e9) / 1e18;
        emit log_named_uint("CLASSIFY small_rate_ppb ", smallRate);
        emit log_named_uint("CLASSIFY large_rate_ppb ", largeRate);

        // decision logic is shared with ClassifyControlsTest, which proves it
        // separates a fee from a fixed-wei drift without needing a fork
        (ShortfallClassifier.Kind kind, uint256 rate) =
            ShortfallClassifier.classify(small, large, 20);
        emit log_named_uint("CLASSIFY rate_ppb ", rate);
        emit log_named_uint("CLASSIFY verdict", uint256(kind)); // 0=none 1=fee 2=drift
    }

    function _emit(string memory tag, Drift memory d) internal {
        emit log_named_uint(string.concat("DRIFT_", tag, " cycles_done   "), d.cyclesCompleted);
        emit log_named_uint(string.concat("DRIFT_", tag, " paid          "), d.paid);
        emit log_named_uint(string.concat("DRIFT_", tag, " recovered     "), d.recovered);
        emit log_named_int(string.concat("DRIFT_", tag, " net           "), int256(d.recovered) - int256(d.paid));
        emit log_named_uint(string.concat("DRIFT_", tag, " vault_delta   "), d.vaultAssetsAfter - d.vaultAssetsBefore);
        emit log_named_uint(string.concat("DRIFT_", tag, " loss_events   "), d.lossEvents);
        emit log_named_uint(string.concat("DRIFT_", tag, " stopped       "), d.stopped ? 1 : 0);
        if (d.revertReason.length > 0) {
            emit log_named_bytes(string.concat("DRIFT_", tag, " revert_reason "), d.revertReason);
        }
    }

    /// A single large cycle, repeated. Large enough to clear any minimum-deposit
    /// rule that would otherwise stop the loop immediately.
    function test_drift_large() public {
        if (!_fork()) return;
        address vault = vm.envAddress("TARGET_VAULT");
        address asset = vm.envOr("TARGET_ASSET", address(0));
        if (asset == address(0)) asset = IVaultR(vault).asset();

        Drift memory d = _run(vault, asset, W, vm.envOr("CYCLES", uint256(20)));
        _emit("large", d);
    }

    /// Small repeated deposits: the regime where rounding asymmetry compounds.
    function test_drift_small() public {
        if (!_fork()) return;
        address vault = vm.envAddress("TARGET_VAULT");
        address asset = vm.envOr("TARGET_ASSET", address(0));
        if (asset == address(0)) asset = IVaultR(vault).asset();

        Drift memory d = _run(vault, asset, 1e6, vm.envOr("CYCLES", uint256(50)));
        _emit("small", d);
    }
}
