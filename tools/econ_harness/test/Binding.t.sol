// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import {NaiveVault, OffsetVault, MockToken} from "../src/Fixtures.sol";

/// @notice Executes the donation attack on the fixture vaults and emits the
///         resulting numbers so `script/check_binding.py` can diff them against
///         `core/cs_econ.py`'s predictions.
///
/// If the EVM disagrees with the model here, every number cs_econ reports for a
/// real vault is suspect - so this gates the toolchain, not the vaults.
contract BindingTest is Test {
    struct Result {
        uint256 victimShares;
        uint256 attackerOut;
        int256 attackerProfit;   // signed: a losing attack must report the loss
        uint256 victimLoss;      // unsigned: a loss cannot be negative
    }

    MockToken token;
    NaiveVault naive;
    OffsetVault offsetVault;

    uint256 constant W = 1e18;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {
        token = new MockToken();
        naive = new NaiveVault(address(token));
        offsetVault = new OffsetVault(address(token));
    }

    function _sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a - b : 0;
    }

    /// @dev Mirrors `donation_attack` in cs_econ.py exactly:
    ///      seed -> donate -> victim deposit -> attacker redeems everything.
    ///      Results are returned in a struct rather than four stack slots; this
    ///      function overflows the EVM stack otherwise, and `--via-ir` is not an
    ///      acceptable substitute because it changes the codegen under test.
    function _runDonationAttack(address vault, uint256 seed, uint256 donation, uint256 victimDeposit)
        internal
        returns (Result memory r)
    {
        token.mint(attacker, seed + donation);
        token.mint(victim, victimDeposit);

        // 1. seed
        vm.prank(attacker);
        NaiveVault(vault).deposit(seed);

        // 2. donation: assets rise, supply does not
        vm.prank(attacker);
        NaiveVault(vault).donate(donation);

        // 3. victim deposit
        uint256 predicted = NaiveVault(vault).convertToShares(victimDeposit);
        vm.prank(victim);
        try NaiveVault(vault).deposit(victimDeposit) returns (uint256 minted) {
            r.victimShares = minted;
        } catch {
            r.victimShares = 0;
        }
        assertEq(predicted, r.victimShares, "convertToShares must predict the mint");

        uint256 vaultAssets = NaiveVault(vault).totalAssets();
        uint256 totalSupply = NaiveVault(vault).totalSupply();

        // 4. value the victim's stake on the SAME snapshot cs_econ.py uses:
        //    after the victim deposits, before the attacker redeems. Measuring
        //    after the withdrawal shifts the result by a wei and makes the two
        //    disagree for reasons that have nothing to do with the maths.
        uint256 victimOut = NaiveVault(vault).convertToAssets(r.victimShares);
        r.victimLoss = _sub(victimDeposit, victimOut);

        // attacker redeems everything it holds
        vm.prank(attacker);
        r.attackerOut = NaiveVault(vault).withdraw(totalSupply - r.victimShares);

        // Signed: clamping a losing attack to zero would hide it, and a harness
        // that hides losses misleads exactly as much as a model that invents them.
        r.attackerProfit = int256(r.attackerOut) - int256(seed + donation);
    }

    function _emit(string memory label, Result memory r) internal {
        emit log_named_uint(string.concat("MODEL ", label, " victim_shares"), r.victimShares);
        emit log_named_uint(string.concat("MODEL ", label, " attacker_out  "), r.attackerOut);
        emit log_named_int(string.concat("MODEL ", label, " profit       "), r.attackerProfit);
        emit log_named_uint(string.concat("MODEL ", label, " victim_loss  "), r.victimLoss);
    }

    /// The catastrophic case: a 1-wei seed makes the naive vault mint the victim
    /// zero shares. This is the case a narrow seed sweep cannot see.
    function test_bind_naive_tinySeed() public {
        Result memory r = _runDonationAttack(address(naive), 1, 100 * W, W);
        _emit("naive_tiny", r);
        assertEq(r.victimShares, 0, "naive vault must mint zero shares at a 1-wei seed");
    }

    function test_bind_naive_equalSeed() public {
        Result memory r = _runDonationAttack(address(naive), W, 100 * W, W);
        _emit("naive_equal", r);
        assertGt(r.victimShares, 0, "equal seed must still mint shares");
    }

    function test_bind_offset_isProtected() public {
        Result memory r = _runDonationAttack(address(offsetVault), 1, 100 * W, W);
        _emit("offset_tiny", r);
        assertGt(r.victimShares, 0, "offset vault must still mint shares at a 1-wei seed");
    }

    /// Conservation: what the attacker fails to recover is what the victim loses.
    /// If this fails, one side is mis-accounted and every profit number is suspect.
    function test_conservation_holds_on_naive() public {
        Result memory r = _runDonationAttack(address(naive), 1e3, 100 * W, W);
        emit log_named_int("CONSERVATION attacker_profit", r.attackerProfit);
        emit log_named_uint("CONSERVATION victim_loss     ", r.victimLoss);
        // only meaningful when the attack actually profited
        if (r.attackerProfit > 0) {
            assertLe(_sub(r.victimLoss, uint256(r.attackerProfit)), 2, "loss and profit must agree");
        }
    }
}