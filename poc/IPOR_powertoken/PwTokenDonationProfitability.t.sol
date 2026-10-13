// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.26;

import "../TestCommons.sol";
import "../PowerTokensTestsSystem.sol";
import "../../contracts/interfaces/IPowerTokenStakeService.sol";
import "../../contracts/interfaces/IPowerTokenInternal.sol";
import "../../contracts/interfaces/IPowerToken.sol";
import "../../contracts/mocks/tokens/MockToken.sol";

/// @notice Why the donation mechanism in PwTokenDonationAttack.t.sol is NOT
///         economically exploitable against a pool with more than one holder.
///
///         The attack file proves the mechanism: a bare ERC-20 transfer inflates
///         `rate = balanceOf(this) * 1e18 / baseTotalSupply`, and the next depositor
///         is credited `amount * 1e18 / rate`, which rounds to zero once the
///         donation exceeds their deposit. Their tokens end up in the contract.
///
///         A mechanism is only a vulnerability if someone profits by it. The donor
///         is diluted along with everyone else. Writing f for the attacker's share
///         of base supply:
///
///             attacker stakes A, contract holds I + A, rate = 1
///             attacker donates D   -> rate = 1 + D/(I+A)
///             attacker redeems A   -> receives A * (1 + D/(I+A))
///             net                  = -D + D*A/(I+A) = -D*(1 - f)
///
///         Strictly negative for every f < 1, break-even only at f == 1. On the live
///         Ethereum deployment `_baseTotalSupply` is ~10.93e6 IPOR, so f == 1 means
///         buying the entire outstanding supply — not an attack.
///
///         The fee-free `redeemPwToken` path does not change this: it returns only
///         the attacker's pro-rata share, so it cannot exceed D unless f == 1.
///
///         These tests pin the sign of the result so it cannot be lost to a later
///         refactor. If deposits ever became creditable without a proportional
///         token pull, or a caller could write base directly, `attackerEndsDown`
///         fails.
contract PwTokenDonationProfitabilityTest is TestCommons {
    PowerTokensTestsSystem internal _system;
    address internal _router;
    address internal _powerToken;
    address internal _iporToken;
    uint256 internal _coolDown;

    address internal _attacker;
    address internal _incumbent;

    uint256 internal constant UNIT = 1e18;

    function setUp() external {
        _system = new PowerTokensTestsSystem();
        _router = _system.router();
        _powerToken = _system.powerToken();
        _iporToken = _system.iporToken();
        _coolDown = _system.COOL_DOWN_IN_SECONDS();

        _attacker = _getUserAddress(1);
        _incumbent = _getUserAddress(2);

        _system.makeAllApprovals(_attacker);
        _system.makeAllApprovals(_incumbent);
        _system.transferIporToken(_attacker, 10_000_000 * UNIT);
        _system.transferIporToken(_incumbent, 10_000_000 * UNIT);
    }

    /// @dev The whole attack, end to end, from the attacker's point of view.
    function test_attackerEndsDown_afterDonateAndRedeem() external {
        uint256 attackerStart = MockToken(_iporToken).balanceOf(_attacker);

        vm.prank(_incumbent);
        IPowerTokenStakeService(_router).stakeGovernanceTokenToPowerToken(
            _incumbent,
            1_000_000 * UNIT
        );

        vm.prank(_attacker);
        IPowerTokenStakeService(_router).stakeGovernanceTokenToPowerToken(_attacker, 1_000 * UNIT);

        uint256 baseSupply = IPowerTokenInternal(_powerToken).totalSupplyBase();
        assertGt(baseSupply, 1_000 * UNIT, "attacker must not own the whole ledger");

        vm.prank(_attacker);
        MockToken(_iporToken).transfer(_powerToken, 500_000 * UNIT);

        uint256 attackerPwToken = IPowerToken(_powerToken).balanceOf(_attacker);
        assertGt(attackerPwToken, 0);

        vm.prank(_attacker);
        IPowerTokenStakeService(_router).pwTokenCooldown(attackerPwToken);
        vm.warp(block.timestamp + _coolDown + 1);

        vm.prank(_attacker);
        IPowerTokenStakeService(_router).redeemPwToken(_attacker);

        uint256 attackerEnd = MockToken(_iporToken).balanceOf(_attacker);

        // The donation was pure cost. The attacker got their stake back and a
        // slice of their own donation, and that slice is smaller than the donation.
        assertLt(attackerEnd, attackerStart, "KEY: a donation attack must cost the attacker");
    }

    /// @dev Same shape, but checking the magnitude against the donation itself.
    function test_recoveryIsStrictlyLessThanDonation() external {
        uint256 donation = 500_000 * UNIT;
        uint256 attackerStake = 1_000 * UNIT;

        vm.prank(_incumbent);
        IPowerTokenStakeService(_router).stakeGovernanceTokenToPowerToken(
            _incumbent,
            1_000_000 * UNIT
        );

        vm.prank(_attacker);
        IPowerTokenStakeService(_router).stakeGovernanceTokenToPowerToken(_attacker, attackerStake);

        vm.prank(_attacker);
        MockToken(_iporToken).transfer(_powerToken, donation);

        uint256 attackerPwToken = IPowerToken(_powerToken).balanceOf(_attacker);
        vm.prank(_attacker);
        IPowerTokenStakeService(_router).pwTokenCooldown(attackerPwToken);
        vm.warp(block.timestamp + _coolDown + 1);

        // Stake before redeem; donate+redeem are the attack.
        uint256 before = MockToken(_iporToken).balanceOf(_attacker);
        vm.prank(_attacker);
        IPowerTokenStakeService(_router).redeemPwToken(_attacker);
        uint256 recovered = MockToken(_iporToken).balanceOf(_attacker) - before;

        assertLt(recovered, donation, "KEY: recovered must be less than donated");
        assertGt(recovered, 0, "the attacker does recover a pro-rata slice");
    }

    /// @dev Fuzz the sign of the result across pool shapes.
    ///
    ///      Precondition asserted inline: the incumbent's stake strictly exceeds
    ///      the attacker's, which guarantees f < 1 for the attacker.
    function testFuzz_donationAlwaysCostsTheAttacker(
        uint96 incumbentSeed,
        uint96 attackerSeed,
        uint96 donationSeed
    ) external {
        uint256 incumbentStake = (uint256(incumbentSeed) % 1_000_000) * UNIT + 1 * UNIT;
        uint256 attackerStake = (uint256(attackerSeed) % 100_000) * UNIT + 1 * UNIT;
        uint256 donation = (uint256(donationSeed) % 1_000_000) * UNIT + 1 * UNIT;

        // Guarantee f < 1 rather than relying on the modulo ranges lining up.
        vm.assume(incumbentStake > attackerStake);

        uint256 attackerStart = MockToken(_iporToken).balanceOf(_attacker);

        vm.prank(_incumbent);
        IPowerTokenStakeService(_router).stakeGovernanceTokenToPowerToken(
            _incumbent,
            incumbentStake
        );

        vm.prank(_attacker);
        IPowerTokenStakeService(_router).stakeGovernanceTokenToPowerToken(_attacker, attackerStake);

        assertGt(
            IPowerTokenInternal(_powerToken).totalSupplyBase(),
            attackerStake,
            "precondition: attacker must not own the whole base ledger"
        );

        vm.prank(_attacker);
        MockToken(_iporToken).transfer(_powerToken, donation);

        uint256 attackerPwToken = IPowerToken(_powerToken).balanceOf(_attacker);
        vm.prank(_attacker);
        IPowerTokenStakeService(_router).pwTokenCooldown(attackerPwToken);
        vm.warp(block.timestamp + _coolDown + 1);

        vm.prank(_attacker);
        IPowerTokenStakeService(_router).redeemPwToken(_attacker);

        uint256 attackerEnd = MockToken(_iporToken).balanceOf(_attacker);

        assertLt(
            attackerEnd,
            attackerStart,
            "donation attack must never be profitable while f < 1"
        );
    }
}