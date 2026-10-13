// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24";

contract FlashGovernance {
    mapping(address => uint256) public votes;
    uint256 public treasury;

    // BUG: voting power is read from the LIVE balance with no checkpoint,
    // so tokens can be flash-borrow, voted with, and returned in one tx.
    function getVotes(address account) public view returns (uint256) {
        return votes[account];
    }

    function propose(address to, uint256 amount) external {
        uint256 power = getVotes(msg.sender);
        require(power > 0, "no votes");
        treasury -= amount;
        payable(to).transfer(amount);
    }
}
