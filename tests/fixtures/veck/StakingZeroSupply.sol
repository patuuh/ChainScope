// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract StakingRewards {
    uint256 public rewardPerTokenStored;
    uint256 public totalSupply;
    uint256 public rewardRate;

    // BUG: at totalSupply == 0 the accumulator is written anyway, so the
    // entire emission is captured by the first staker to appear.
    function updateReward(address account) public returns (uint256) {
        if (totalSupply == 0) {
            return rewardPerTokenStored;
        }
        rewardPerTokenStored += (rewardRate * 1e18) / totalSupply;
        return rewardPerTokenStored;
    }

    function earned(address account) external view returns (uint256) {
        return rewardPerTokenStored * stake[account] / 1e18;
    }

    mapping(address => uint256) public stake;
}
