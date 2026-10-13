// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24";

contract FeeOnTransferPool {
    mapping(address => uint256) public reserves;
    address public token;

    // BUG: assumes transferFrom moved exactly `amount`. With a 2% fee-on-transfer
    // token the contract's balance grows slower than `reserves` and it goes
    // insolvent on the first withdrawal.
    function addLiquidity(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        reserves[msg.sender] += amount;
    }

    function removeLiquidity(uint256 shares) external {
        uint256 amount = reserves[msg.sender] / 2;
        reserves[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    function safeTransferFrom(address to, uint256 amount) internal {
        token.transferFrom(to, address(this), amount);
    }
}
