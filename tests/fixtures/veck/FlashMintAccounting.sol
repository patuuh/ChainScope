// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract FlashLender {
    mapping(address => uint256) public balanceOf;
    uint256 public feeBps = 30;

    // BUG: the fee is debited and the balance checked only in the callback's
    // return path - a receiver that returns a malformed value keeps the funds.
    function _flashLoan(address to, uint256 amount) external {
        balanceOf[to] += amount;
        require(IFlashReceiver(to).onFlashLoan(amount, feeBps) == 0, "rejected");
    }

    function flashMint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        require(IFlashReceiver(to).onFlashLoan(amount, feeBps) == 0, "rejected");
    }
}

interface IFlashReceiver {
    function onFlashLoan(uint256 amount, uint256 fee) external returns (uint256);
}
