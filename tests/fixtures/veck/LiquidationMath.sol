// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract LendingMarket {
    uint256 public liquidationThreshold = 8000;
    uint256 public closeFactor = 5000;
    mapping(address => uint256) public debt;

    // BUG: no liquidation penalty and no reserve check - a liquidator can
    // take the entire collateral for a fraction of the debt.
    function healthFactor(address borrower) external view returns (uint256) {
        uint256 d = debt[borrower];
        if (d == 0) return type(uint256).max;
        return (collateral[borrower] * liquidationThreshold) / d;
    }

    function liquidateBorrow(address borrower) external {
        uint256 seized = collateral[borrower];
        collateral[borrower] = 0;
        debt[borrower] = 0;
        pythToken.transfer(msg.sender, seized);
    }

    mapping(address => uint256) public collateral;
    address public pythToken = address(0);
}
