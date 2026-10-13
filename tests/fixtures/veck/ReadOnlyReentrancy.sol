// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
}

contract ReadOnlyReentrantVault {
    ICurvePool constant curve = ICurvePool(0x0000000000000000000000000000000000000001);
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    // BUG: `totalAssets` is updated AFTER the token transfer, so during the
    // transfer a reentrant read of get_virtual_price()/shares sees stale state.
    function deposit(uint256 amount) external {
        totalAssets += amount;
        token.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
    }

    function pricePerShare() external view returns (uint256) {
        return curve.get_virtual_price() * totalAssets / shares[msg.sender];
    }

    address public token = address(0);
}
