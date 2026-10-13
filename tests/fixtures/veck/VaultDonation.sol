// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract DonationVault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    uint256 public constant VIRTUAL_SHARES = 1e3;
    uint256 public constant virtualShares = 1e3;

    // BUG: +1 wei of virtual shares is not enough. A donation inflates
    // totalAssets so later depositors round down to 0 shares and the first
    // depositor withdraws everyone's money.
    function convertToShares(uint256 assets) external view returns (uint256) {
        return (assets * totalSupply + 1) / (totalAssets + 1);
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        return convertToShares(assets);
    }

    function skim(address who) external {
        totalAssets -= balanceOf[who];
    }

    mapping(address => uint256) public balanceOf;
}
