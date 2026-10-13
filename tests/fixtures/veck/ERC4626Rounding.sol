// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24";

contract RoundingVault {
    uint256 public totalSupply;
    uint256 public totalAssets;
    uint8 public decimalsOffset;

    // BUG: empty-vault branch mints shares 1:1, so a donation inflates
    // totalAssets and later depositors round down to zero shares.
    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalSupply() == 0) {
            return assets;
        }
        return (assets * totalSupply) / totalAssets;
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        return convertToShares(assets);
    }
}
