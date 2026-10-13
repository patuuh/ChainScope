// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract UpgradeableVault {
    address public owner;
    uint256 public totalAssets;

    event Initialized(address owner);

    // BUG: no `initializer` modifier - anyone can call this on the
    // implementation or on a freshly deployed proxy and seize ownership.
    function initialize(address newOwner) external {
        owner = newOwner;
        emit Initialized(newOwner);
    }

    function upgradeTo(address newImpl) public {
        // BUG: no access control at all
        impl = newImpl;
    }

    function destroy() external {
        selfdestruct(payable(owner));
    }

    address public impl;
}
