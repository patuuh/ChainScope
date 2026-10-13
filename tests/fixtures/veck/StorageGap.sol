// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VaultStorageV1 {
    struct OwnerStorage {
        address owner;
    }

    address public owner;
    uint256 public balance;
    uint256[50] private __gap;
}

contract VaultStorageV2 {
    struct OwnerStorage {
        address owner;
    }

    address public owner;
    uint256 public balance;
    bool public paused;
    uint256[49] private __gap;
}
