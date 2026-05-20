// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

struct GlobalPosition {
    uint256 amount;
    address holder;
}

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}

interface IVaultCallback {
    function onDeposit(address user, uint256 amount) external;
}

contract AdvancedVault {
    address public owner;
    mapping(address => uint256) public balances;
    bool private _locked;

    struct VaultConfig {
        uint256 maxDeposit;
        uint256 minDeposit;
    }

    modifier nonReentrant() {
        require(!_locked, "Locked");
        _locked = true;
        _;
        _locked = false;
    }

    constructor(address _owner) {
        owner = _owner;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }

    fallback() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        balances[msg.sender] -= amount;
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
    }

    function withdraw(uint256 amount, address to) external nonReentrant {
        balances[msg.sender] -= amount;
        (bool success,) = to.call{value: amount}("");
        require(success);
    }

    function execute(address target, bytes calldata data) external {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "Call failed");
    }

    function query(address target, bytes calldata data) external view returns (bytes memory) {
        (bool ok, bytes memory ret) = target.staticcall(data);
        require(ok, "Static call failed");
        return ret;
    }

    function unsafeAuth() external view returns (bool) {
        return tx.origin == owner;
    }

    function batchAdd(uint256[] memory values) external {
        unchecked {
            for (uint256 i = 0; i < values.length; i++) {
                balances[msg.sender] += values[i];
            }
        }
    }

    function getSlot(uint256 slot) external view returns (uint256 result) {
        assembly {
            result := sload(slot)
        }
    }
}
