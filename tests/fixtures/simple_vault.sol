// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Ownable {
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
}

contract SimpleVault is Ownable {
    enum VaultState { Inactive, Active, Paused, Closed }

    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    VaultState public state;
    IERC20 public token;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event StateChanged(VaultState from, VaultState to);

    function activate() external onlyOwner {
        require(state == VaultState.Inactive, "Not inactive");
        state = VaultState.Active;
        emit StateChanged(VaultState.Inactive, VaultState.Active);
    }

    function deposit(uint256 amount) external {
        require(state == VaultState.Active, "Not active");
        require(amount > 0, "Zero amount");
        balances[msg.sender] += amount;
        totalDeposits += amount;
        token.transfer(address(this), amount);
        emit Deposited(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        require(state == VaultState.Active, "Not active");
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function emergencyWithdraw() external onlyOwner {
        uint256 bal = address(this).balance;
        (bool success, ) = owner.call{value: bal}("");
        require(success, "Transfer failed");
    }

    function pause() external onlyOwner {
        require(state == VaultState.Active, "Not active");
        state = VaultState.Paused;
    }

    function close() external onlyOwner {
        state = VaultState.Closed;
    }

    function migrateToNew(address newVault) external onlyOwner {
        (bool success, ) = newVault.delegatecall(abi.encodeWithSignature("migrate()"));
        require(success, "Migration failed");
    }

    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
    }
}
