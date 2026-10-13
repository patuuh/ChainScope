// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract UnguardedAdminVault {
    address public owner;
    mapping(address => uint256) public balanceOf;
    address payable public feeRecipient;

    // BUG: all three are externally callable with no access control.
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function withdrawFees(address payable to) external {
        to.transfer(address(this).balance);
    }

    function setOracle(address oracle) external {
        oracleAddress = oracle;
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    address public oracleAddress;

    function onlyOwner_placeholder() internal view {
        require(msg.sender == owner);
    }
}
