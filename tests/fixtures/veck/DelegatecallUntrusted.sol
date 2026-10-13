// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ModuleExecutor {
    address public owner;

    // BUG: delegatecall to a user-supplied target runs attacker code in this
    // contract's storage; writing slot 0 overwrites `owner`.
    function execute(address target, bytes memory data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "exec failed");
    }

    function executeFromModule(address module, bytes calldata data) external {
        (bool ok, ) = module.delegatecall(data);
        require(ok, "module failed");
    }
}
