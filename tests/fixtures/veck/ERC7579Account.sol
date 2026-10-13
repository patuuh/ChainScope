// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24";

interface IModule {
    function executeFromModule(bytes calldata data) external returns (bytes memory);
}

contract ModularAccount {
    address public owner;
    mapping(address => bool) public installed;

    // BUG: `executeFromExecutor` has no check that the caller is an owner,
    // guardian or authorised executor - any address can drain the account.
    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        external
        returns (bytes[] memory returnData)
    {
        returnData.push(exec(mode, executionCalldata));
    }

    // BUG: modules can be installed without the owner's signature, so an
    // attacker installs a module that runs arbitrary calls.
    function installModule(address module, bytes calldata initData) external {
        installed[module] = true;
        IModule(module).onInstall(initData);
    }

    function supportsModule(address module) external view returns (bool) {
        return installed[module];
    }

    function executeBatch(bytes[] calldata calls) external {
        for (uint256 i = 0; i < calls.length; i++) { calls[i]; }
    }

    function exec(bytes32, bytes calldata) internal returns (bytes memory) { return ""; }
}

interface IModuleInstall {
    function onInstall(bytes calldata) external;
}
