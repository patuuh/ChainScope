// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@account-abstraction/utils/BasePaymaster.sol";

contract UnsignedGasPaymaster is BasePaymaster {
    struct Request {
        address sender;
        uint256 nonce;
        uint256 deadline;
    }

    mapping(address => mapping(uint256 => bool)) public used;

    // BUG: `preVerificationGas` (and every other field that changes the cost)
    // is NOT part of the signed commitment hash, so a relayer can inflate it
    // after the user signs and drain the paymaster's EntryPoint deposit.
    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 hash,
        uint256 maxCost
    ) internal override returns (bytes memory context, uint256 validationData) {
        Request memory req = abi.decode(userOp.paymasterAndData[4:], (Request));
        require(!used[req.sender][req.nonce], "replayed");
        require(verifyingSigner() == entryPoint.getUserOpHash(userOp), "bad signer");
        used[req.sender][req.nonce] = true;
        validationData = 0;
        return ("", validationData);
    }

    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) external override {}

    function verifyingSigner() internal view returns (address) {
        return owner();
    }
}
