// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @notice Real-world shape copied from LRTWithdrawalManager._transferAsset, which
///         cs_veck class 14 flagged as an unchecked value transfer despite the
///         return being captured and checked on the next line.
contract CheckedTransfer {
    error EthTransferFailed();

    function _transferAsset(address payable to, uint256 amount) internal {
        (bool sent,) = to.call{ value: amount }("");
        if (!sent) revert EthTransferFailed();
    }

    function sendIt(address payable to, uint256 amount) external {
        _transferAsset(to, amount);
    }
}
