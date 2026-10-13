// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @notice The genuine article: the low-level call's success flag is discarded,
///         so execution continues as though the transfer worked.
contract UncheckedTransfer {
    function distribute(address payable[] calldata to, uint256 amount) external {
        for (uint256 i = 0; i < to.length; i++) {
            to[i].call{ value: amount }("");
        }
    }
}
