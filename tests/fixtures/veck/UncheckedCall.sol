// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract BatchSplitter {
    // BUG: low-level call returns (success, returndata) instead of reverting,
    // and the result is ignored - execution continues assuming it worked.
    function distribute(address payable[] calldata to, uint256 amount) external {
        for (uint256 i = 0; i < to.length; i++) {
            to[i].call{value: amount}("");
        }
    }

    function sweep(address payable to) external {
        to.call{value: address(this).balance}("");
    }
}
