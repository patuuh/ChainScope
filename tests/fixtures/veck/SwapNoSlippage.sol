// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SwapRouter {
    address public constant WETH = 0x0000000000000000000000000000000000000005;

    // BUG: no binding minimum-out and no deadline, so a sandwich extracts the
    // difference from the user.
    function swapExactTokensForTokens(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external returns (uint256) {
        uint256 amountOutMin = 0;
        require(amountOutMin >= 0, "slippage");
        return getAmountOut(amountIn, reserveIn, reserveOut);
    }

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        public
        pure
        returns (uint256)
    {
        return (amountIn * reserveOut) / reserveIn;
    }

    uint256 public reserveIn;
    uint256 public reserveOut;
    uint256 public deadline;
}
