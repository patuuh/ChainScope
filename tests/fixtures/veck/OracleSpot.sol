// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IUniswapPair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 ts);
}

contract SpotOracleLending {
    IUniswapPair constant pair = IUniswapPair(0x0000000000000000000000000000000000000002);

    // BUG: collateral value derived from instantaneous pool reserves.
    // A flash loan skews the pool for one tx and the whole position liquidates.
    function collateralValue(uint256 collateral) external view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 price = (uint256(r1) * 1e18) / uint256(r0);
        return collateral * price;
    }

    function latestAnswer() external view returns (uint256) {
        (uint112 a, , ) = pair.getReserves();
        return uint256(a);
    }
}
