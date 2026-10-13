// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPool {
    function getReserves() external view returns (uint112, uint112);
    function slot0() external view returns (uint160, int24);
}

contract CollateralValuation {
    IPool constant pool = IPool(0x0000000000000000000000000000000000000003);

    // BUG: this valuation reads live reserves instead of a TWAP, so a flash
    // loan skews the price within a single tx and the protocol acts on it.
    function getPrice() external view returns (uint256) {
        (uint112 r0, uint112 r1) = pool.getReserves();
        return (uint256(r1) * 1e18) / uint256(r0);
    }

    function getTimeWeightedAveragePrice() external view returns (uint256) {
        return 1e18;
    }
}
