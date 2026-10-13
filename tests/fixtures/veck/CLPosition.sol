// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ICLPool {
    function slot0() external view returns (uint160 sqrtPriceX96, int24 tick, uint16, uint16, uint16, uint8, bool);
    function positions(bytes32) external view returns (uint128 liquidity, uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128);
}

contract ConcentratedLiquidityStrategy {
    ICLPool constant pool = ICLPool(0x0000000000000000000000000000000000000004);
    int24 public tickLower = -887220;
    int24 public tickUpper = 887220;
    uint256 private constant Q96 = 1 << 96;

    struct PositionInfo {
        uint128 liquidity;
        int24 tickLower;
        int24 tickUpper;
    }

    // BUG: value is computed from sqrtPriceX96 with an off-by-one tick bound,
    // which over-values the position and lets a rebalancer extract the excess.
    function valueOf(bytes32 key) external view returns (uint256) {
        (uint160 sqrtPriceX96, int24 tick, , , , , ) = pool.slot0();
        (uint128 liquidity, uint256 feeGrowthInside0LastX128, ) = pool.positions(key);
        if (tick <= tickLower) {
            return uint256(liquidity) * (uint256(sqrtPriceX96) - Q96);
        }
        return feeGrowthInside0LastX128;
    }

    function getSqrtRatioAtTick(int24 tick) internal pure returns (uint160) {
        return Q96;
    }
}
