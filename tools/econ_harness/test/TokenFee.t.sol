// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;
import "forge-std/Test.sol";
interface IT { function balanceOf(address) external view returns (uint256);
              function transfer(address,uint256) external returns (bool); }
contract TokenFeeTest is Test {
    address a = makeAddr("a"); address b = makeAddr("b");
    function test_plain_transfer() public {
        address asset = vm.envOr("ASSET", address(0));
        if (asset == address(0) || vm.envOr("FORK_BLOCK", uint256(0)) == 0) {
            emit log("ASSET/FORK_BLOCK unset - skipping");
            return;
        }
        vm.createSelectFork(
            vm.envOr("RPC_URL", string("https://ethereum.publicnode.com")),
            vm.envOr("FORK_BLOCK", uint256(0))
        );
        uint256 pre = IT(asset).balanceOf(b);
        deal(asset, a, 1000e18);
        vm.prank(a);
        IT(asset).transfer(b, 1e18);
        uint256 got = IT(asset).balanceOf(b) - pre;
        emit log_named_uint("sent     ", 1e18);
        emit log_named_uint("received ", got);
        emit log_named_int ("fee      ", int256(1e18) - int256(got));
    }
}
