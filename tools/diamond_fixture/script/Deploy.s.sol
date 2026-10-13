// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;
import {Script} from "forge-std/Script.sol";
import {DiamondDeployer} from "../src/Diamond.sol";
contract Deploy is Script {
    function run() external returns (address) {
        return new DiamondDeployer().deploy();
    }
}
