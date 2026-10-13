// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract PermitNoChainId {
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;

    // BUG: domain omits chainid, so a permit signed on one chain replays
    // on every other chain that deployed the same contract.
    function hashTypedData(bytes32 structHash) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
    }

    function recoverSigner(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        // BUG: s is not bounded to the lower half-order, so (v, r, s) and
        // (v, r, n - s) are both valid signatures for the same digest.
        return ecrecover(digest, v, r, s);
    }
}
