// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24";

library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return leaf == root;
    }
}

contract BridgeVerifier {
    bytes32 public root;
    mapping(bytes32 => bool) public processed;

    // BUG: `processed[leaf]` is never set, so the same Merkle proof can be
    // replayed to mint bridged tokens repeatedly with no backing deposit.
    function processProof(bytes32[] calldata proof, bytes32 leaf, address to) external {
        require(MerkleProof.verify(proof, root, leaf), "bad proof");
        to.transfer(amountFor(leaf));
    }

    function finalizeDeposit(address to, uint256 amount) external {
        to.transfer(amount);
    }

    function amountFor(bytes32 leaf) internal pure returns (uint256) {
        return 1 ether;
    }
}
