// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OzMerkleAirdropDistributor} from
    "../fixtures/fake-airdrop/c-safe-impl/OzMerkleAirdropDistributor.sol";
import {MockERC20} from "../src/MockERC20.sol";

/// @title fake-airdrop tier (c) real-safe HOLDOUT: OpenZeppelin MerkleProof Merkle-gated claim.
/// @notice PRECISION-SIDE safe holdout. No clean independent vuln fake-airdrop incident exists at
///         code level at our provenance bar, so this vector's independent holdout is genuinely-safe
///         real code the harness MUST stay silent on. The inclusion proof is verified by UNMODIFIED
///         OpenZeppelin `MerkleProof` (v5.1.0, MIT) - a canonical verifier the detectors were never
///         tuned against, and a DIFFERENT source than the existing Solady-MerkleProofLib holdout.
///         split=holdout. See PROVENANCE.md.
contract RealSafeOzMerkleAirdropHoldoutTest is Test {
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant ATTACKER = address(0xBAD);
    uint256 constant AMT_A = 100e18;
    uint256 constant AMT_B = 50e18;

    /// @dev OZ standard double-hash leaf (second-preimage resistant), matching the distributor.
    function _leaf(address a, uint256 amt) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(a, amt))));
    }

    /// @dev Sorted-pair hash, matching OZ MerkleProof's commutativeKeccak256 verification order.
    function _hashPair(bytes32 x, bytes32 y) internal pure returns (bytes32) {
        return uint256(x) < uint256(y)
            ? keccak256(abi.encodePacked(x, y))
            : keccak256(abi.encodePacked(y, x));
    }

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[fake-airdrop] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_ozMerkleAirdrop_realSafe_blocked() public {
        bytes32 leafA = _leaf(ALICE, AMT_A);
        bytes32 leafB = _leaf(BOB, AMT_B);
        bytes32 root = _hashPair(leafA, leafB);

        MockERC20 token = new MockERC20();
        OzMerkleAirdropDistributor dist = new OzMerkleAirdropDistributor(address(token), root);
        token.mint(address(dist), AMT_A + AMT_B);

        // Proof for ALICE is the sibling leaf (BOB's).
        bytes32[] memory proofA = new bytes32[](1);
        proofA[0] = leafB;

        // Guard: the rightful account genuinely claims its exact committed allocation
        // (authority is real -> the BLOCKED verdict below is not vacuous).
        dist.claim(ALICE, AMT_A, proofA);
        assertEq(token.balanceOf(ALICE), AMT_A, "rightful claim should succeed");

        // Attack 1: an account ABSENT from the tree cannot claim (its leaf isn't committed).
        bytes32[] memory forged = new bytes32[](1);
        forged[0] = leafA;
        vm.expectRevert(OzMerkleAirdropDistributor.InvalidProof.selector);
        dist.claim(ATTACKER, AMT_B, forged);

        // Attack 2: inflating the amount for an in-tree account changes the leaf -> no proof matches.
        vm.expectRevert(OzMerkleAirdropDistributor.InvalidProof.selector);
        dist.claim(BOB, AMT_A + AMT_B, proofA);

        bool drained = token.balanceOf(ATTACKER) > 0 || token.balanceOf(address(dist)) < AMT_B;
        _report("oz-merkleproof-safe", drained);

        assertFalse(drained, "no unauthorized tokens should leave the distributor");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker gets nothing");
        assertEq(token.balanceOf(address(dist)), AMT_B, "only Alice's committed allocation left; Bob's remains");
    }
}
