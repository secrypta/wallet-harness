// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MerkleProofLib} from "../../vendor/solady-accounts/utils/MerkleProofLib.sol";

/// @title MerkleAirdropDistributor - safe, Merkle-gated airdrop claim vehicle.
/// @notice fake-airdrop tier (c) real-safe HOLDOUT vehicle. The ONLY authored code on top of
///         the UNMODIFIED Solady `MerkleProofLib` (Vectorized/solady, MIT): it gates each
///         claim on an inclusion proof against a fixed Merkle root, so an account can withdraw
///         only its own committed allocation exactly once. This is the canonical safe
///         airdrop-distributor pattern (Uniswap/OP-style Merkle distributor): NOT an open mint,
///         NOT an attacker-chosen amount. The inclusion check is delegated to Solady's real
///         verifier - the detectors were never tuned against it (independent precision holdout).
contract MerkleAirdropDistributor {
    /// @dev The airdropped ERC-20 (any standard transfer()-able token).
    address public immutable token;
    /// @dev Commitment to the full (account, amount) allocation set.
    bytes32 public immutable merkleRoot;
    /// @dev One claim per account.
    mapping(address => bool) public claimed;

    error AlreadyClaimed();
    error InvalidProof();

    event Claimed(address indexed account, uint256 amount);

    constructor(address token_, bytes32 merkleRoot_) {
        token = token_;
        merkleRoot = merkleRoot_;
    }

    /// @notice Claim `amount` for `account` iff `proof` proves (account, amount) is in the tree.
    /// @dev Leaf = keccak256(abi.encodePacked(account, amount)) - the standard distributor leaf.
    ///      A forged proof, a wrong amount, or an account absent from the tree all fail the
    ///      Solady verification and revert; nothing is transferred.
    function claim(address account, uint256 amount, bytes32[] calldata proof) external {
        if (claimed[account]) revert AlreadyClaimed();
        bytes32 leaf = keccak256(abi.encodePacked(account, amount));
        if (!MerkleProofLib.verifyCalldata(proof, merkleRoot, leaf)) revert InvalidProof();
        claimed[account] = true;
        // Standard ERC-20 transfer of the committed allocation to the rightful account.
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSignature("transfer(address,uint256)", account, amount));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
        emit Claimed(account, amount);
    }
}
