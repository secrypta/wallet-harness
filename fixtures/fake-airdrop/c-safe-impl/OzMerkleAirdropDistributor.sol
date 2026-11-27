// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MerkleProof} from "../../vendor/oz/utils/cryptography/MerkleProof.sol";

/// @title OzMerkleAirdropDistributor - safe, Merkle-gated airdrop claim vehicle (OpenZeppelin).
/// @notice fake-airdrop tier (c) real-safe HOLDOUT vehicle. The ONLY authored code on top of the
///         UNMODIFIED OpenZeppelin `MerkleProof` (fixtures/vendor/oz/utils/cryptography/, MIT,
///         pinned v5.1.0; see fixtures/vendor/PROVENANCE.md): it gates each claim on an inclusion
///         proof against a fixed Merkle root, so an account can withdraw only its own committed
///         allocation exactly once. This is the canonical safe airdrop-distributor pattern
///         (Uniswap/OP-style Merkle distributor): NOT an open mint, NOT an attacker-chosen amount.
///
///         Distinct from the existing holdouts: `solady-merkle-airdrop-safe` uses Solady's
///         `MerkleProofLib` and `oz-safe-claim` uses an OZ ERC-20 as the asset. This fixture
///         delegates the inclusion check to OpenZeppelin's canonical `MerkleProof.verifyCalldata`
///         - a different canonical verifier wal was never tuned against (independent precision
///         holdout). The leaf uses OZ's standard double-hash convention to resist second-preimage
///         attacks: leaf = keccak256(bytes.concat(keccak256(abi.encode(account, amount)))).
contract OzMerkleAirdropDistributor {
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
    /// @dev A forged proof, a wrong amount, or an account absent from the tree all fail the
    ///      OpenZeppelin verification and revert; nothing is transferred.
    function claim(address account, uint256 amount, bytes32[] calldata proof) external {
        if (claimed[account]) revert AlreadyClaimed();
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(account, amount))));
        if (!MerkleProof.verifyCalldata(proof, merkleRoot, leaf)) revert InvalidProof();
        claimed[account] = true;
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSignature("transfer(address,uint256)", account, amount));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
        emit Claimed(account, amount);
    }
}
