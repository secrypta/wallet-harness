// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "../../vendor/oz/utils/cryptography/EIP712.sol";
import {ECDSA} from "../../vendor/oz/utils/cryptography/ECDSA.sol";

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

/// @title OzClearSigningWallet - clear-signing wallet that authorizes withdrawals ONLY from a
///        decodable EIP-712 typed signature, with NO raw-hash (`eth_sign`) entrypoint. Real-safe
///        (tier c) vehicle for the blind-eth-sign vector.
/// @notice The safety-critical logic - the EIP-712 domain/digest (`EIP712._hashTypedDataV4`)
///         and signature recovery (`ECDSA.recover`, zero-address/malleability safe) - is
///         vendored byte-identical OpenZeppelin v5.1.0 (fixtures/vendor/oz/, see
///         fixtures/vendor/PROVENANCE.md). This contract adds only a typed `Withdraw` struct, a
///         replay nonce, and a withdrawal gated on recovery over the wallet's OWN typed digest.
///         Crucially there is NO function that accepts a bare 32-byte hash + signature: the
///         wallet always reconstructs its typed digest from decodable fields before recovering.
///         So a signature obtained by blind-signing an attacker-chosen opaque hash (the
///         eth_sign phishing path) does not recover to the signer here and authorizes nothing;
///         the harness must stay silent (BLOCKED).
contract OzClearSigningWallet is EIP712 {
    address public immutable signer;
    mapping(uint256 => bool) public usedNonce;

    bytes32 private constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address token,address to,uint256 amount,uint256 nonce)");

    constructor(address signer_) EIP712("OzClearSigningWallet", "1") {
        signer = signer_;
    }

    /// @dev The decodable typed digest this wallet authorizes against. A signer who signs this
    ///      sees (via EIP-712 clear signing) the exact token/recipient/amount/nonce - never an
    ///      opaque blob.
    function withdrawDigest(address token, address to, uint256 amount, uint256 nonce)
        public
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(WITHDRAW_TYPEHASH, token, to, amount, nonce));
        return _hashTypedDataV4(structHash);
    }

    /// @notice Authority comes only from a signature over the typed digest above. No raw-hash
    ///         path exists, so a blind-signed opaque hash cannot be replayed into a withdrawal.
    function withdraw(address token, address to, uint256 amount, uint256 nonce, bytes calldata signature)
        external
    {
        require(!usedNonce[nonce], "wallet: nonce used");
        bytes32 digest = withdrawDigest(token, to, amount, nonce);
        address recovered = ECDSA.recover(digest, signature);
        require(recovered == signer, "wallet: not a clear-signed authorization");
        usedNonce[nonce] = true;
        require(IERC20Min(token).transfer(to, amount), "wallet: transfer failed");
    }
}
