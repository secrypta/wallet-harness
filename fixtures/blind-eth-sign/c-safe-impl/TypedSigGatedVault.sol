// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignatureVerification} from "../../vendor/permit2/src/libraries/SignatureVerification.sol";

/// @title TypedSigGatedVault - safe, typed-signature-gated withdrawal vehicle.
/// @notice blind-eth-sign tier (c) real-safe HOLDOUT vehicle. The ONLY authored code on top of
///         the UNMODIFIED Uniswap Permit2 `SignatureVerification` library (MIT): it releases
///         funds only against a signature over a FULLY-TYPED EIP-712 digest (domain-separated,
///         structured `Withdrawal`). This is the safe counterpart of the blind-eth-sign vector:
///         a "blind" signature over an opaque raw hash (the eth_sign danger) does NOT match the
///         typed digest, so the canonical verifier rejects it (recovered signer != owner) and
///         nothing moves. The recovery/validation is delegated to Permit2's real verifier - an
///         independent canonical source (not OZ, not Solady) the detectors were never tuned
///         against.
contract TypedSigGatedVault {
    using SignatureVerification for bytes;

    address public immutable owner;      // the account whose typed signature authorizes a withdrawal
    address public immutable token;      // the held ERC-20
    uint256 public nonce;                // consumed per authorized withdrawal (anti-replay)

    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant WITHDRAWAL_TYPEHASH =
        keccak256("Withdrawal(address to,uint256 amount,uint256 nonce)");

    constructor(address owner_, address token_) {
        owner = owner_;
        token = token_;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("TypedSigGatedVault")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice The EIP-712 typed digest the owner must have signed to authorize this withdrawal.
    function digest(address to, uint256 amount, uint256 nonce_) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(WITHDRAWAL_TYPEHASH, to, amount, nonce_));
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /// @notice Release `amount` to `to` iff `signature` is the owner's signature over the
    ///         TYPED digest for the current nonce. A blind/raw-hash signature yields a
    ///         different recovered signer and is rejected by Permit2's SignatureVerification.
    function withdraw(address to, uint256 amount, bytes calldata signature) external {
        bytes32 d = digest(to, amount, nonce);
        // Reverts (InvalidSigner / InvalidSignature / InvalidSignatureLength) on anything that
        // is not the owner's signature over exactly this typed digest.
        signature.verify(d, owner);
        unchecked { ++nonce; }
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }
}
