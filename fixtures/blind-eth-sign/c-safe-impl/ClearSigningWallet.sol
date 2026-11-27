// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title ClearSigningWallet - reference implementation of the clear-signing / typed-only defense.
/// @notice There is no single canonical third-party library for "never blind-sign a raw hash",
///         so tier (c) is a faithful REFERENCE-IMPL of the clear-signing defense (the direction
///         of EIP-712 typed data + ERC-7730 clear signing), honestly marked as such. See
///         PROVENANCE.md.
///
///         The wallet derives every authorization digest itself from a structured, domain-bound
///         EIP-712 order and accepts only signatures over that digest. There is no entrypoint
///         that takes an attacker-supplied raw 32-byte hash, so a signature obtained by
///         blind-signing a bare hash cannot authorize anything here (the recovered signer will
///         not match the owner) -> the blind-hash drain path is unreachable (BLOCKED). A guard
///         shows a genuine typed order the owner signed still executes, so the defense is not
///         vacuous.
contract ClearSigningWallet {
    address public immutable owner;
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant ORDER_TYPEHASH =
        keccak256("Order(address token,address to,uint256 amount,uint256 nonce)");
    mapping(uint256 => bool) public usedNonce;

    error BlindOrUnauthorizedSignature();

    constructor(address owner_) {
        owner = owner_;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("ClearSigningWallet")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /// Only a decodable EIP-712 typed order is accepted; the digest is computed here from the
    /// struct under this wallet's domain, so a raw blind-signed hash cannot match.
    function executeOrder(
        address token,
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 structHash = keccak256(abi.encode(ORDER_TYPEHASH, token, to, amount, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        if (ecrecover(digest, v, r, s) != owner) revert BlindOrUnauthorizedSignature();
        require(!usedNonce[nonce], "nonce used");
        usedNonce[nonce] = true;
        IERC20(token).transferFrom(owner, to, amount);
    }
}
