// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// blind-eth-sign (raw-hash signing) vector (#12). Toy targets.
//
// `eth_sign` asks a wallet to sign an OPAQUE 32-byte hash: no "\x19Ethereum Signed Message"
// prefix, no EIP-712 domain, no structure the user can read. That hash can commit to anything
// - a transfer, a Permit, an exchange order. A victim tricked into signing a bare hash yields
// a signature the attacker replays wherever that hash is valid, draining the account with no
// on-chain approval and nothing displayed to the user.
//
// This differs from signature-phishing (which anchors on EIP-712 *typed* order signatures,
// e.g. Seaport): the distinguishing defect here is signing an UNSTRUCTURED, UNDISPLAYABLE hash.
// The defense is categorical - only accept decodable EIP-712 typed data (clear signing).

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title BlindSigWallet - authorizes transfers from a RAW 32-byte hash signature (eth_sign).
/// @notice Models the legacy `eth_sign` path: the owner signs an opaque hash the attacker
///         chose (it commits to token/recipient/amount), and this contract simply recovers the
///         signer from that raw hash and executes. The user never saw what they authorized.
contract BlindSigWallet {
    address public immutable owner;
    mapping(bytes32 => bool) public consumed;

    constructor(address owner_) {
        owner = owner_;
    }

    /// The raw-hash authorization: `h` is exactly what the owner blind-signed; the attacker
    /// picked (token,to,amount) and computed its hash off-chain before phishing the signature.
    function executeBlind(address token, address to, uint256 amount, uint8 v, bytes32 r, bytes32 s)
        external
    {
        bytes32 h = keccak256(abi.encode(token, to, amount));
        require(ecrecover(h, v, r, s) == owner, "bad signature");
        require(!consumed[h], "replayed");
        consumed[h] = true;
        IERC20(token).transferFrom(owner, to, amount);
    }
}

/// @title TypedSigWallet - accepts ONLY decodable EIP-712 typed authorizations (clear signing).
/// @notice The defense against blind signing: every authorization is a structured, domain-bound
///         EIP-712 message the wallet can decode and display, and there is NO entrypoint that
///         accepts an attacker-chosen raw hash. A signature produced by blind-signing a bare
///         hash does not validate here, because this contract derives the digest itself from the
///         typed struct under its own domain separator - so the blind-hash drain path is
///         unreachable.
contract TypedSigWallet {
    address public immutable owner;
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant ORDER_TYPEHASH =
        keccak256("Order(address token,address to,uint256 amount,uint256 nonce)");
    mapping(uint256 => bool) public usedNonce;

    constructor(address owner_) {
        owner = owner_;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("TypedSigWallet")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function executeTyped(
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
        require(ecrecover(digest, v, r, s) == owner, "bad typed signature");
        require(!usedNonce[nonce], "nonce used");
        usedNonce[nonce] = true;
        IERC20(token).transferFrom(owner, to, amount);
    }
}
