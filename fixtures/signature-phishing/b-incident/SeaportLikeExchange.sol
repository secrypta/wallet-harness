// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC721Move {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

/// @title SeaportLikeExchange - minimized offline model of a marketplace that executes a
///        signed off-chain NFT order, for the signature-phishing (b) real-incident fixture.
/// @notice NOT our toy ERC-20 settlement: this reproduces the shape behind the OpenSea
///         migration phishing (Feb 2022) and the Kevin Rose / Moonbirds (Jan 2023) losses -
///         victims signed off-chain Seaport/Wyvern ORDERS (not a plain setApprovalForAll),
///         and a relayer/taker fulfilled them, sweeping the NFTs. The owner has granted the
///         exchange operator approval (as real marketplace users do); authority to move a
///         specific tokenId to a specific recipient then comes purely from the owner's
///         EIP-712 signature over an order. Only the order-verification + transfer surface
///         needed to replay that path is modeled. Offline only - no live RPC.
contract SeaportLikeExchange {
    struct Order {
        address offerer; // NFT owner / signer
        address nftToken; // ERC-721 collection
        uint256 tokenId; // the offered token
        address recipient; // who receives the NFT (the taker)
        uint256 nonce;
        uint256 deadline;
    }

    mapping(address => uint256) public nonces;
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address offerer,address nftToken,uint256 tokenId,address recipient,uint256 nonce,uint256 deadline)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;

    event OrderFulfilled(address indexed offerer, address indexed nftToken, uint256 tokenId, address recipient);

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("SeaportLikeExchange")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    function hashOrder(Order calldata o) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(ORDER_TYPEHASH, o.offerer, o.nftToken, o.tokenId, o.recipient, o.nonce, o.deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /// @notice Anyone holding the offerer's valid signature can fulfill the order; the NFT
    ///         moves to the order's recipient. Strict guards so a revert means "this order
    ///         was not authorized", not a malformed-signature accident.
    function fulfillOrder(Order calldata o, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= o.deadline, "Exchange: order expired");
        require(o.nonce == nonces[o.offerer], "Exchange: bad nonce");
        address recovered = ecrecover(hashOrder(o), v, r, s);
        require(recovered != address(0) && recovered == o.offerer, "Exchange: bad signature");
        nonces[o.offerer]++;
        IERC721Move(o.nftToken).transferFrom(o.offerer, o.recipient, o.tokenId);
        emit OrderFulfilled(o.offerer, o.nftToken, o.tokenId, o.recipient);
    }
}
