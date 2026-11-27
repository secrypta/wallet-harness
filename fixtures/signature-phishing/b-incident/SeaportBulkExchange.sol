// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC721Move {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

/// @title SeaportBulkExchange - minimized offline model of Seaport bulk order fulfillment,
///        for the signature-phishing (b) real-incident fixture (RTFKT / CloneX, 2022-12-08).
/// @notice Distinct from SeaportLikeExchange (single order): this models the BULK private-
///         listing path used in the RTFKT airdrop-lure phishing - the on-chain drain tx
///         0xbf2542540ce22abe7a1822e15d67a50b73a7ba18e036bb305103e51606122b69 called Seaport
///         1.1's fulfillAvailableAdvancedOrders (selector 0xa8174404), moving many NFTs in a
///         single transaction. The key abuse element is a PRIVATE LISTING whose consideration
///         to the offerer is ZERO: the victim blind-signs off-chain orders that "sell" their
///         NFTs to the attacker's taker for 0 ETH, and a relayer bulk-fulfills them. The
///         victim had already granted the marketplace routine operator approval (as real
///         marketplace users do); the authority to move each tokenId to the taker then comes
///         purely from the victim's EIP-712 order signatures. Only the order-verification +
///         zero-price settlement + bulk transfer surface needed to replay that path is
///         modeled. Offline only - no live RPC. See PROVENANCE.md.
contract SeaportBulkExchange {
    struct Order {
        address offerer; // NFT owner / signer (the victim)
        address nftToken; // ERC-721 collection
        uint256 tokenId; // the offered token
        uint256 price; // ETH consideration paid to the offerer (0 for a private-listing scam)
        address recipient; // who receives the NFT (the taker / attacker)
        uint256 nonce;
        uint256 deadline;
    }

    mapping(address => uint256) public nonces;
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address offerer,address nftToken,uint256 tokenId,uint256 price,address recipient,uint256 nonce,uint256 deadline)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;

    event OrderFulfilled(address indexed offerer, address indexed nftToken, uint256 tokenId, address recipient, uint256 price);

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("SeaportBulkExchange")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    function hashOrder(Order calldata o) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(ORDER_TYPEHASH, o.offerer, o.nftToken, o.tokenId, o.price, o.recipient, o.nonce, o.deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /// @notice Bulk-fulfill many signed orders in one call (models Seaport's
    ///         fulfillAvailableAdvancedOrders). Each order whose signature verifies is
    ///         settled: `price` ETH is forwarded to the offerer and the NFT moves to the
    ///         order's recipient. An order that fails verification is skipped, so the taker
    ///         can sweep every token the victim actually signed for. Returns the count filled.
    function fulfillAvailableAdvancedOrders(Order[] calldata orders, uint8[] calldata v, bytes32[] calldata r, bytes32[] calldata s)
        external
        payable
        returns (uint256 filled)
    {
        require(orders.length == v.length && v.length == r.length && r.length == s.length, "Exchange: length mismatch");
        for (uint256 i = 0; i < orders.length; i++) {
            Order calldata o = orders[i];
            if (block.timestamp > o.deadline) continue;
            if (o.nonce != nonces[o.offerer]) continue;
            address recovered = ecrecover(hashOrder(o), v[i], r[i], s[i]);
            if (recovered == address(0) || recovered != o.offerer) continue;
            nonces[o.offerer]++;
            // Zero-price private listing: the offerer is paid `price` (0 in the scam) and
            // loses the NFT to the taker. Settlement proceeds regardless of price.
            if (o.price > 0) {
                (bool ok,) = o.offerer.call{value: o.price}("");
                require(ok, "Exchange: consideration payment failed");
            }
            IERC721Move(o.nftToken).transferFrom(o.offerer, o.recipient, o.tokenId);
            emit OrderFulfilled(o.offerer, o.nftToken, o.tokenId, o.recipient, o.price);
            filled++;
        }
    }
}
