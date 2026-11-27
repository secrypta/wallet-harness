// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC721} from "../src/MockERC721.sol";
import {SeaportLikeExchange} from "../fixtures/signature-phishing/b-incident/SeaportLikeExchange.sol";

/// @title signature-phishing (b) real-incident fixture: Seaport/Wyvern order-signature theft.
/// @notice Minimized OFFLINE replay of the path behind the OpenSea migration phishing (Feb
///         2022) and the Kevin Rose / Moonbirds (Jan 2023) losses: the victim had granted a
///         marketplace operator approval (routine) and then blind-signed an off-chain order
///         transferring an NFT to the attacker; a relayer/taker fulfilled it and the NFT
///         left the victim - without the victim ever sending a transaction. The permit-style
///         owner is a key-derived stand-in: EIP-712 needs a valid signature and the real
///         victims' keys are (rightly) not public, so this is a pattern-level reproduction
///         anchored to those public incidents (see PROVENANCE.md). The verdict is derived
///         from the real outcome (the NFT changed owner to the attacker).
contract SeaportSignatureIncidentTest is Test {
    uint256 constant OWNER_PK = 0xBAD5EA; // stand-in signer (real victim keys are not public)
    address constant ATTACKER = address(0xA77ACC); // taker / relayer (no public address given)
    uint256 constant TOKEN_ID = 1;

    function _report(string memory target, bool stolen) internal pure {
        console.log(
            string.concat(
                "[signature-phishing] target=", target, " verdict=", stolen ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_seaportOrderIncident_isStolen() public {
        MockERC721 nft = new MockERC721();
        SeaportLikeExchange exchange = new SeaportLikeExchange();
        address owner = vm.addr(OWNER_PK);
        nft.mint(owner, TOKEN_ID);

        // Routine marketplace setup: the owner approves the exchange as an operator.
        vm.prank(owner);
        nft.setApprovalForAll(address(exchange), true);

        // The order the victim is phished into blind-signing: offer the NFT to the attacker.
        SeaportLikeExchange.Order memory order = SeaportLikeExchange.Order({
            offerer: owner,
            nftToken: address(nft),
            tokenId: TOKEN_ID,
            recipient: ATTACKER,
            nonce: 0,
            deadline: block.timestamp + 1 hours
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, exchange.hashOrder(order));

        // The attacker/relayer fulfills the signed order; the NFT leaves the victim.
        vm.prank(ATTACKER);
        try exchange.fulfillOrder(order, v, r, s) {} catch {}

        bool stolen = (nft.ownerOf(TOKEN_ID) == ATTACKER);
        _report("seaport-order-victim", stolen);

        assertTrue(stolen, "incident replay should move the NFT to the attacker");
        assertEq(nft.balanceOf(owner), 0, "victim should lose the NFT");
    }
}
