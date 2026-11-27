// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC721} from "../src/MockERC721.sol";
import {MaliciousOperator} from "../src/MaliciousOperator.sol";

/// @title set-approval-for-all (b) real-incident fixture: PREMINT front-end injection (2022-07-17).
/// @notice Minimized OFFLINE replay of the documented PREMINT drain path (no live RPC). The
///         premint.xyz front-end was compromised with injected JavaScript that, during a
///         routine action, presented a fake "wallet verification" prompt whose actual on-chain
///         call was setApprovalForAll(operator, true) (selector 0xa22cb465) to an attacker-
///         controlled operator returned by the attacker's back-end. The operator then
///         transferFrom-swept the victims' collections (~314-321 NFTs from ~28 wallets,
///         ~275 ETH / ~$375K). This is the set-approval-for-all vector: blanket operator
///         authority granted to a malicious address. The attacker EOA below is the real,
///         on-chain-confirmed address (see PROVENANCE.md); the victim/collection are stand-ins.
///         The verdict is derived from the real outcome (the collection left the victim).
contract PremintIncidentTest is Test {
    // Real attacker EOA (cross-confirmed Beosin + CertiK, on-chain active EOA - see PROVENANCE.md).
    address constant ATTACKER = 0x0C9797805a22E507Bf48F35C72A67f001b7418d0;
    address constant VICTIM = address(0x9E27114D); // representative victim (stand-in)
    uint256 constant COLLECTION_SIZE = 6; // the victim's whole collection

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[set-approval-for-all] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function test_premintIncident_sweepsCollection() public {
        MockERC721 nft = new MockERC721();
        MaliciousOperator operator = new MaliciousOperator();

        uint256[] memory ids = new uint256[](COLLECTION_SIZE);
        for (uint256 i = 0; i < COLLECTION_SIZE; i++) {
            nft.mint(VICTIM, i + 1);
            ids[i] = i + 1;
        }
        assertEq(nft.balanceOf(VICTIM), COLLECTION_SIZE, "victim holds the collection");

        // The injected "wallet verification" call: victim grants blanket operator authority
        // (setApprovalForAll, selector 0xa22cb465) to the attacker-controlled operator.
        vm.prank(VICTIM);
        nft.setApprovalForAll(address(operator), true);

        // The operator (funded by / paid out to the real attacker EOA) sweeps the whole
        // collection in one session.
        vm.prank(ATTACKER);
        uint256 taken = operator.sweep(address(nft), VICTIM, ids);

        bool drained = (nft.balanceOf(VICTIM) == 0 && taken == COLLECTION_SIZE);
        _report("premint-operator-victim", drained);

        assertTrue(drained, "operator should have swept the whole collection");
        assertEq(nft.balanceOf(VICTIM), 0, "victim collection emptied");
        assertEq(nft.balanceOf(address(operator)), COLLECTION_SIZE, "operator holds the swept collection");
    }
}
