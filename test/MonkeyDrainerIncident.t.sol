// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MonkeyDrainerNFTClone} from
    "../fixtures/set-approval-for-all/b-incident/MonkeyDrainerNFTClone.sol";

/// @title set-approval-for-all (b) real-incident fixture: Monkey Drainer (2022).
/// @notice Minimized OFFLINE replay of the documented Monkey Drainer path (no live RPC):
///         the victim is lured into `setApprovalForAll(operator, true)` (selector
///         0xa22cb465), then the malicious operator `transferFrom`'s the victim's ENTIRE
///         collection out. The verdict is derived from the real outcome (every token left
///         the victim), not hardcoded; the harness must flag this fixture
///         (label=vuln -> VULNERABLE). Addresses are representative - see PROVENANCE.md for
///         why the exact per-victim tx is marked incident-level.
contract MonkeyDrainerIncidentTest is Test {
    // Representative addresses for the offline replay (see PROVENANCE.md: blog-level sources
    // name the operation and selector; exact per-victim tx not pinned).
    address constant OPERATOR = address(0x4044ED17); // the Monkey Drainer operator (stand-in)
    address constant VICTIM = address(0x5156714D);

    uint256 constant COLLECTION_SIZE = 6; // the victim's whole collection

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[set-approval-for-all] target=", target, " verdict=", verdict));
    }

    function test_monkeyDrainerIncident_sweepsCollection() public {
        MonkeyDrainerNFTClone nft = new MonkeyDrainerNFTClone();
        for (uint256 i = 1; i <= COLLECTION_SIZE; i++) {
            nft.mint(VICTIM, i);
        }
        assertEq(nft.balanceOf(VICTIM), COLLECTION_SIZE, "victim holds the collection");

        // The phishing call: victim grants blanket operator authority (selector 0xa22cb465).
        vm.prank(VICTIM);
        nft.setApprovalForAll(OPERATOR, true);

        // The drainer sweeps the entire collection in one operator session.
        uint256 swept = 0;
        for (uint256 i = 1; i <= COLLECTION_SIZE; i++) {
            vm.prank(OPERATOR);
            nft.transferFrom(VICTIM, OPERATOR, i);
            swept++;
        }

        bool drained = (nft.balanceOf(VICTIM) == 0 && swept == COLLECTION_SIZE);
        _report("monkeydrainer-victim", drained);

        assertTrue(drained, "operator should have swept the whole collection");
        assertEq(nft.balanceOf(VICTIM), 0, "victim collection emptied");
        assertEq(nft.balanceOf(OPERATOR), COLLECTION_SIZE, "operator holds the swept collection");
    }
}
