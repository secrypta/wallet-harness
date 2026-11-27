// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {StEthLikeToken} from "../fixtures/fake-airdrop/b-incident/StEthLikeToken.sol";
import {GiftToken} from "../src/GiftToken.sol";
import {MaliciousSpender} from "../src/MaliciousSpender.sol";

/// @title fake-airdrop (b) real-incident fixture: LFG fake-airdrop guide (2023, ~$125K stETH).
/// @notice Minimized OFFLINE replay of the documented path (no live RPC): an unsolicited
///         "airdrop" bait lured the victim into a fake "claim" flow that, instead of
///         touching the gift, made them approve the attacker's spender on their REAL asset
///         (stETH). The attacker then drained that real asset via transferFrom while the
///         worthless bait stayed put. The verdict is derived from the real outcome (the real
///         asset left the victim). See PROVENANCE.md.
contract LfgFakeAirdropIncidentTest is Test {
    address constant VICTIM = address(0x1E57);
    address constant ATTACKER = address(0xA77ACC);
    uint256 constant REAL_BALANCE = 70e18; // ~$125K of stETH, representative
    uint256 constant GIFT_BALANCE = 5000e18; // minted by GiftToken's constructor

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[fake-airdrop] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_lfgFakeAirdropIncident_isDrained() public {
        StEthLikeToken real = new StEthLikeToken();
        GiftToken gift = new GiftToken(VICTIM); // unsolicited bait lands on the victim
        MaliciousSpender spender = new MaliciousSpender();
        real.mint(VICTIM, REAL_BALANCE);

        // The fake "claim" tricks the victim into approving the attacker's spender on their
        // REAL asset (unlimited), not the gift.
        vm.prank(VICTIM);
        real.approve(address(spender), type(uint256).max);

        uint256 realBefore = real.balanceOf(VICTIM);
        vm.prank(ATTACKER);
        spender.drain(address(real), VICTIM);

        uint256 finalReal = real.balanceOf(VICTIM);
        bool drained = (realBefore > 0 && finalReal == 0);
        _report("lfg-claim-victim", drained);

        assertTrue(drained, "the real asset should be drained");
        assertEq(finalReal, 0, "victim's real asset should be emptied");
        assertEq(real.balanceOf(address(spender)), REAL_BALANCE, "attacker spender holds the drained asset");
        assertEq(gift.balanceOf(VICTIM), GIFT_BALANCE, "the bait should stay untouched");
    }
}
