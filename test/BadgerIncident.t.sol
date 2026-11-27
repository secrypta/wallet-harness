// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {BadgerSettClone} from "../fixtures/approve-drainer/b-incident/BadgerSettClone.sol";

/// @title approve-drainer (b) real-incident fixture: BadgerDAO (2021-12-02).
/// @notice Minimized OFFLINE replay of the documented attack path (no live RPC): the victim
///         grants an allowance to the attacker spender via `increaseAllowance` (as injected
///         by the compromised Badger front-end), then the attacker `transferFrom`'s the
///         victim's whole balance out. The real on-chain addresses from the public
///         post-mortem are used for fidelity (see PROVENANCE.md). The verdict is derived
///         from the real outcome (the balance left the victim), not hardcoded; the harness
///         must flag this fixture (label=vuln -> VULNERABLE).
contract BadgerIncidentTest is Test {
    // Public, documented addresses (rekt.news/badger-rekt + Etherscan).
    address constant ATTACKER = 0x1FCdb04d0C5364FBd92C73cA8AF9BAA72c269107;
    address constant VICTIM = 0x53461E4fddcC1385f1256Ae24ce3505Be664f249;

    // Representative balance for the minimized replay (8 decimals). The exact per-victim
    // amount is not part of the public provenance; the cited ~900 byvWBTC (>$50M) is the
    // aggregate drain across 500+ approvers. The vector is what matters, not the figure.
    uint256 constant VICTIM_BALANCE = 900e8;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[approve-drainer] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_badgerIncident_isDrained() public {
        BadgerSettClone token = new BadgerSettClone();
        token.mint(VICTIM, VICTIM_BALANCE);

        // Approval tx 0x5e4c7966...afe1f34: victim increaseAllowance to the attacker spender.
        vm.prank(VICTIM);
        token.increaseAllowance(ATTACKER, type(uint256).max);

        uint256 balanceBefore = token.balanceOf(VICTIM);

        // Drain tx 0x951babdd...41029869: attacker transferFrom empties the victim.
        vm.prank(ATTACKER);
        token.transferFrom(VICTIM, ATTACKER, balanceBefore);

        uint256 finalBalance = token.balanceOf(VICTIM);
        bool drained = (balanceBefore > 0 && finalBalance == 0);
        _report("badger-victim", drained);

        assertTrue(drained, "incident replay should drain the victim");
        assertEq(finalBalance, 0, "victim should be emptied");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker should hold the drained balance");
    }
}
