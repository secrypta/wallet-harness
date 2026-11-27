// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {WormholeInitGuardSafe} from
    "../fixtures/upgrade-governance/c-safe-impl/wormhole-initguard-safe/WormholeInitGuardSafe.sol";

/// @title upgrade-governance tier (c): Wormhole SECURE (post-fix) implementation - holdout.
/// @notice SAFE half of the vulnerable->safe pair with wormhole-uninit-impl-victim. The same
///         takeover attempt as the incident is run against the secure clone: the implementation
///         is initialized (locked) by the legitimate setup (the step the incident failed to
///         perform), and Wormhole's per-implementation `initializedImplementations` guard then
///         reverts any attacker `initialize()`, so the guardian is never seized and the
///         guardian-only upgrade path stays with the rightful guardian. The harness MUST stay
///         silent here (verdict BLOCKED) - the honest 0-false-positive test. Non-vacuous: the
///         legit guardian still upgrades, and a fresh implementation can be initialized exactly
///         once before the per-implementation guard locks it (proving the guard is real).
contract RealSafeWormholeInitGuardHoldoutTest is Test {
    address constant ATTACKER = address(0xBAD);
    address constant LEGIT_GUARDIAN = address(0x6007);
    address constant EVIL_IMPL = address(0xE11);
    address constant BENIGN_IMPL = address(0xB16);

    function _report(string memory target, bool takenOver) internal pure {
        string memory verdict = takenOver ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[upgrade-governance] target=", target, " verdict=", verdict));
    }

    /// Core safe property: the SAME attack as the incident fails against the secure clone.
    function test_wormhole_initGuard_takeoverBlocked() public {
        WormholeInitGuardSafe impl = new WormholeInitGuardSafe();

        // Legitimate setup initializes (locks) the implementation - the step the incident
        // failed to do. In the incident the impl was left uninitialized; here it is not.
        impl.initialize(LEGIT_GUARDIAN);
        assertTrue(impl.initialized(), "implementation is initialized/locked (post-fix state)");
        assertEq(impl.guardian(), LEGIT_GUARDIAN, "legit guardian is in control");

        // ATTACK (same as the incident): try to initialize the implementation directly to
        // seize the guardian set. The per-implementation guard reverts it.
        vm.prank(ATTACKER);
        vm.expectRevert(bytes("already initialized"));
        impl.initialize(ATTACKER);

        // ATTACK: try to drive the guardian-only upgrade path without being the guardian.
        vm.prank(ATTACKER);
        vm.expectRevert(bytes("not guardian"));
        impl.submitContractUpgrade(EVIL_IMPL);

        bool takenOver = (impl.guardian() == ATTACKER || impl.implementation() == EVIL_IMPL);
        _report("wormhole-initguard-safe", takenOver);

        assertFalse(takenOver, "initialized implementation with re-init guard cannot be seized");
        assertEq(impl.guardian(), LEGIT_GUARDIAN, "guardian unchanged - attacker seized nothing");
        assertEq(impl.implementation(), address(0), "upgrade pointer never moved by the attacker");
    }

    /// Non-vacuous (1): the legitimate guardian still performs the privileged upgrade action,
    /// so BLOCKED means "the takeover is stopped", not "nothing can ever change".
    function test_wormhole_initGuard_legitGuardianUpgradeApplies() public {
        WormholeInitGuardSafe impl = new WormholeInitGuardSafe();
        impl.initialize(LEGIT_GUARDIAN);

        vm.prank(LEGIT_GUARDIAN);
        impl.submitContractUpgrade(BENIGN_IMPL);

        assertEq(impl.implementation(), BENIGN_IMPL, "rightful guardian can drive a legit upgrade");
    }

    /// Non-vacuous (2): the per-implementation guard is a REAL one-shot, not dead code - a
    /// fresh (not-yet-initialized) implementation can be initialized exactly once, and a second
    /// initialize() then reverts. This also proves the flag is keyed per implementation.
    function test_wormhole_initGuard_perImplOneShot() public {
        WormholeInitGuardSafe fresh = new WormholeInitGuardSafe();
        assertFalse(fresh.initialized(), "a fresh implementation starts uninitialized");

        fresh.initialize(LEGIT_GUARDIAN); // succeeds exactly once
        assertTrue(fresh.initialized(), "first initialize locks this implementation");
        assertEq(fresh.guardian(), LEGIT_GUARDIAN, "guardian set by the one legitimate init");

        vm.expectRevert(bytes("already initialized"));
        fresh.initialize(ATTACKER); // second call is rejected by the per-impl guard
    }
}
