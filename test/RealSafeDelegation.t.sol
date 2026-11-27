// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {DelegationSweeper} from "../src/DelegationVector.sol";
import {
    AllowlistedDelegatePolicy,
    AuditedNoopDelegate
} from "../fixtures/eip7702-delegation/c-safe-impl/AllowlistedDelegatePolicy.sol";

/// @title eip7702-delegation (c) real-safe fixture: allow-listed-delegate policy (reference-impl).
/// @notice The 0-false-positive test for the canonical EIP-7702 defense. The attacker sweeper is
///         not on the policy's audited allow-list, so honorDelegation reverts and the delegation
///         that would run hostile code in the account's context never installs -> the drain path
///         is unreachable (BLOCKED). A guard installs and activates an allow-listed audited
///         delegate, so BLOCKED means "unknown delegate rejected", not "nothing works".
contract RealSafeDelegationTest is Test {
    address constant ATTACKER = address(0xBAD);
    uint256 constant BALANCE = 100e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[eip7702-delegation] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    /// Safe: an unknown (attacker) delegate is refused -> no sweep possible.
    function test_allowlistedPolicy_blocksUnknownDelegate() public {
        MockERC20 token = new MockERC20();
        AllowlistedDelegatePolicy policy = new AllowlistedDelegatePolicy();
        token.mint(address(policy), BALANCE);

        DelegationSweeper sweeper = new DelegationSweeper();
        // The attacker's sweeper was never audited/allow-listed: honoring it must revert.
        vm.expectRevert(
            abi.encodeWithSelector(AllowlistedDelegatePolicy.DelegateNotAllowlisted.selector, address(sweeper))
        );
        policy.honorDelegation(address(sweeper));

        bool drained = token.balanceOf(ATTACKER) > 0;
        _report("allowlisted-deleg-safe", drained);

        assertFalse(drained, "attacker must receive nothing");
        assertEq(token.balanceOf(address(policy)), BALANCE, "account balance intact");
    }

    /// Guard: an allow-listed audited delegate installs and runs, so the policy is not vacuous.
    function test_guard_auditedDelegate_installsAndRuns() public {
        AllowlistedDelegatePolicy policy = new AllowlistedDelegatePolicy();
        AuditedNoopDelegate audited = new AuditedNoopDelegate();

        policy.setAudited(address(audited), true);
        policy.honorDelegation(address(audited));
        assertEq(policy.activeDelegate(), address(audited), "audited delegate should install");

        // And it executes without reverting.
        policy.activate(abi.encodeWithSelector(AuditedNoopDelegate.run.selector));
    }
}
