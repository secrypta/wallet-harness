// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {SoladyHandoverDelegate} from
    "../fixtures/eip7702-delegation/c-safe-impl/SoladyHandoverDelegate.sol";

/// @title Tier-(c) real-safe HOLDOUT for eip7702-delegation: Solady two-step ownership handover.
/// @notice A 7702 hijack tries to seize the delegate's owner slot and drain. With unmodified Solady
///         `Ownable`, an attacker's `requestOwnershipHandover` only registers a pending request;
///         `completeOwnershipHandover`/`transferOwnership` are `onlyOwner`, so the attacker never
///         becomes owner and cannot reach the owner-gated `execute` -> the harness MUST stay silent
///         (verdict BLOCKED, label safe). A guard runs the legitimate two-step handover and shows
///         the new owner CAN execute, so BLOCKED is a real rejection, not a dead account.
///         split=holdout; verdict from the real outcome.
contract RealSafeSoladyHandoverHoldoutTest is Test {
    address constant OWNER = address(0x0E);
    address constant NEW_OWNER = address(0x0D);
    address constant ATTACKER = address(0xA77ACC);
    uint256 constant START_BALANCE = 100e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[eip7702-delegation] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function _drain(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("transfer(address,uint256)", to, amount);
    }

    function _setup() internal returns (MockERC20 token, SoladyHandoverDelegate d) {
        token = new MockERC20();
        d = new SoladyHandoverDelegate();
        d.initialize(OWNER);
        token.mint(address(d), START_BALANCE);
    }

    function test_eip7702_soladyHandover_blocked() public {
        (MockERC20 token, SoladyHandoverDelegate d) = _setup();

        // Attacker registers a handover request (allowed) but cannot complete it for themselves,
        // and cannot execute without being owner.
        vm.prank(ATTACKER);
        d.requestOwnershipHandover();

        vm.prank(ATTACKER);
        try d.completeOwnershipHandover(ATTACKER) {} catch {} // onlyOwner -> reverts

        vm.prank(ATTACKER);
        try d.execute(address(token), 0, _drain(ATTACKER, START_BALANCE)) {} catch {} // not owner -> reverts

        bool drained = (token.balanceOf(address(d)) < START_BALANCE)
            || token.balanceOf(ATTACKER) > 0 || d.owner() == ATTACKER;
        _report("solady-handover-safe", drained);

        assertFalse(drained, "attacker must not seize ownership or drain the delegate");
        assertEq(d.owner(), OWNER, "ownership stays with the original owner");
        assertEq(token.balanceOf(address(d)), START_BALANCE, "delegate balance intact");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker gets nothing");
    }

    /// Guard: the legitimate two-step handover works and the new owner CAN execute - so BLOCKED
    /// above is a real rejection of the attacker, not a dead account.
    function test_guard_legitHandover_thenExecute() public {
        (MockERC20 token, SoladyHandoverDelegate d) = _setup();
        address dest = address(0xC0FFEE);

        // Step 1: the intended new owner requests the handover.
        vm.prank(NEW_OWNER);
        d.requestOwnershipHandover();
        // Step 2: the CURRENT owner completes it.
        vm.prank(OWNER);
        d.completeOwnershipHandover(NEW_OWNER);
        assertEq(d.owner(), NEW_OWNER, "two-step handover should transfer ownership");

        vm.prank(NEW_OWNER);
        d.execute(address(token), 0, _drain(dest, 10e18));
        assertEq(token.balanceOf(dest), 10e18, "new owner should be able to execute");
        assertEq(token.balanceOf(address(d)), START_BALANCE - 10e18, "only the authorized move happened");
    }
}
