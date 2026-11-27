// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {SoladyInitGuardDelegate} from
    "../fixtures/eip7702-delegation/c-safe-impl/SoladyInitGuardDelegate.sol";

/// @title Tier-(c) real-safe HOLDOUT for eip7702-delegation: Solady init-guard reinit defense.
/// @notice A 7702-delegate account can `execute` arbitrary calls for the EOA; the hijack vector is
///         an attacker re-initializing ownership to seize it. The init guard and `onlyOwner` check
///         are unmodified Solady `Ownable` (v0.1.22, MIT), opted into via `_guardInitializeOwner`.
///         An attacker's re-`initialize` reverts `AlreadyInitialized` and a non-owner `execute`
///         reverts `Unauthorized`, so the account's funds cannot be drained -> the harness MUST
///         stay silent (verdict BLOCKED, label safe). A guard proves the real owner CAN execute,
///         so BLOCKED is a real rejection, not a dead contract. split=holdout; verdict derived
///         from the real outcome.
contract RealSafeSoladyInitGuardHoldoutTest is Test {
    address constant OWNER = address(0x0E);
    address constant ATTACKER = address(0xA77ACC);
    uint256 constant START_BALANCE = 100e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[eip7702-delegation] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function _drainCalldata(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("transfer(address,uint256)", to, amount);
    }

    function test_eip7702_soladyInitGuard_blocked() public {
        MockERC20 token = new MockERC20();
        SoladyInitGuardDelegate delegate = new SoladyInitGuardDelegate();
        // The authorizing EOA initializes its delegate once.
        delegate.initialize(OWNER);
        token.mint(address(delegate), START_BALANCE);

        // Attack 1: re-initialization hijack - attacker tries to seize ownership.
        vm.prank(ATTACKER);
        try delegate.initialize(ATTACKER) {} catch {}

        // Attack 2: direct non-owner execute - attacker tries to drain regardless.
        vm.prank(ATTACKER);
        try delegate.execute(address(token), 0, _drainCalldata(ATTACKER, START_BALANCE)) {} catch {}

        bool drained = (token.balanceOf(address(delegate)) < START_BALANCE) || token.balanceOf(ATTACKER) > 0;
        _report("solady-initguard-safe", drained);

        assertFalse(drained, "reinit-hijack / non-owner execute must not drain the delegate");
        assertEq(delegate.owner(), OWNER, "ownership must remain with the first (legitimate) owner");
        assertEq(token.balanceOf(address(delegate)), START_BALANCE, "delegate balance intact");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker gets nothing");
    }

    /// Guard: the real owner CAN execute - so BLOCKED above is a real rejection of the attacker,
    /// not a dead/misconfigured contract.
    function test_guard_owner_canExecute() public {
        MockERC20 token = new MockERC20();
        SoladyInitGuardDelegate delegate = new SoladyInitGuardDelegate();
        delegate.initialize(OWNER);
        token.mint(address(delegate), START_BALANCE);

        address dest = address(0xC0FFEE);
        vm.prank(OWNER);
        delegate.execute(address(token), 0, _drainCalldata(dest, 10e18));

        assertEq(token.balanceOf(dest), 10e18, "owner-authorized execute should succeed");
        assertEq(token.balanceOf(address(delegate)), START_BALANCE - 10e18, "only the owner-moved amount left");
    }
}
