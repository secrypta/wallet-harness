// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {SoladyRolesDelegate} from
    "../fixtures/eip7702-delegation/c-safe-impl/SoladyRolesDelegate.sol";

/// @title Tier-(c) real-safe HOLDOUT for eip7702-delegation: Solady OwnableRoles-gated executor.
/// @notice A 7702-delegate can `execute` arbitrary calls; the gate is unmodified Solady
///         `OwnableRoles` - only the owner or an EXECUTOR_ROLE holder may execute. A caller with
///         neither reverts `Unauthorized`, so the account's funds cannot be drained by an
///         unauthorized party -> the harness MUST stay silent (verdict BLOCKED, label safe). Guards
///         prove both the owner and a role-holder CAN execute, so BLOCKED is a real rejection.
///         split=holdout; verdict from the real outcome.
contract RealSafeSoladyRolesDelegateHoldoutTest is Test {
    address constant OWNER = address(0x0E);
    address constant RELAYER = address(0x5E); // granted EXECUTOR_ROLE by the owner
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

    function _setup() internal returns (MockERC20 token, SoladyRolesDelegate d) {
        token = new MockERC20();
        d = new SoladyRolesDelegate();
        d.initialize(OWNER);
        token.mint(address(d), START_BALANCE);
        uint256 role = d.EXECUTOR_ROLE(); // resolve before prank (avoid consuming it on this call)
        vm.prank(OWNER);
        d.grantRoles(RELAYER, role);
    }

    function test_eip7702_soladyRoles_blocked() public {
        (MockERC20 token, SoladyRolesDelegate d) = _setup();

        // Attacker has neither the owner key nor EXECUTOR_ROLE; execute must revert.
        vm.prank(ATTACKER);
        try d.execute(address(token), 0, _drain(ATTACKER, START_BALANCE)) {} catch {}

        bool drained = (token.balanceOf(address(d)) < START_BALANCE) || token.balanceOf(ATTACKER) > 0;
        _report("solady-ownableroles-exec-safe", drained);

        assertFalse(drained, "a caller without owner/role must not drain the delegate");
        assertEq(token.balanceOf(address(d)), START_BALANCE, "delegate balance intact");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker gets nothing");
    }

    /// Guards: the owner AND a role-holder CAN execute - so BLOCKED above is a real rejection.
    function test_guard_ownerAndRole_canExecute() public {
        (MockERC20 token, SoladyRolesDelegate d) = _setup();
        address dest = address(0xC0FFEE);

        vm.prank(OWNER);
        d.execute(address(token), 0, _drain(dest, 10e18));
        assertEq(token.balanceOf(dest), 10e18, "owner should be able to execute");

        vm.prank(RELAYER);
        d.execute(address(token), 0, _drain(dest, 5e18));
        assertEq(token.balanceOf(dest), 15e18, "EXECUTOR_ROLE holder should be able to execute");
        assertEq(token.balanceOf(address(d)), START_BALANCE - 15e18, "only authorized moves happened");
    }
}
