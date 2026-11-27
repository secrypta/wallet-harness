// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OzAccessControlExecutorWallet} from
    "../fixtures/eip7702-delegation/c-safe-impl/OzAccessControlExecutorWallet.sol";

/// @title Tier-(c) real-safe HOLDOUT for eip7702-delegation: OZ `AccessControl`-gated executor.
/// @notice The arbitrary-call executor an EIP-7702 account exposes is gated by unmodified OZ
///         v5.1.0 `AccessControl`. An attacker (a malicious delegate / arbitrary caller without
///         EXECUTOR_ROLE) submits a call that would sweep the account's ETH; `onlyRole` reverts
///         and nothing leaves -> the harness must stay silent (BLOCKED, label safe). A guard
///         proves a role-holder CAN execute, so BLOCKED is a real authorization rejection, not a
///         broken executor. Verdict derived from the real outcome. Uses a DIFFERENT real auth
///         library (OZ AccessControl) than the Solady-Ownable ERC7821 fixture.
contract RealSafeOzAccessControlExecHoldoutTest is Test {
    address constant EXECUTOR = address(0xE2EC0); // the role-holder
    address constant ATTACKER = address(0xA77ACC);
    address constant SINK = address(0xC0FFEE); // benign recipient for the guard
    uint256 constant VAULT = 100 ether;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[eip7702-delegation] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    /// Protected (c): a caller without EXECUTOR_ROLE cannot execute an arbitrary drain call.
    function test_eip7702_ozAccessControlExec_blocked() public {
        OzAccessControlExecutorWallet wallet = new OzAccessControlExecutorWallet(EXECUTOR);
        vm.deal(address(wallet), VAULT);

        vm.prank(ATTACKER);
        try wallet.execute(ATTACKER, VAULT, "") {} catch {}

        bool drained = (address(wallet).balance < VAULT);
        _report("oz-accesscontrol-exec-safe", drained);

        assertFalse(drained, "a non-role caller must not drain the account");
        assertEq(address(wallet).balance, VAULT, "account balance intact");
        assertEq(ATTACKER.balance, 0, "attacker gets nothing");
    }

    /// Guard: the role-holder CAN execute - BLOCKED above is a real auth rejection.
    function test_guard_executorRole_canExecute() public {
        OzAccessControlExecutorWallet wallet = new OzAccessControlExecutorWallet(EXECUTOR);
        vm.deal(address(wallet), VAULT);

        vm.prank(EXECUTOR);
        wallet.execute(SINK, 1 ether, "");

        assertEq(SINK.balance, 1 ether, "role-holder execution should succeed");
        assertEq(address(wallet).balance, VAULT - 1 ether, "only the authorized amount moved");
    }
}
