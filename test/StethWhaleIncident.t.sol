// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {LidoStEthClone} from "../fixtures/approve-drainer/b-incident/LidoStEthClone.sol";

/// @title approve-drainer (b) real-incident fixture: 2023-09-06 whale approval phishing (~$24M).
/// @notice Minimized OFFLINE replay of the documented attack path (no live RPC): a whale was
///         phished into granting an allowance to the attacker spender via `increaseAllowance`
///         (an on-chain approval, NOT an off-chain permit), after which the attacker
///         `transferFrom`'d the victim's entire stETH balance out in one tx. The real on-chain
///         addresses from the public post-mortem are used for fidelity (see PROVENANCE.md). The
///         verdict is derived from the real outcome (the balance left the victim), not
///         hardcoded; the harness must flag this fixture (label=vuln -> VULNERABLE).
contract StethWhaleIncidentTest is Test {
    // Public, documented addresses (PeckShield/SharkTeam + Etherscan "Phish/Hack" labels).
    // Spender held the approval and executed the drain transferFrom (Etherscan: Fake_Phishing186944).
    address constant SPENDER = 0x4c10a462CD1e639Da8A062aE8a33a23401120ab1;
    address constant VICTIM = 0x13e382dfe53207E9ce2eeEab330F69da2794179E;

    // Exact on-chain drained amount from the verified drain tx (stETH leg, 18 decimals):
    // 9,579.212966327732523199 stETH (~$17.46M at tx time). The incident also drained a
    // separate 4,851 rETH leg (~$8.5M); this fixture replays the verified stETH leg.
    uint256 constant VICTIM_BALANCE = 9579_212966327732523199;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[approve-drainer] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_stethWhaleIncident_isDrained() public {
        LidoStEthClone token = new LidoStEthClone();
        token.mint(VICTIM, VICTIM_BALANCE);

        // Documented approval step: victim phished into increaseAllowance to the attacker spender.
        vm.prank(VICTIM);
        token.increaseAllowance(SPENDER, type(uint256).max);

        uint256 balanceBefore = token.balanceOf(VICTIM);

        // Drain tx 0xcbe7b32e...2f77913: attacker transferFrom empties the victim's stETH.
        vm.prank(SPENDER);
        token.transferFrom(VICTIM, SPENDER, balanceBefore);

        uint256 finalBalance = token.balanceOf(VICTIM);
        bool drained = (balanceBefore > 0 && finalBalance == 0);
        _report("steth-whale-victim", drained);

        assertTrue(drained, "incident replay should drain the victim");
        assertEq(finalBalance, 0, "victim should be emptied");
        assertEq(token.balanceOf(SPENDER), VICTIM_BALANCE, "spender should hold the drained stETH");
    }
}
