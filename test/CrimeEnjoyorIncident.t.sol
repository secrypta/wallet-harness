// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {DelegationSweeper, VulnerableDelegationAccount} from "../src/DelegationVector.sol";

/// @title eip7702-delegation (b) real-incident fixture: the "CrimeEnjoyor" reusable sweeper.
/// @notice Minimized OFFLINE repro (no live RPC) of the EIP-7702 drain pattern Wintermute
///         documented after Pectra (2025): a single reusable sweeper delegate accounted for the
///         vast majority of malicious 7702 delegations observed. A victim with a phished 7702
///         "enable smart account" authorization delegates their EOA to the sweeper, which drains
///         everything in one transaction. We model the 7702 "code runs as the account" semantics
///         explicitly via delegatecall (no vm.signDelegation dependency); the dollar figures vary
///         across public write-ups, so the proof level is incident/class-level. See PROVENANCE.md.
contract CrimeEnjoyorIncidentTest is Test {
    address constant ATTACKER = address(0xBAD);
    uint256 constant VICTIM_BALANCE = 250e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[eip7702-delegation] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_crimeEnjoyorIncident_isDrained() public {
        MockERC20 token = new MockERC20();
        VulnerableDelegationAccount victim = new VulnerableDelegationAccount();
        token.mint(address(victim), VICTIM_BALANCE);

        // One reusable sweeper serves every victim (the "CrimeEnjoyor" pattern).
        DelegationSweeper crimeEnjoyor = new DelegationSweeper();

        // Victim signs the phished 7702 SET_CODE authorization pointing the EOA at the sweeper.
        victim.installDelegation(address(crimeEnjoyor));
        // The sweeper is activated and empties the account in a single tx.
        victim.activate(abi.encodeWithSelector(DelegationSweeper.sweep.selector, address(token), ATTACKER));

        bool drained = token.balanceOf(ATTACKER) == VICTIM_BALANCE && token.balanceOf(address(victim)) == 0;
        _report("crimeenjoyor-victim", drained);

        assertTrue(drained, "the sweeper should drain the whole account");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker received the full balance");
    }
}
