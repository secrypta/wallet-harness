// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SvenSweeperDelegate, SvenVulnerableAccount} from
    "../fixtures/eip7702-delegation/b-incident/SvenDelegateClone.sol";

/// @title eip7702-delegation (b) real-incident HOLDOUT: the sven.eth EIP-7702 delegation drain.
/// @notice Minimized OFFLINE repro (no live RPC) of the 2026-10-14 sven.eth drain (~9.12 ETH +
///         1.69 TAPEETH, ~$22.7K, Ethereum). The victim's EOA signed an EIP-7702 SET_CODE (type-4)
///         authorization delegating its code to an attacker-controlled delegate; an attacker-run
///         sponsor submitted the sponsored type-4 tx, and the delegate ran in the account's context
///         and swept its ETH to the attacker. We model the 7702 "code runs as the account" semantics
///         via delegatecall. The verdict is derived from the real outcome (the account's ETH ends up
///         at the attacker), not hardcoded. HOLDOUT (label=vuln). Facts/sources: PROVENANCE.md.
contract SvenDelegationIncidentTest is Test {
    address payable constant ATTACKER = payable(address(0xBAD));
    uint256 constant VICTIM_ETH = 9.1231 ether; // the real drained ETH amount

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[eip7702-delegation] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_svenEthDelegationIncident_isDrained() public {
        SvenVulnerableAccount victim = new SvenVulnerableAccount(); // EOA: 0xd8ba9e..4a28
        vm.deal(address(victim), VICTIM_ETH);

        // Attacker's delegate (real delegate: 0x0366b55f948a688888ca6e029ad0831f6ec260d1).
        SvenSweeperDelegate sweeper = new SvenSweeperDelegate();

        // Victim signs the EIP-7702 SET_CODE authorization pointing the EOA at the attacker delegate
        // (real sponsored type-4 tx 0x36e0d149..820ee, from attacker sponsor 0x9208097c..20bc).
        victim.installDelegation(address(sweeper));
        // The sponsor activates it; the delegate runs as the account and sweeps its ETH.
        victim.activate(abi.encodeWithSelector(SvenSweeperDelegate.sweepEth.selector, ATTACKER));

        bool drained = ATTACKER.balance == VICTIM_ETH && address(victim).balance == 0;
        _report("sven-eth-victim", drained);

        assertTrue(drained, "a malicious 7702 delegation should sweep the whole account");
        assertEq(ATTACKER.balance, VICTIM_ETH, "attacker received the full ETH balance");
    }
}
