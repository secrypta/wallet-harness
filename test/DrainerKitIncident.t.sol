// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {CalldataVulnerableWallet} from "../src/CalldataVulnerableWallet.sol";
import {DrainerKitModule} from "../fixtures/malicious-calldata/b-incident/DrainerKitModule.sol";

/// @title malicious-calldata (b) real-class fixture: drainer-kit hidden approval.
/// @notice Minimized OFFLINE reproduction of the documented drainer-kit pattern (no live
///         RPC): a wallet that executes calldata "by its label" delegatecalls a module
///         whose benign-named `connect()` hides an `approve` to the kit; the attacker then
///         sweeps the balance. The verdict is derived from the real outcome, not hardcoded;
///         the harness must flag this fixture (label=vuln -> VULNERABLE). This reproduces a
///         CLASS (see PROVENANCE.md), not a specific victim tx.
contract DrainerKitIncidentTest is Test {
    uint256 constant START_BALANCE = 100e18;
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_drainerKit_hiddenApproval_isDrained() public {
        MockERC20 token = new MockERC20();
        DrainerKitModule kit = new DrainerKitModule(address(token));
        CalldataVulnerableWallet wallet = new CalldataVulnerableWallet();
        token.mint(address(wallet), START_BALANCE);

        // The dApp presents this as a benign "Claim"; the real calldata hides an approve.
        wallet.executeByLabel("Claim rewards", address(kit));

        // The hidden allowance lets the attacker sweep the balance.
        vm.prank(ATTACKER);
        kit.drain(address(wallet));

        bool drained = (token.balanceOf(address(wallet)) == 0 && START_BALANCE > 0);
        _report("drainer-kit-victim", drained);

        assertTrue(drained, "hidden-approval calldata should have drained the wallet");
        assertEq(token.balanceOf(address(kit)), START_BALANCE, "drainer kit took the funds");
    }
}
