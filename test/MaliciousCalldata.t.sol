// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {HiddenEffectModule} from "../src/HiddenEffectModule.sol";
import {BenignModule} from "../src/BenignModule.sol";
import {CalldataVulnerableWallet} from "../src/CalldataVulnerableWallet.sol";
import {CalldataSafeWallet} from "../src/CalldataSafeWallet.sol";

/// @title malicious-calldata vector, proven by test body.
/// @notice The presented action is "Connect"; the real calldata hides an `approve` of the
///         wallet's assets. A wallet that executes by the label is drained; a wallet that
///         simulates the net effect and rejects a mismatch stays safe. Both run the same
///         delegatecall - only the execution policy differs.
contract MaliciousCalldataTest is Test {
    uint256 constant START_BALANCE = 100e18;
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    /// Vulnerable target: executes the module by its benign label; the hidden approve lets
    /// the attacker drain the full balance.
    function test_vulnerableTarget_isDrained() public {
        MockERC20 token = new MockERC20();
        HiddenEffectModule module = new HiddenEffectModule(address(token));
        CalldataVulnerableWallet wallet = new CalldataVulnerableWallet();
        token.mint(address(wallet), START_BALANCE);

        // The dApp presents this as "Connect"; the real effect is a hidden approval.
        wallet.executeByLabel("Connect", address(module));

        // Anyone can now pull the balance via the hidden allowance.
        vm.prank(ATTACKER);
        module.drain(address(wallet));

        bool drained = (token.balanceOf(address(wallet)) == 0 && START_BALANCE > 0);
        _report("vulnerable-call", drained);

        assertTrue(drained, "hidden-effect calldata should have drained the wallet");
        assertEq(token.balanceOf(address(module)), START_BALANCE, "attacker module took the funds");
    }

    /// Protected target: simulates the real effect and rejects the hidden approval; the
    /// drain never takes hold.
    function test_protectedTarget_isBlocked() public {
        MockERC20 token = new MockERC20();
        HiddenEffectModule module = new HiddenEffectModule(address(token));
        CalldataSafeWallet wallet = new CalldataSafeWallet();
        token.mint(address(wallet), START_BALANCE);

        // Simulation surfaces the hidden allowance grant and reverts the whole action.
        try wallet.executeSimulated(address(module), address(token)) {
            // would mean the hidden effect slipped through
        } catch {
            // expected: rejected, hidden approve rolled back
        }

        // With no allowance granted, the attacker's drain cannot pull anything.
        vm.prank(ATTACKER);
        try module.drain(address(wallet)) {} catch {}

        bool drained = (token.balanceOf(address(wallet)) < START_BALANCE);
        _report("safe-call", drained);

        assertFalse(drained, "simulated-effect policy must not let the hidden drain through");
        assertEq(token.balanceOf(address(wallet)), START_BALANCE, "wallet balance intact");
        assertEq(token.allowance(address(wallet), address(module)), 0, "no hidden allowance remained");
    }

    /// Guard: a genuinely benign module (no asset effect) still executes under the
    /// protected policy - so BLOCKED above is a real rejection, not a policy that refuses
    /// everything.
    function test_protected_benignCallStillWorks() public {
        MockERC20 token = new MockERC20();
        BenignModule module = new BenignModule();
        CalldataSafeWallet wallet = new CalldataSafeWallet();
        token.mint(address(wallet), START_BALANCE);

        // Must not revert: effect matches the stated benign intent.
        wallet.executeSimulated(address(module), address(token));

        assertEq(token.balanceOf(address(wallet)), START_BALANCE, "benign call must not move assets");
        assertEq(token.allowance(address(wallet), address(module)), 0, "benign call grants nothing");
    }
}
