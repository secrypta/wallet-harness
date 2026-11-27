// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {BenignModule} from "../src/BenignModule.sol";
import {SimulatedExecutor} from "../fixtures/malicious-calldata/c-safe-impl/SimulatedExecutor.sol";
import {DrainerKitModule} from "../fixtures/malicious-calldata/b-incident/DrainerKitModule.sol";

/// @title malicious-calldata (c) reference-impl proof: net-effect simulation guard.
/// @notice The protected executor simulates the calldata's real net effect and rejects a
///         hidden approval/transfer - catching the SAME drainer-kit module used by the (b)
///         fixture, without knowing its hidden effect in advance. The harness MUST stay
///         silent (verdict BLOCKED, label safe). A guard shows a genuinely benign action
///         still executes, so BLOCKED is a real rejection, not a policy that refuses
///         everything.
contract RealSafeCalldataTest is Test {
    uint256 constant START_BALANCE = 100e18;
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    /// Protected (c): the simulation catches the hidden approve and rejects the action; the
    /// drain never takes hold.
    function test_maliciousCalldata_simulatedGuard_blocked() public {
        MockERC20 token = new MockERC20();
        DrainerKitModule kit = new DrainerKitModule(address(token));
        SimulatedExecutor executor = new SimulatedExecutor();
        token.mint(address(executor), START_BALANCE);

        // The guard simulates the hidden-approve calldata and reverts before committing.
        try executor.executeSimulated(address(kit), address(token)) {
            // would mean the hidden effect slipped through
        } catch {
            // expected: simulation surfaced the hidden grant and rejected it
        }

        // No allowance was ever committed, so the attacker's drain cannot pull anything.
        vm.prank(ATTACKER);
        try kit.drain(address(executor)) {} catch {}

        bool drained = (token.balanceOf(address(executor)) < START_BALANCE);
        _report("simulated-exec-safe", drained);

        assertFalse(drained, "net-effect simulation must stop the hidden-approval drain");
        assertEq(token.balanceOf(address(executor)), START_BALANCE, "balance intact");
        assertEq(token.allowance(address(executor), address(kit)), 0, "no hidden allowance committed");
    }

    /// Guard: a genuinely benign action simulates clean and is committed - the guard does
    /// not refuse everything.
    function test_benignAction_simulatesCleanAndExecutes() public {
        MockERC20 token = new MockERC20();
        BenignModule benign = new BenignModule();
        SimulatedExecutor executor = new SimulatedExecutor();
        token.mint(address(executor), START_BALANCE);

        // Must not revert: the simulated net effect is benign.
        executor.executeSimulated(address(benign), address(token));

        assertEq(token.balanceOf(address(executor)), START_BALANCE, "benign action moves nothing");
        assertEq(token.allowance(address(executor), address(benign)), 0, "benign action grants nothing");
    }
}
