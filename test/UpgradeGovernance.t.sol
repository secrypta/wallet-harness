// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {VulnerableUpgradeWallet} from "../src/VulnerableUpgradeWallet.sol";
import {SafeUpgradeWallet} from "../src/SafeUpgradeWallet.sol";
import {BenignWalletLogic, MaliciousWalletLogic} from "../src/UpgradeModules.sol";

/// @title upgrade-governance vector (R10'), proven by test body.
/// @notice The "target" is the wallet's UPGRADE policy, not the delegatecall itself. Both
///         wallets delegate asset logic to a swappable implementation; the difference is
///         whether that swap is instant & single-key (vulnerable) or timelock/guardian
///         gated (safe). We model a compromised owner key and ask: can the attacker swap in
///         a hostile implementation and drain the wallet right now?
contract UpgradeGovernanceTest is Test {
    address constant OWNER = address(0xA11CE);
    address constant GUARDIAN = address(0x6A12D);
    address constant ATTACKER = address(0xBAD);
    address constant PAYEE = address(0xF00D); // intended, honest recipient

    uint256 constant START_BALANCE = 100e18;
    uint256 constant AMOUNT = 10e18;

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[upgrade-governance] target=", target, " verdict=", verdict));
    }

    /// Vulnerable target: a single compromised owner key swaps in a malicious
    /// implementation INSTANTLY (no timelock/guardian) and the next execute sweeps the
    /// wallet to the attacker.
    function test_vulnerableTarget_isDrainedByInstantUpgrade() public {
        MockERC20 token = new MockERC20();
        BenignWalletLogic benign = new BenignWalletLogic();
        MaliciousWalletLogic evil = new MaliciousWalletLogic(ATTACKER);

        VulnerableUpgradeWallet wallet = new VulnerableUpgradeWallet(OWNER, address(benign));
        token.mint(address(wallet), START_BALANCE);

        // Owner key is compromised. Attacker acts as owner: one instant swap, then execute.
        vm.startPrank(OWNER);
        wallet.upgradeTo(address(evil)); // no delay, no guardian: takes effect immediately
        wallet.execute(address(token), PAYEE, AMOUNT); // malicious impl ignores args, sweeps all
        vm.stopPrank();

        bool drained = (token.balanceOf(ATTACKER) == START_BALANCE);
        _report("vulnerable-upgrade", drained);

        assertTrue(drained, "instant single-key upgrade should drain the wallet");
        assertEq(token.balanceOf(address(wallet)), 0, "wallet emptied");
        assertEq(token.balanceOf(PAYEE), 0, "intended recipient got nothing - args ignored");
    }

    /// Protected target: the same compromised owner key CANNOT drain, because the upgrade is
    /// timelock-gated. Proposing the malicious implementation is allowed, but applying it
    /// immediately reverts, so no hostile implementation is ever active and the drain fails.
    function test_protectedTarget_instantUpgradeBlockedByTimelock() public {
        MockERC20 token = new MockERC20();
        BenignWalletLogic benign = new BenignWalletLogic();
        MaliciousWalletLogic evil = new MaliciousWalletLogic(ATTACKER);

        SafeUpgradeWallet wallet = new SafeUpgradeWallet(OWNER, GUARDIAN, address(benign));
        token.mint(address(wallet), START_BALANCE);

        // Compromised owner proposes the hostile implementation and tries to apply it now.
        vm.startPrank(OWNER);
        wallet.proposeUpgrade(address(evil));
        vm.expectRevert(bytes("timelock not elapsed"));
        wallet.executeUpgrade(); // instant swap is impossible
        vm.stopPrank();

        // Implementation is still the benign one, so an execute pays the intended recipient,
        // not the attacker - the drain did not happen.
        vm.prank(OWNER);
        wallet.execute(address(token), PAYEE, AMOUNT);

        bool drained = (token.balanceOf(ATTACKER) > 0);
        _report("safe-upgrade", drained);

        assertFalse(drained, "timelock/guardian must prevent the instant malicious upgrade");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker got nothing");
        assertEq(token.balanceOf(PAYEE), AMOUNT, "benign implementation still active");
    }

    /// Guardian half: during the delay window a second key cancels the pending hostile
    /// upgrade outright, so even after the delay it cannot be applied.
    function test_protected_guardianCancelsPendingUpgrade() public {
        MockERC20 token = new MockERC20();
        BenignWalletLogic benign = new BenignWalletLogic();
        MaliciousWalletLogic evil = new MaliciousWalletLogic(ATTACKER);

        SafeUpgradeWallet wallet = new SafeUpgradeWallet(OWNER, GUARDIAN, address(benign));
        token.mint(address(wallet), START_BALANCE);

        vm.prank(OWNER);
        wallet.proposeUpgrade(address(evil));

        // Guardian vetoes the pending upgrade.
        vm.prank(GUARDIAN);
        wallet.cancelUpgrade();

        // Even after the full delay there is nothing to apply.
        vm.warp(block.timestamp + 2 days + 1);
        vm.prank(OWNER);
        vm.expectRevert(bytes("no pending upgrade"));
        wallet.executeUpgrade();

        assertEq(token.balanceOf(ATTACKER), 0, "guardian veto kept the attacker out");
    }

    /// Guard against a vacuous BLOCKED: the governed upgrade is not broken - a legitimate
    /// new implementation CAN be applied after the timelock elapses, and a plain execute on
    /// the benign implementation still works. Otherwise "BLOCKED" could mean "nothing ever
    /// works" rather than "the attack is stopped".
    function test_protected_legitUpgradeAndExecuteStillWork() public {
        MockERC20 token = new MockERC20();
        BenignWalletLogic benign = new BenignWalletLogic();
        BenignWalletLogic benignV2 = new BenignWalletLogic(); // a legitimate new implementation

        SafeUpgradeWallet wallet = new SafeUpgradeWallet(OWNER, GUARDIAN, address(benign));
        token.mint(address(wallet), START_BALANCE);

        // A normal payment works on the current (benign) implementation.
        vm.prank(OWNER);
        wallet.execute(address(token), PAYEE, AMOUNT);
        assertEq(token.balanceOf(PAYEE), AMOUNT, "benign execute must work");

        // A legitimate upgrade goes through once the delay has elapsed.
        vm.prank(OWNER);
        wallet.proposeUpgrade(address(benignV2));
        vm.warp(block.timestamp + 2 days + 1);
        vm.prank(OWNER);
        wallet.executeUpgrade();
        assertEq(wallet.implementation(), address(benignV2), "legit upgrade must apply after delay");

        // And the upgraded wallet still functions.
        vm.prank(OWNER);
        wallet.execute(address(token), PAYEE, AMOUNT);
        assertEq(token.balanceOf(PAYEE), AMOUNT * 2, "execute works after a legit upgrade");
    }
}
