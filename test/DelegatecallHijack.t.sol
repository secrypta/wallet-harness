// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {VulnerableAccount} from "../src/VulnerableAccount.sol";
import {SafeAccount} from "../src/SafeAccount.sol";
import {AccountTakeoverModule} from "../src/AccountTakeoverModule.sol";
import {AuditedLibModule} from "../src/AuditedLibModule.sol";

/// @title delegatecall-hijack vector (a-toy), proven by test body.
/// @notice The signer sees a benign transfer; the payload's `operation` flag is flipped to
///         delegatecall against an attacker contract. An account that forwards delegatecall
///         to any target lets that contract run in its storage - overwriting slot 0 (the
///         logic/masterCopy pointer) and sweeping assets. An account that allow-lists
///         delegatecall targets blocks it. Same payload - only the exec policy differs.
contract DelegatecallHijackTest is Test {
    uint256 constant START_BALANCE = 100e18;
    address constant ATTACKER = address(0xA77ACC);
    address constant ORIG_IMPL = address(0x100C); // the legitimate logic pointer
    address constant ACCOUNT_OWNER = address(0x0E);

    function _report(string memory target, bool hijacked) internal pure {
        string memory verdict = hijacked ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[delegatecall-hijack] target=", target, " verdict=", verdict));
    }

    /// Vulnerable target: execTransaction with operation=delegatecall to attacker code
    /// rewrites the logic pointer and drains the balance -> account taken over.
    function test_vulnerableTarget_isHijacked() public {
        MockERC20 token = new MockERC20();
        VulnerableAccount account = new VulnerableAccount(ORIG_IMPL, ACCOUNT_OWNER);
        AccountTakeoverModule module = new AccountTakeoverModule();
        token.mint(address(account), START_BALANCE);

        // The submitted payload LOOKS like a routine action but operation = 1 (delegatecall)
        // against the attacker module, which overwrites slot 0 and sweeps the balance.
        bytes memory data =
            abi.encodeWithSignature("hijack(address,address,address)", ATTACKER, address(token), ATTACKER);
        account.execTransaction(address(module), data, 1);

        bool implSwapped = (account.implementation() != ORIG_IMPL);
        bool drained = (token.balanceOf(address(account)) == 0);
        bool hijacked = implSwapped && drained;
        _report("vulnerable-exec", hijacked);

        assertTrue(hijacked, "delegatecall should have hijacked the account");
        assertEq(account.implementation(), ATTACKER, "logic pointer taken over by attacker");
        assertEq(token.balanceOf(ATTACKER), START_BALANCE, "attacker swept the account balance");
    }

    /// Protected target: the delegatecall guard rejects a delegatecall to a non-allow-listed
    /// target, so the attacker code never runs. Logic pointer and assets are intact.
    function test_protectedTarget_isBlocked() public {
        MockERC20 token = new MockERC20();
        SafeAccount account = new SafeAccount(ORIG_IMPL, ACCOUNT_OWNER);
        AccountTakeoverModule module = new AccountTakeoverModule();
        token.mint(address(account), START_BALANCE);

        bytes memory data =
            abi.encodeWithSignature("hijack(address,address,address)", ATTACKER, address(token), ATTACKER);
        vm.expectRevert(
            abi.encodeWithSelector(SafeAccount.DelegatecallToUntrusted.selector, address(module))
        );
        account.execTransaction(address(module), data, 1);

        bool implSwapped = (account.implementation() != ORIG_IMPL);
        bool drained = (token.balanceOf(address(account)) < START_BALANCE);
        bool hijacked = implSwapped || drained;
        _report("safe-exec", hijacked);

        assertFalse(hijacked, "guard must block the delegatecall hijack");
        assertEq(account.implementation(), ORIG_IMPL, "logic pointer unchanged");
        assertEq(token.balanceOf(address(account)), START_BALANCE, "balance intact");
    }

    /// Guard A: a plain call (operation 0) still works under the safe policy - a normal
    /// token transfer out of the account executes. BLOCKED is not "refuse everything".
    function test_protected_plainCallStillWorks() public {
        MockERC20 token = new MockERC20();
        SafeAccount account = new SafeAccount(ORIG_IMPL, ACCOUNT_OWNER);
        token.mint(address(account), START_BALANCE);

        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", ATTACKER, 1e18);
        account.execTransaction(address(token), data, 0); // operation 0 = call

        assertEq(token.balanceOf(ATTACKER), 1e18, "normal call transfer must work");
        assertEq(account.implementation(), ORIG_IMPL, "plain call does not touch the logic pointer");
    }

    /// Guard B: a delegatecall to an ALLOW-LISTED audited library still runs under the safe
    /// policy - the guard restricts the target, it does not ban delegatecall outright.
    function test_protected_allowlistedDelegateRuns() public {
        SafeAccount account = new SafeAccount(ORIG_IMPL, ACCOUNT_OWNER);
        AuditedLibModule lib = new AuditedLibModule();
        account.allowDelegate(address(lib), true);

        account.execTransaction(address(lib), abi.encodeWithSignature("ping()"), 1); // succeeds

        assertEq(account.implementation(), ORIG_IMPL, "audited delegate leaves the logic pointer intact");
    }
}
