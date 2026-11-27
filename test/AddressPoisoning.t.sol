// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {AddressBook} from "../src/AddressBook.sol";
import {VulnerableSendWallet} from "../src/VulnerableSendWallet.sol";
import {SafeSendWallet} from "../src/SafeSendWallet.sol";

/// @title address-poisoning vector, proven by test body.
/// @notice This is a UX / transaction-history attack, not a contract bug: the "target" is
///         the wallet's send policy. The real counterparty and the attacker's look-alike
///         share the same TRUNCATED display (`0x1234...cdef`) but differ in the full
///         address. A policy that trusts the displayed match pays the attacker; a policy
///         that verifies the FULL address against the address book rejects the look-alike.
contract AddressPoisoningTest is Test {
    // Same displayed prefix (0x1234) and suffix (0xcdef), different middle. Built via a
    // numeric literal + uint160 cast so no EIP-55 checksum is needed.
    // Leading `00` keeps these as plain numeric literals (same value), so Solidity does
    // not treat them as checksummed address literals.
    address constant REAL_COUNTERPARTY =
        address(uint160(0x001234aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaCDEF));
    address constant POISON_LOOKALIKE =
        address(uint160(0x001234bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbCDEF)); // the attacker

    uint256 constant START_BALANCE = 100e18;
    uint256 constant AMOUNT = 40e18;

    function _report(string memory target, bool misrouted) internal pure {
        string memory verdict = misrouted ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[address-poisoning] target=", target, " verdict=", verdict));
    }

    /// @dev Establishes the poisoning premise: the look-alike is indistinguishable from the
    ///      real counterparty in the wallet's truncated display, yet is a different address.
    function _assertPoisoningPremise(AddressBook book) internal pure {
        assertTrue(
            book.displayedMatches(REAL_COUNTERPARTY, POISON_LOOKALIKE),
            "look-alike must share the displayed prefix/suffix"
        );
        assertTrue(REAL_COUNTERPARTY != POISON_LOOKALIKE, "full addresses must differ");
    }

    /// Vulnerable target: the wallet accepts a recipient that merely LOOKS like the
    /// verified counterparty (truncated match), so the poisoned look-alike is paid.
    function test_vulnerableTarget_isPoisoned() public {
        MockERC20 token = new MockERC20();
        AddressBook book = new AddressBook();
        book.addVerified(REAL_COUNTERPARTY);
        _assertPoisoningPremise(book);

        VulnerableSendWallet wallet = new VulnerableSendWallet(book);
        token.mint(address(wallet), START_BALANCE);

        // Victim means to pay REAL_COUNTERPARTY but copies the look-alike from history.
        wallet.send(address(token), REAL_COUNTERPARTY, POISON_LOOKALIKE, AMOUNT);

        bool misrouted = (token.balanceOf(POISON_LOOKALIKE) > 0);
        _report("vulnerable-send", misrouted);

        assertTrue(misrouted, "funds should have reached the attacker look-alike");
        assertEq(token.balanceOf(POISON_LOOKALIKE), AMOUNT, "attacker received the funds");
        assertEq(token.balanceOf(REAL_COUNTERPARTY), 0, "real counterparty got nothing");
    }

    /// Protected target: the wallet verifies the FULL address against the book, so the
    /// look-alike (not a verified counterparty) is rejected and the attacker gets nothing.
    function test_protectedTarget_isBlocked() public {
        MockERC20 token = new MockERC20();
        AddressBook book = new AddressBook();
        book.addVerified(REAL_COUNTERPARTY);
        _assertPoisoningPremise(book);

        SafeSendWallet wallet = new SafeSendWallet(book);
        token.mint(address(wallet), START_BALANCE);

        // Sending to the look-alike copied from history must be rejected.
        vm.expectRevert(bytes("recipient not a verified counterparty"));
        wallet.send(address(token), POISON_LOOKALIKE, AMOUNT);

        bool misrouted = (token.balanceOf(POISON_LOOKALIKE) > 0);
        _report("safe-send", misrouted);

        assertFalse(misrouted, "attacker look-alike must not receive funds");
        assertEq(token.balanceOf(POISON_LOOKALIKE), 0, "attacker balance stays zero");
        assertEq(token.balanceOf(address(wallet)), START_BALANCE, "wallet balance intact");
    }

    /// Guard: the protected policy is not vacuously blocking everything - a genuine send to
    /// a verified counterparty by full address still succeeds. Otherwise BLOCKED would be a
    /// false pass.
    function test_protected_genuineSendStillWorks() public {
        MockERC20 token = new MockERC20();
        AddressBook book = new AddressBook();
        book.addVerified(REAL_COUNTERPARTY);

        SafeSendWallet wallet = new SafeSendWallet(book);
        token.mint(address(wallet), START_BALANCE);

        wallet.send(address(token), REAL_COUNTERPARTY, AMOUNT);

        assertEq(token.balanceOf(REAL_COUNTERPARTY), AMOUNT, "verified counterparty must be payable");
        assertEq(token.balanceOf(POISON_LOOKALIKE), 0, "attacker never involved in a genuine send");
    }
}
