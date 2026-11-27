// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AddressBook} from "../src/AddressBook.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {VerifiedSendPolicy} from "../fixtures/address-poisoning/c-safe-impl/VerifiedSendPolicy.sol";

/// @title address-poisoning (c) real-safe fixture: canonical full-address verification.
/// @notice The 0-false-positive test for the canonical defense. The attacker has planted a
///         look-alike that matches the real counterparty on the truncated wallet display
///         but differs in full address. A send policy that verifies the FULL recipient
///         address against the user's verified book rejects the look-alike, so the funds
///         never reach the attacker -> BLOCKED. A guard shows a genuine send to a verified
///         counterparty still succeeds, so BLOCKED is not vacuous.
contract RealSafeAddressPoisoningTest is Test {
    // Numeric literals (leading 00) + uint160 cast: no EIP-55 checksum needed. The two
    // addresses share the displayed prefix 0x1234..CDEF but differ in the full address.
    address constant REAL_COUNTERPARTY =
        address(uint160(0x001234aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaCDEF));
    address constant POISON_LOOKALIKE =
        address(uint160(0x001234bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbCDEF)); // the attacker

    uint256 constant START_BALANCE = 100e18;
    uint256 constant AMOUNT = 40e18;

    function _report(string memory target, bool misrouted) internal pure {
        console.log(
            string.concat(
                "[address-poisoning] target=", target, " verdict=", misrouted ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function _assertPoisoningPremise(AddressBook book) internal pure {
        require(book.displayedMatches(REAL_COUNTERPARTY, POISON_LOOKALIKE), "premise: display must match");
        require(REAL_COUNTERPARTY != POISON_LOOKALIKE, "premise: full addresses must differ");
    }

    /// Safe: full-address verification rejects the poisoned look-alike -> funds retained.
    function test_verifiedSend_blocksPoisonedLookalike() public {
        AddressBook book = new AddressBook();
        book.addVerified(REAL_COUNTERPARTY);
        _assertPoisoningPremise(book);

        VerifiedSendPolicy policy = new VerifiedSendPolicy(book);
        MockERC20 token = new MockERC20();
        token.mint(address(policy), START_BALANCE);

        // The user means to pay REAL_COUNTERPARTY but copied the look-alike from history.
        try policy.send(address(token), POISON_LOOKALIKE, AMOUNT) {} catch {}

        bool misrouted = token.balanceOf(POISON_LOOKALIKE) > 0;
        _report("verified-send-safe", misrouted);

        assertFalse(misrouted, "funds must not reach the poisoned look-alike");
        assertEq(token.balanceOf(POISON_LOOKALIKE), 0, "attacker should receive nothing");
        assertEq(token.balanceOf(address(policy)), START_BALANCE, "funds should be retained");
    }

    /// Guard: a genuine send to the verified counterparty succeeds, so the BLOCKED above
    /// means "the look-alike was rejected", not "this policy can never send".
    function test_guard_verifiedCounterparty_isSendable() public {
        AddressBook book = new AddressBook();
        book.addVerified(REAL_COUNTERPARTY);

        VerifiedSendPolicy policy = new VerifiedSendPolicy(book);
        MockERC20 token = new MockERC20();
        token.mint(address(policy), START_BALANCE);

        policy.send(address(token), REAL_COUNTERPARTY, AMOUNT);

        assertEq(token.balanceOf(REAL_COUNTERPARTY), AMOUNT, "genuine verified send should succeed");
        assertEq(token.balanceOf(address(policy)), START_BALANCE - AMOUNT, "only the sent amount should leave");
    }
}
