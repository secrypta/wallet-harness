// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AddressBook} from "../src/AddressBook.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {VulnerableSendWallet} from "../src/VulnerableSendWallet.sol";

/// @title address-poisoning (b) real-incident fixture: Dec 2024 ~$50M USDT poisoning.
/// @notice Minimized OFFLINE replay of the documented pattern (no live RPC): an attacker had
///         seeded the victim's transfer history with a zero-value / look-alike entry whose
///         truncated wallet display (leading/trailing bytes) matches the real counterparty.
///         The victim then copied the look-alike from history and paid it; because the full
///         address differs, the funds went to the attacker. Models a wallet that trusts the
///         displayed match (VulnerableSendWallet). The USDT amount is 6-decimal. The verdict
///         is derived from the real outcome (funds landed on the look-alike). See PROVENANCE.md.
contract UsdtAddressPoisonIncidentTest is Test {
    // Numeric literals (leading 00) + uint160 cast: no EIP-55 checksum needed. The real
    // counterparty and the poison look-alike share the displayed prefix/suffix 0x1A2B..9F7C
    // but differ in the full address. (Representative: the Dec 2024 incident's exact victim
    // tx is not pinned here - see PROVENANCE.md.)
    address constant REAL_COUNTERPARTY =
        address(uint160(0x001a2baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9f7c));
    address constant POISON_LOOKALIKE =
        address(uint160(0x001a2bcccccccccccccccccccccccccccccccc9f7c)); // the attacker

    uint256 constant VICTIM_BALANCE = 50_000_000e6; // USDT has 6 decimals
    uint256 constant SEND_AMOUNT = 50_000_000e6;

    function _report(string memory target, bool misrouted) internal pure {
        console.log(
            string.concat(
                "[address-poisoning] target=", target, " verdict=", misrouted ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_usdtPoisonIncident_isMisrouted() public {
        AddressBook book = new AddressBook();
        book.addVerified(REAL_COUNTERPARTY);
        // Poisoning premise: the look-alike shares the truncated display but differs fully.
        require(book.displayedMatches(REAL_COUNTERPARTY, POISON_LOOKALIKE), "premise: display must match");
        require(REAL_COUNTERPARTY != POISON_LOOKALIKE, "premise: full addresses must differ");

        VulnerableSendWallet wallet = new VulnerableSendWallet(book);
        MockERC20 usdt = new MockERC20();
        usdt.mint(address(wallet), VICTIM_BALANCE);

        // The victim means to pay REAL_COUNTERPARTY but copied the look-alike from history;
        // the wallet accepts it because it only checks the truncated display.
        wallet.send(address(usdt), REAL_COUNTERPARTY, POISON_LOOKALIKE, SEND_AMOUNT);

        bool misrouted = usdt.balanceOf(POISON_LOOKALIKE) > 0;
        _report("usdt-poison-victim", misrouted);

        assertTrue(misrouted, "funds should land on the poison look-alike");
        assertEq(usdt.balanceOf(POISON_LOOKALIKE), SEND_AMOUNT, "attacker should receive the payment");
        assertEq(usdt.balanceOf(REAL_COUNTERPARTY), 0, "real counterparty should receive nothing");
    }
}
