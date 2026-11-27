// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AddressBook} from "../src/AddressBook.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {VulnerableSendWallet} from "../src/VulnerableSendWallet.sol";

/// @title address-poisoning (b) real-incident HOLDOUT: May 2024 ~$68M WBTC poisoning.
/// @notice Minimized OFFLINE replay of the documented pattern (no live RPC): an attacker had
///         seeded the victim's history with a look-alike entry whose truncated wallet display
///         matches a real counterparty the victim had paid before. On 2024-05-03 the victim
///         copied the look-alike from history and sent ~1,155 WBTC to it; because the full
///         address differs, the funds went to the attacker. Models a wallet that trusts the
///         displayed match (VulnerableSendWallet). The verdict is derived from the real outcome
///         (funds landed on the look-alike), not hardcoded. See PROVENANCE.md.
///
///         HOLDOUT: authored after the wal detectors froze at v0.1; wal was NOT tuned to pass
///         it. Independent from the dev usdt-poison fixture (a distinct, separately-documented
///         incident with its OWN real on-chain addresses, used verbatim below).
contract WbtcAddressPoisonIncidentTest is Test {
    // The real on-chain parties, verbatim from the public reports (see PROVENANCE.md).
    // Note they genuinely share the displayed prefix (0xd9A1) AND suffix (853a91) while the
    // full 20-byte addresses differ - the defining property of the address-poisoning vector.
    address constant VICTIM = 0x1E227979f0b5BC691a70DEAed2e0F39a6F538FD5;
    address constant REAL_COUNTERPARTY = 0xd9A1b0B1e1aE382DbDc898Ea68012FfcB2853a91; // intended
    address constant POISON_LOOKALIKE = 0xd9A1C3788D81257612E2581A6ea0aDa244853a91;  // attacker

    uint256 constant SEND_AMOUNT = 1_155 * 1e8; // ~1,155 WBTC (WBTC has 8 decimals)

    function _report(string memory target, bool misrouted) internal pure {
        console.log(
            string.concat(
                "[address-poisoning] target=", target, " verdict=", misrouted ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_wbtcPoisonIncident_isMisrouted() public {
        // Poisoning premise, checked on the REAL incident addresses: the look-alike shares the
        // truncated display with the real counterparty but is a different full address.
        AddressBook book = new AddressBook();
        require(book.displayedMatches(REAL_COUNTERPARTY, POISON_LOOKALIKE), "premise: display must match");
        require(REAL_COUNTERPARTY != POISON_LOOKALIKE, "premise: full addresses must differ");

        book.addVerified(REAL_COUNTERPARTY);

        VulnerableSendWallet wallet = new VulnerableSendWallet(book);
        MockERC20 wbtc = new MockERC20();
        wbtc.mint(address(wallet), SEND_AMOUNT);

        // The victim means to pay REAL_COUNTERPARTY but copied the look-alike from history;
        // the wallet accepts it because it only checks the truncated display.
        wallet.send(address(wbtc), REAL_COUNTERPARTY, POISON_LOOKALIKE, SEND_AMOUNT);

        bool misrouted = wbtc.balanceOf(POISON_LOOKALIKE) > 0;
        _report("wbtc-poison-victim", misrouted);

        assertTrue(misrouted, "funds should land on the poison look-alike");
        assertEq(wbtc.balanceOf(POISON_LOOKALIKE), SEND_AMOUNT, "attacker should receive the payment");
        assertEq(wbtc.balanceOf(REAL_COUNTERPARTY), 0, "real counterparty should receive nothing");
        // VICTIM is cited for provenance (the losing account); not otherwise exercised.
        assertTrue(VICTIM != address(0), "victim address pinned for provenance");
    }
}
