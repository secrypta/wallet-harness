// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AddressBook} from "../src/AddressBook.sol";
import {OZERC20Fixture} from "../fixtures/approve-drainer/c-safe-impl/OZERC20Fixture.sol";

/// @title address-poisoning (c) real-safe fixture: benign near-collision, real OZ ERC-20 send.
/// @notice PRECISION / 0-FP control specific to the poisoning logic. The transfer here is the
///         UNMODIFIED OpenZeppelin v5.1.0 ERC20.transfer (real third-party code, see
///         PROVENANCE.md). The scenario is the honest complement of the attack: a near-collision
///         EXISTS in the user's history (a decoy address shares the displayed prefix+suffix with
///         the intended counterparty) yet the user pays the correct, verified FULL address. A
///         poisoning detector must NOT flag a legitimate send just because some other address
///         shares the truncated display - doing so would be a false positive. Funds reach the
///         intended recipient, the decoy gets nothing -> not misrouted -> BLOCKED.
///
///         Honest scope: the real code is OZ ERC20; the near-collision SETUP is an AUTHORED
///         synthetic control (there is no real-world incident of a *benign* collision to cite,
///         and no third-party on-chain anti-poisoning library exists). See PROVENANCE.md.
contract RealSafeAddressPoisoningNearCollisionTest is Test {
    // 42-hex numeric literals (leading 00) + uint160 cast: no EIP-55 checksum needed. Both
    // share the displayed prefix 0xDEAD..BEEF but differ in the full address. INTENDED is the
    // user's verified counterparty; DECOY is a look-alike that merely appears in history.
    address constant INTENDED =
        address(uint160(0x00DEAD11111111111111111111111111111111BEEF));
    address constant DECOY =
        address(uint160(0x00DEAD22222222222222222222222222222222BEEF));
    address constant SENDER = address(0x5E4DE2);

    uint256 constant START_BALANCE = 100e18;
    uint256 constant AMOUNT = 40e18;

    function _report(string memory target, bool misrouted) internal pure {
        console.log(
            string.concat(
                "[address-poisoning] target=", target, " verdict=", misrouted ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    /// Safe: a legitimate send to the verified full address is NOT poisoning, even though a
    /// displayed-prefix/suffix near-collision exists in history. Real OZ ERC20.transfer.
    function test_benignNearCollision_legitSend_isNotPoisoning() public {
        AddressBook book = new AddressBook();
        book.addVerified(INTENDED);

        // Premise: a genuine near-collision exists (same truncated display, different full
        // address), so this is a real precision test for the poisoning logic - not a trivially
        // clean case with no collision.
        require(book.displayedMatches(INTENDED, DECOY), "premise: displayed prefix/suffix must match");
        require(INTENDED != DECOY, "premise: full addresses must differ");

        OZERC20Fixture token = new OZERC20Fixture();
        token.mint(SENDER, START_BALANCE);

        // The user pays the intended, verified counterparty by its FULL address via the real
        // OpenZeppelin ERC20.transfer. (It does NOT send to the look-alike decoy.)
        vm.prank(SENDER);
        token.transfer(INTENDED, AMOUNT);

        // A poisoning drain would land funds at the look-alike decoy. Here nothing does.
        bool misrouted = token.balanceOf(DECOY) > 0;
        _report("oz-erc20-benign-nearcollision-safe", misrouted);

        assertFalse(misrouted, "legit send must not be treated as a poisoning drain");
        assertEq(token.balanceOf(DECOY), 0, "look-alike decoy must receive nothing");
        // Non-vacuous: the real transfer did move funds - to the correct intended recipient.
        assertEq(token.balanceOf(INTENDED), AMOUNT, "intended verified counterparty received the funds");
        assertEq(token.balanceOf(SENDER), START_BALANCE - AMOUNT, "only the sent amount left the sender");
    }
}
