// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AddressBook} from "./AddressBook.sol";

interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title VulnerableSendWallet - wallet with the UNSAFE send policy.
/// @notice It "verifies" a recipient by the TRUNCATED display form only (leading/trailing
///         bytes). A poisoning look-alike pulled from history shares that display with the
///         real counterparty, so it passes the check and the funds go to the attacker.
///         This models a user copying a look-alike address from a poisoned history and a
///         wallet that trusts the displayed match.
contract VulnerableSendWallet {
    AddressBook public immutable book;

    constructor(AddressBook book_) {
        book = book_;
    }

    /// @param intendedCounterparty who the user believes they are paying (a verified
    ///        counterparty), used only for the (unsafe) truncated-display check.
    /// @param to the address actually copied from history (the poisoned look-alike).
    function send(address token, address intendedCounterparty, address to, uint256 amount) external {
        // Unsafe: accept `to` as long as it LOOKS like the intended counterparty in the
        // wallet UI (same truncated prefix/suffix). A look-alike satisfies this.
        require(book.isVerified(intendedCounterparty), "intended counterparty not verified");
        require(book.displayedMatches(intendedCounterparty, to), "display mismatch");
        IERC20Transfer(token).transfer(to, amount);
    }
}
