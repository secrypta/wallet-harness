// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============================ PROVENANCE ============================
// Real-safe fixture (validation tier (c)) for the address-poisoning vector.
// Address-poisoning is a UX / transaction-history attack, not a contract bug,
// so there is NO third-party library whose code we can vendor as the safe
// implementation. The canonical defense in real wallets is: resolve the
// recipient by the FULL address of a counterparty the user has explicitly
// verified, never by the truncated display an attacker crafts a look-alike to
// match. This contract is a faithful REFERENCE IMPLEMENTATION of that canonical
// pattern (authored here), not vendored third-party code - stated honestly so a
// reviewer is not misled. See PROVENANCE.md.
// ====================================================================

import {AddressBook} from "../../../src/AddressBook.sol";

interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title VerifiedSendPolicy - canonical full-address-verification send policy.
/// @notice Reference implementation of the defense real wallets use against address
///         poisoning: a transfer is allowed only to a recipient the user has verified by
///         FULL address in their address book. A poisoning look-alike (same truncated
///         display, different full address) is not verified, so the send reverts and the
///         funds never reach the attacker. A genuine send to a verified counterparty still
///         succeeds (so BLOCKED is never a vacuous "nothing can send").
contract VerifiedSendPolicy {
    AddressBook public immutable book;

    constructor(AddressBook book_) {
        book = book_;
    }

    function send(address token, address to, uint256 amount) external {
        require(book.isVerified(to), "address-poisoning: recipient not verified by full address");
        IERC20Transfer(token).transfer(to, amount);
    }
}
