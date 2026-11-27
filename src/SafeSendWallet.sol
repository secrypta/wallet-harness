// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AddressBook} from "./AddressBook.sol";

interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title SafeSendWallet - wallet with the DEFENSIVE send policy.
/// @notice It verifies the recipient by the FULL address against the verified address
///         book, never the truncated display. A poisoning look-alike (same displayed
///         prefix/suffix, different full address) is not a verified counterparty, so the
///         send is rejected and the funds never reach the attacker. A genuine send to a
///         verified counterparty still succeeds (guard against a false BLOCKED).
contract SafeSendWallet {
    AddressBook public immutable book;

    constructor(AddressBook book_) {
        book = book_;
    }

    function send(address token, address to, uint256 amount) external {
        // Safe: the recipient must be a verified counterparty by FULL address. A
        // truncated look-alike is not in the book and is rejected here.
        require(book.isVerified(to), "recipient not a verified counterparty");
        IERC20Transfer(token).transfer(to, amount);
    }
}
