// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title Challenge - a wallet that pays counterparties from an address book.
/// @notice This is the VULNERABLE version. Your job is to fix `send` so the address-poisoning
///         vector no longer works, WITHOUT breaking the legitimate flow.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this
///         name and arguments. You may change only the body of `send`. The verified address
///         book below (`verified` / `trust`) is already available.
///
/// The intended use: the wallet saves counterparties it has verified (`trust`) and pays them
/// with `send`. The bug below is that `send` pays ANY destination it is handed - so a
/// poisoned look-alike address copied from transaction history (same truncated form as a real
/// counterparty, different in the middle) is paid exactly like the real one.
contract Challenge {
    mapping(address => bool) public verified;

    /// @notice Save a counterparty the user has verified out-of-band (full address).
    function trust(address counterparty) external {
        verified[counterparty] = true;
    }

    function send(address token, address to, uint256 amount) external {
        // BUG: no destination check - a look-alike from history is paid like a real counterparty.
        IERC20Transfer(token).transfer(to, amount);
    }
}
