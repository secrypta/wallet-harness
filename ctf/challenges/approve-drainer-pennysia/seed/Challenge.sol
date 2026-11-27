// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - minimized Pennysia Settlement with the real arbitrary-route bug.
/// @notice This is the VULNERABLE version. Your job is to fix `executeSwap` so the arbitrary-
///         route drain no longer works, WITHOUT breaking a legitimate allow-listed swap.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this name
///         and arguments. You may change only the body of `executeSwap`.
///
/// `executeSwap` forwards an attacker-chosen `(venue, route)` as a low-level call from the
/// Settlement's own context. Because users granted the Settlement a standing approval, a crafted
/// route whose venue is the token and whose calldata is `transferFrom(victim, attacker, amount)`
/// spends the victim's allowance. An allow-list is provided but not consulted - that is the bug.
contract Challenge {
    mapping(address => bool) public allowedVenue;

    /// @notice Register a venue as a legitimate swap target.
    function allowVenue(address venue) external {
        allowedVenue[venue] = true;
    }

    function executeSwap(address venue, bytes calldata route) external {
        // BUG: calls an arbitrary venue with the Settlement's own authority, ignoring the
        //      allow-list - so a route pointed at the token drains standing approvals.
        (bool ok, ) = venue.call(route);
        require(ok, "swap failed");
    }
}
