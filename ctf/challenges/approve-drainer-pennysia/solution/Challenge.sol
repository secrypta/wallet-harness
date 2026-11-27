// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the Pennysia arbitrary-route drain.
/// @notice The only change is in `executeSwap`: require that the venue was explicitly
///         allow-listed before calling it. A legitimate swap through a registered venue still
///         executes, but a route pointed at an arbitrary address (e.g. the token, to spend a
///         victim's standing approval) is rejected.
contract Challenge {
    mapping(address => bool) public allowedVenue;

    function allowVenue(address venue) external {
        allowedVenue[venue] = true;
    }

    function executeSwap(address venue, bytes calldata route) external {
        // FIX: only route to venues that were explicitly allow-listed.
        require(allowedVenue[venue], "venue not allow-listed");
        (bool ok, ) = venue.call(route);
        require(ok, "swap failed");
    }
}
