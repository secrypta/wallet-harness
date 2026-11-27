// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the Parity wallet-library drain.
/// @notice Guard ownership setup so it can run only ONCE. The first `initWallet` sets the
///         owner; any later call reverts, so an attacker can no longer re-initialize a live
///         wallet to themselves. The legitimate first setup and `execute` still work. This is
///         the historical "already initialized" fix.
contract Challenge {
    address public owner;       // slot 0 (aligned with the proxy)
    bool public initialized;    // slot 1 (aligned with the proxy)

    function initWallet(address newOwner) public {
        // FIX: ownership can be set only once.
        require(!initialized, "Parity: already initialized");
        initialized = true;
        owner = newOwner;
    }

    function execute(address to, uint256 value) public {
        require(msg.sender == owner, "Parity: not owner");
        (bool ok, ) = to.call{value: value}("");
        require(ok, "Parity: send failed");
    }
}
