// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AddressBook - verified counterparties for the address-poisoning corpus vector.
/// @notice Toy, test-only registry of counterparties the user has explicitly verified
///         (by FULL address). The address-poisoning vector works because wallets show
///         addresses truncated (`0x1234...cdef`) and an attacker plants a look-alike with
///         the same displayed prefix/suffix but a different full address. A safe send
///         policy checks membership here by the full address; a naive one trusts the
///         truncated display, which `displayedMatches` models.
contract AddressBook {
    mapping(address => bool) public isVerified;

    event Verified(address indexed counterparty);

    /// @notice Toy registration (no access control on purpose; fixtures only).
    function addVerified(address counterparty) external {
        isVerified[counterparty] = true;
        emit Verified(counterparty);
    }

    /// @notice The truncated, human-visible form two addresses share in a wallet UI:
    ///         the leading 2 bytes and trailing 2 bytes (e.g. `0x1234...cdef`). This is
    ///         what a user eyeballs when copying from history - and exactly what a
    ///         poisoning look-alike is crafted to match. Comparing on this (instead of
    ///         the full address) is the unsafe behaviour.
    function displayedMatches(address a, address b) public pure returns (bool) {
        uint160 x = uint160(a);
        uint160 y = uint160(b);
        uint160 prefix = 1 << 144; // top 2 bytes live above bit 144
        bool samePrefix = (x / prefix) == (y / prefix);
        bool sameSuffix = (x & 0xFFFF) == (y & 0xFFFF);
        return samePrefix && sameSuffix;
    }
}
