// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title Challenge - reference FIX for the address-poisoning vector.
/// @notice Resolve the destination against the verified address book (full address) before
///         paying. A verified counterparty is still paid normally; a look-alike that was
///         never verified - e.g. one planted in history - is rejected.
contract Challenge {
    mapping(address => bool) public verified;

    function trust(address counterparty) external {
        verified[counterparty] = true;
    }

    function send(address token, address to, uint256 amount) external {
        require(verified[to], "address-poisoning: destination not a verified counterparty");
        IERC20Transfer(token).transfer(to, amount);
    }
}
