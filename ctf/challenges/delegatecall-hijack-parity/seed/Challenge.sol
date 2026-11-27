// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - the shared Parity-style wallet library (minimized).
/// @notice This is the VULNERABLE version. Your job is to fix `initWallet` so the
///         delegatecall-hijack that drained the Parity multisig wallets can no longer happen,
///         WITHOUT breaking the wallet's legitimate first setup.
///
///         Keep the `initWallet` signature exactly as-is - the hidden grader calls it by this
///         name and arguments (through the proxy's delegatecall fallback). You may change only
///         its body. `execute` is not part of the puzzle.
///
///         This library runs in the PROXY's storage context via delegatecall, so `owner`
///         (slot 0) and `initialized` (slot 1) are the proxy's slots. The bug below: `initWallet`
///         sets the owner on EVERY call, so an attacker can re-initialize a live, funded wallet
///         to themselves and then `execute` a drain - the first Parity hack (2017-07-19).
contract Challenge {
    address public owner;       // slot 0 (aligned with the proxy)
    bool public initialized;    // slot 1 (aligned with the proxy) - provided for your fix

    function initWallet(address newOwner) public {
        // BUG: no "already initialized" guard - ownership can be (re)assigned by anyone.
        owner = newOwner;
    }

    function execute(address to, uint256 value) public {
        require(msg.sender == owner, "Parity: not owner");
        (bool ok, ) = to.call{value: value}("");
        require(ok, "Parity: send failed");
    }
}
