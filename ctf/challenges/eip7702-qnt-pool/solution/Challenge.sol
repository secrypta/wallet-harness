// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the QNT reserve-pool 7702 drain.
/// @notice The pool trusts whoever drives this delegated code, so this code must decide who is
///         allowed to drive it. Gate `batch` on the account owner recorded at construction. The
///         owner can still batch legitimate reserve movements; an attacker's call reverts before
///         any reserves move.
contract Challenge {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function batch(address[] calldata targets, bytes[] calldata payloads) external {
        // FIX: only the account owner may drive the delegated batch executor.
        require(msg.sender == owner, "eip7702: not account owner");
        require(targets.length == payloads.length, "length mismatch");
        for (uint256 i; i < targets.length; i++) {
            (bool ok,) = targets[i].call(payloads[i]);
            require(ok, "batch: sub-call failed");
        }
    }
}
