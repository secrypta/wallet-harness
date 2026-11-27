// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the eip7702-delegation vector.
/// @notice Gate the batch executor on the caller: only the account owner recorded at
///         construction may drive the delegated code. The owner can still batch legitimate
///         calls; an attacker's call reverts before any asset moves.
contract Challenge {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function batch(address[] calldata targets, bytes[] calldata payloads) external {
        // FIX: only the account owner may drive the delegated executor.
        require(msg.sender == owner, "eip7702: not account owner");
        require(targets.length == payloads.length, "length mismatch");
        for (uint256 i; i < targets.length; i++) {
            (bool ok,) = targets[i].call(payloads[i]);
            require(ok, "batch: sub-call failed");
        }
    }
}
