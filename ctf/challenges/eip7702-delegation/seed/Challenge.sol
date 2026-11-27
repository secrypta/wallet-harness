// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - a delegated batch executor for an EIP-7702 account.
/// @notice This is the VULNERABLE version. Your job is to fix `batch` so only the account
///         owner can drive it, WITHOUT breaking the owner's own batch calls.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this
///         name and arguments. You may change only the body.
///
/// The intended use: the account owner batches several calls into one (e.g. approve + swap).
/// The bug is that `batch` has NO caller authorization - anyone can drive the delegated
/// account's code and make it transfer the account's whole balance to an attacker. The
/// `owner` is recorded at construction for you to gate against.
contract Challenge {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function batch(address[] calldata targets, bytes[] calldata payloads) external {
        // BUG: no check on msg.sender - any caller can drive the account's delegated code.
        require(targets.length == payloads.length, "length mismatch");
        for (uint256 i; i < targets.length; i++) {
            (bool ok,) = targets[i].call(payloads[i]);
            require(ok, "batch: sub-call failed");
        }
    }
}
