// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - the batch executor an admin EOA delegated to under EIP-7702.
/// @notice This is the VULNERABLE version, modeled on the QNT reserve-pool drain
///         (2026-04-28, ~1,974.55 QNT / ~$124.9K; pinned tx 0xef9994...684f). The executor runs
///         AS the admin account, so any contract that trusts the admin by address (here the
///         reserve pool) honors the calls it makes. The bug is that `batch` has NO caller
///         authorization - anyone can drive the account's delegated code and sweep the pool.
///
///         Your job is to fix `batch` so only the account owner can drive it, WITHOUT breaking
///         the owner's legitimate reserve movements. Keep the function signature exactly as-is;
///         change only the body. The account `owner` is recorded at construction for you.
contract Challenge {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function batch(address[] calldata targets, bytes[] calldata payloads) external {
        // BUG: no check on msg.sender - anyone can drive this delegated executor.
        require(targets.length == payloads.length, "length mismatch");
        for (uint256 i; i < targets.length; i++) {
            (bool ok,) = targets[i].call(payloads[i]);
            require(ok, "batch: sub-call failed");
        }
    }
}
