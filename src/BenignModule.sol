// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BenignModule - a genuinely harmless module for the guard case.
/// @notice Its `connect()` really is benign: it touches no assets and grants no
///         allowance. Used to prove the protected wallet's simulation does not reject
///         everything (a legitimate benign action still executes), so a BLOCKED verdict
///         on the malicious module is not a false positive.
contract BenignModule {
    event Connected();

    /// @notice No asset movement, no approvals - the effect matches the stated intent.
    function connect() external {
        emit Connected();
    }
}
