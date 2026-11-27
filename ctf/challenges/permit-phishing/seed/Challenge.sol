// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - a wallet client's EIP-2612 permit signing policy.
/// @notice This is the VULNERABLE version. Your job is to fix `permitValueFor` so the
///         permit-phishing vector no longer works, WITHOUT breaking the legitimate flow.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this
///         name and argument, then signs a permit for the value you return. You may change
///         only the body.
///
/// The intended use: the wallet is about to sign an EIP-2612 permit so a spender can move
/// up to `actionAmount` of a token for one interaction. The bug below is that it signs an
/// UNLIMITED value instead, so whoever submits that signed permit can later pull the ENTIRE
/// balance via transferFrom - the classic permit-phishing drain. No on-chain approve tx is
/// ever sent, which is exactly why the victim sees "nothing to inspect".
contract Challenge {
    function permitValueFor(uint256 actionAmount) external pure returns (uint256) {
        // BUG: signs an infinite permit; the unused authority lets a spender drain everything.
        actionAmount; // currently ignored
        return type(uint256).max;
    }
}
