// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - a wallet client's Permit2 signing policy.
/// @notice This is the VULNERABLE version. Your job is to fix `permit2AmountFor` so the
///         permit2-phishing vector no longer works, WITHOUT breaking the legitimate flow.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this
///         name and argument, then signs a Permit2 `PermitSingle` for the amount you return.
///         You may change only the body.
///
/// The intended use: the wallet is about to sign a Permit2 authorization so a spender can
/// move up to `actionAmount` of a token for one interaction. The bug below is that it
/// authorizes the maximum `uint160` instead, so whoever submits that signed permit can later
/// pull the ENTIRE balance through `Permit2.transferFrom` - the permit2-phishing drain. One
/// signature, no on-chain approve from the victim.
contract Challenge {
    function permit2AmountFor(uint256 actionAmount) external pure returns (uint160) {
        // BUG: authorizes the full uint160 range; the unused authority drains everything.
        actionAmount; // currently ignored
        return type(uint160).max;
    }
}
