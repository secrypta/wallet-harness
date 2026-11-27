// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - a wallet client's Permit2 signing policy (Lixir-style incident: LINK drain).
/// @notice This is the VULNERABLE version, reproducing the incident: it signs an UNBOUNDED
///         Permit2 amount. Your job is to fix `permit2AmountFor` so the phishing drain no longer
///         works, WITHOUT breaking the legitimate flow.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this name
///         and argument, then signs a Permit2 `PermitSingle` for the amount you return. You may
///         change only the body.
///
/// The intended use: authorize a Permit2 spend of up to `actionAmount` for one interaction. The
/// bug below is that it authorizes the maximum `uint160` - exactly the unbounded signature the
/// LINK victim was phished into - so whoever holds that signed permit can drain the entire
/// balance through `Permit2.transferFrom`.
contract Challenge {
    function permit2AmountFor(uint256 actionAmount) external pure returns (uint160) {
        // BUG: authorizes the full uint160 range; the unused authority drains everything.
        actionAmount; // currently ignored
        return type(uint160).max;
    }
}
