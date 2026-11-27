// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the permit2-phishing vector.
/// @notice Authorize a Permit2 `amount` of EXACTLY `actionAmount` and nothing more. The
///         legitimate interaction (moving up to `actionAmount`) still works, but a spender
///         that later tries to pull the full balance is stopped inside Permit2 by the bounded
///         allowance. `actionAmount` fits in uint160 for any realistic token amount.
contract Challenge {
    function permit2AmountFor(uint256 actionAmount) external pure returns (uint160) {
        return uint160(actionAmount);
    }
}
