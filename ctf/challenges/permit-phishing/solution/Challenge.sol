// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the permit-phishing vector.
/// @notice Sign a permit for EXACTLY `actionAmount` and nothing more. The legitimate
///         interaction (moving up to `actionAmount`) still works, but a spender that later
///         tries to pull the full balance is stopped by the ERC-20 allowance check, because
///         the signed value - and therefore the granted allowance - is bounded.
contract Challenge {
    function permitValueFor(uint256 actionAmount) external pure returns (uint256) {
        return actionAmount;
    }
}
