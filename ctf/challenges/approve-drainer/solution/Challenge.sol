// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @title Challenge - reference FIX for the approve-drainer vector.
/// @notice Grant an allowance of EXACTLY `actionAmount` and nothing more. The legitimate
///         interaction (moving up to `actionAmount`) still works, but a spender that later
///         tries to pull the full balance is stopped by the ERC-20 allowance check.
contract Challenge {
    function authorizeSpender(address token, address spender, uint256 actionAmount) external {
        IERC20Approve(token).approve(spender, actionAmount);
    }
}
