// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============================ PROVENANCE ============================
// Real-safe fixture (validation tier (c)) for the approve-drainer vector.
// This is the DEFENSIVE allowance policy exercised against the unmodified
// OpenZeppelin ERC20 (v5.1.0, commit 69c8def5f222ff96f2b5beff05dfba996368aa79,
// MIT). It grants exactly the allowance the action needs, so OZ's own
// `_spendAllowance` reverts any attempt to pull more than that. The harness
// MUST stay silent on this fixture (expected verdict: BLOCKED / label safe).
// ====================================================================

import {IERC20} from "../../vendor/oz/token/ERC20/IERC20.sol";

/// @title SafeAllowanceFlow - bounded-approve wallet policy over real OZ ERC20.
/// @notice When an action needs a spender to move `actionAmount` tokens, this
///         wallet approves EXACTLY `actionAmount` - never an unlimited/standing
///         allowance. A spender that later tries to pull the full balance is
///         stopped by OpenZeppelin's allowance check, so the approve-drainer
///         vector reverts and the balance stays intact.
contract SafeAllowanceFlow {
    function authorizeSpender(address token, address spender, uint256 actionAmount) external {
        IERC20(token).approve(spender, actionAmount);
    }
}
