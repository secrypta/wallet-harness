// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============================ PROVENANCE ============================
// Real-safe fixture (validation tier (c)) for the approve-drainer vector.
// The safety-relevant logic - the allowance set/reset helpers and ERC20's own
// `_spendAllowance` check - is UNMODIFIED OpenZeppelin:
//   SafeERC20 (forceApprove / safeDecreaseAllowance) + ERC20
//   source : github.com/OpenZeppelin/openzeppelin-contracts
//   tag    : v5.1.0
//   commit : 69c8def5f222ff96f2b5beff05dfba996368aa79
//   license: MIT (see fixtures vendor/oz/LICENSE)
// This file adds ONLY the authored defensive policy (grant exactly the action
// amount via SafeERC20.forceApprove, then reset it to zero after the action).
// It changes none of OZ's authorization logic. Never deploy on a real network.
// ====================================================================

import {IERC20} from "../../vendor/oz/token/ERC20/IERC20.sol";
import {SafeERC20} from "../../vendor/oz/token/ERC20/utils/SafeERC20.sol";

/// @title SafeErc20AllowanceFlow - canonical OZ SafeERC20 bounded-approve policy.
/// @notice Uses OpenZeppelin's `SafeERC20.forceApprove` to grant a spender EXACTLY the
///         amount an action needs, and `forceApprove(..., 0)` to revoke it afterwards.
///         Because the real OZ ERC20 `_spendAllowance` decrements any bounded allowance,
///         a spender can never pull more than the granted amount, and nothing remains
///         standing after the action. The approve-drainer full-balance pull reverts.
contract SafeErc20AllowanceFlow {
    using SafeERC20 for IERC20;

    /// @notice Grant exactly `actionAmount` to `spender` (no unlimited/standing allowance).
    function authorizeSpender(address token, address spender, uint256 actionAmount) external {
        IERC20(token).forceApprove(spender, actionAmount);
    }

    /// @notice Revoke any residual allowance after the action (reset to zero).
    function revokeSpender(address token, address spender) external {
        IERC20(token).forceApprove(spender, 0);
    }
}
