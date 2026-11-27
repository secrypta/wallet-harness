// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @title SafeWallet - wallet with the DEFENSIVE approval policy.
/// @notice When it needs to let a spender move `actionAmount` tokens, it grants an
///         allowance of EXACTLY `actionAmount` and nothing more. A spender that later
///         tries to pull the full balance is stopped by the ERC-20 allowance check,
///         so the approve-drainer vector reverts and the balance stays intact.
contract SafeWallet {
    function authorizeSpender(address token, address spender, uint256 actionAmount) external {
        IERC20Approve(token).approve(spender, actionAmount);
    }
}
