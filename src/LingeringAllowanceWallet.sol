// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IActionSpender {
    function performAction(address token, uint256 amount) external;
}

/// @title LingeringAllowanceWallet - UNSAFE lingering-allowance policy (R3, vulnerable).
/// @notice To pay for an action the wallet approves a service for `actionAmount`, then lets
///         the service perform an action that spends only `actionSpend` (<= actionAmount).
///         The bug: after the action it NEVER zeroes the unused `actionAmount - actionSpend`
///         allowance. That residual approval keeps lingering and lets the (now malicious or
///         compromised) service pull it later. This is the lingering-allowance drain surface
///         that rule R3 flags.
contract LingeringAllowanceWallet {
    function authorizeAndAct(address token, address spender, uint256 actionAmount, uint256 actionSpend) external {
        IERC20Approve(token).approve(spender, actionAmount);
        IActionSpender(spender).performAction(token, actionSpend); // consumes only part
        // BUG: residual allowance (actionAmount - actionSpend) is left live. No reset.
    }
}
