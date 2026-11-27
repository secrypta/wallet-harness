// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IActionSpender {
    function performAction(address token, uint256 amount) external;
}

/// @title ResetAllowanceWallet - DEFENSIVE lingering-allowance policy (R3, safe).
/// @notice Same flow as the vulnerable wallet - approve `actionAmount`, let the service
///         perform an action spending `actionSpend` - but it then resets the allowance to
///         ZERO. No residual approval lingers, so a later attempt to sweep the leftover
///         finds nothing and the full-balance drain the lingering allowance would have
///         enabled never materializes. Rule R3 must stay silent here (0 false positives).
contract ResetAllowanceWallet {
    function authorizeAndAct(address token, address spender, uint256 actionAmount, uint256 actionSpend) external {
        IERC20Approve(token).approve(spender, actionAmount);
        IActionSpender(spender).performAction(token, actionSpend);
        IERC20Approve(token).approve(spender, 0); // reset: no lingering residual allowance
    }
}
