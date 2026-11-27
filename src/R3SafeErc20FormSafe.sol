// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// DRAFT (scratchpad, NOT committed) - R3 real-form SAFE control (0-FP).
// Same library forms, but the residual allowance IS reset to zero after the action
// (forceApprove(token, spender, 0) / safeApprove(token, spender, 0)). R3 must stay SILENT.
// Target src path when wired: src/R3SafeErc20FormSafe.sol.

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

library SafeERC20 {
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        require(token.approve(spender, value), "approve failed");
    }
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender) + value;
        require(token.approve(spender, newAllowance), "increase failed");
    }
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        token.approve(spender, 0);
        require(token.approve(spender, value), "forceApprove failed");
    }
}

interface IActionSpender {
    function performAction(address token, uint256 amount) external;
}

contract R3SafeErc20FormSafe {
    using SafeERC20 for IERC20;

    /// Approves via the library form, performs the action, then RESETS the allowance to zero
    /// (forceApprove to 0). No residual lingers -> R3 silent.
    function authorizeActReset(address token, address spender, uint256 actionAmount, uint256 actionSpend)
        external
    {
        SafeERC20.safeIncreaseAllowance(IERC20(token), spender, actionAmount);
        IActionSpender(spender).performAction(token, actionSpend);
        SafeERC20.forceApprove(IERC20(token), spender, 0); // reset-to-zero: no lingering allowance
    }
}
