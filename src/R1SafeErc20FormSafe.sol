// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// DRAFT (scratchpad, NOT committed) - R1 real-form SAFE control (0-FP).
// Same SafeERC20 library forms as the vuln toy, but every grant is defensive:
// bounded amount, or max to a FIXED address literal. R1 must stay SILENT on all of
// these once the recognizer lands (0 false positives is a hard requirement).
// Target src path when wired: src/R1SafeErc20FormSafe.sol.

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
}

contract R1SafeErc20FormSafe {
    using SafeERC20 for IERC20;

    // (a) BOUNDED static approve - exactly the action amount -> silent.
    function authorizeBoundedStatic(address token, address spender, uint256 actionAmount) external {
        SafeERC20.safeApprove(IERC20(token), spender, actionAmount);
    }

    // (b) BOUNDED using-for approve -> silent.
    function authorizeBoundedUsingFor(address token, address spender, uint256 actionAmount) external {
        IERC20(token).safeApprove(spender, actionAmount);
    }

    // (c) UNBOUNDED but to a hard-coded address LITERAL (audited counterparty) -> silent
    //     (R1's arbitrary-spender gate exempts address literals).
    function authorizeMaxToFixed(address token) external {
        SafeERC20.safeApprove(IERC20(token), 0x1111111254EEB25477B68fb85Ed929f73A960582, type(uint256).max);
    }

    // (d) BOUNDED increaseAllowance to an arbitrary spender -> silent (amount not max).
    function authorizeBoundedIncrease(address token, address spender, uint256 actionAmount) external {
        SafeERC20.safeIncreaseAllowance(IERC20(token), spender, actionAmount);
    }
}
