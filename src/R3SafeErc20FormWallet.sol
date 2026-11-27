// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// DRAFT (scratchpad, NOT committed) - R3 real-form VULN toy.
// Lingering-allowance (bounded approve + action use + no reset) expressed in the
// library-static form that member-only R3 is blind to. The grant is
// SafeERC20.safeIncreaseAllowance(token, spender, amount) and the "use" is a later
// SafeERC20.safeTransferFrom(token, from, to, amount) / external call - both must be
// recognized by M's shared recognizer. No reset-to-zero afterwards -> R3 must FIRE.
// Target src path when wired: src/R3SafeErc20FormWallet.sol.

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
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

interface IActionSpender {
    function performAction(address token, uint256 amount) external;
}

contract R3SafeErc20FormWallet {
    using SafeERC20 for IERC20;

    /// Approves `spender` for `actionAmount` via the library form, lets it perform an action
    /// that consumes only part, and NEVER zeroes the residual allowance. Lingering-allowance
    /// drain surface (R3), identical in effect to src/LingeringAllowanceWallet.sol but in the
    /// SafeERC20 call shape.
    function authorizeAndAct(address token, address spender, uint256 actionAmount, uint256 actionSpend)
        external
    {
        SafeERC20.safeIncreaseAllowance(IERC20(token), spender, actionAmount);
        IActionSpender(spender).performAction(token, actionSpend); // consumes only part
        // BUG: residual (actionAmount - actionSpend) left live. No reset to zero.
    }
}
