// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// DRAFT (scratchpad, NOT committed) - R1 real-form VULN toy.
// Mirrors the REAL library-static approve form found in verified code (Anyswap
// TransferHelper.safeApprove, Hedgey SafeERC20.safe* family) that the member-only R1
// scan is blind to. Must FIRE under R1 once M's shared form recognizer lands
// (_delegation.py: approve-family normalized across member + static spender=args[1] +
// using-for spender=args[0]). Target src path when wired: src/R1SafeErc20FormWallet.sol.

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

/// @title R1SafeErc20FormWallet - unbounded approve to an arbitrary spender, in LIBRARY form.
/// @notice Same R1 defect as src/VulnerableWallet.sol (unlimited allowance to a non-fixed
///         spender) but expressed through SafeERC20 instead of a direct `token.approve(...)`.
///         `spender` is a caller-supplied parameter (arbitrary) and the amount is
///         type(uint256).max. R1 must flag both the static and the using-for call shapes.
contract R1SafeErc20FormWallet {
    using SafeERC20 for IERC20;

    // (a) STATIC library call: SafeERC20.safeApprove(token, spender, max) -> spender = args[1]
    function authorizeStatic(address token, address spender, uint256 actionAmount) external {
        actionAmount; // deliberately unused: bug is over-approving to infinity
        SafeERC20.safeApprove(IERC20(token), spender, type(uint256).max);
    }

    // (b) USING-FOR library call: token.safeApprove(spender, max) -> spender = args[0]
    function authorizeUsingFor(address token, address spender, uint256 actionAmount) external {
        actionAmount;
        IERC20(token).safeApprove(spender, type(uint256).max);
    }

    // (c) STATIC safeIncreaseAllowance to an arbitrary spender at max (Hedgey call shape)
    function authorizeIncrease(address token, address spender) external {
        SafeERC20.safeIncreaseAllowance(IERC20(token), spender, type(uint256).max);
    }
}
