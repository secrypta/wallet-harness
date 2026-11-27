// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @title VulnerableWallet - wallet with the UNSAFE approval policy.
/// @notice When it needs to let a spender move `actionAmount` tokens, it grants an
///         UNLIMITED allowance (type(uint256).max) instead of just `actionAmount`.
///         This is the single most common wallet-drain enabler: the extra, unused
///         allowance stays live forever and lets a malicious spender take everything.
contract VulnerableWallet {
    /// @param actionAmount the amount the current action actually requires (ignored
    ///        on purpose - the unsafe policy over-approves to "infinity").
    function authorizeSpender(address token, address spender, uint256 actionAmount) external {
        actionAmount; // deliberately unused: the bug is approving far more than needed
        IERC20Approve(token).approve(spender, type(uint256).max);
    }
}
