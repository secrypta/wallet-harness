// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @title Challenge - a wallet that authorizes a spender for a token action.
/// @notice This is the VULNERABLE version. Your job is to fix `authorizeSpender` so the
///         approve-drainer vector no longer works, WITHOUT breaking the legitimate flow.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this
///         name and arguments. You may change only the body.
///
/// The intended use: the wallet holds tokens and wants to let `spender` move up to
/// `actionAmount` of them (e.g. to pay for one interaction). The bug below is that it
/// grants an UNLIMITED allowance instead, so the spender can later pull the ENTIRE
/// balance - the classic approve-drainer.
contract Challenge {
    function authorizeSpender(address token, address spender, uint256 actionAmount) external {
        // BUG: over-approves to infinity; the unused allowance lets the spender drain everything.
        actionAmount; // currently ignored
        IERC20Approve(token).approve(spender, type(uint256).max);
    }
}
