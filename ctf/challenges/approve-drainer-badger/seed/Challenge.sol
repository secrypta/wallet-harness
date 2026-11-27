// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBadgerToken {
    function approve(address spender, uint256 amount) external returns (bool);
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool);
}

/// @title Challenge - the wallet's approval helper for the Badger vault token.
/// @notice This is the VULNERABLE version, reproducing the incident. Your job is to fix
///         `authorizeSpender` so the approve-drainer vector no longer works, WITHOUT breaking
///         the legitimate flow.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this name
///         and arguments. You may change only the body.
///
/// The intended use: the wallet holds vault tokens and wants to let `spender` move up to
/// `actionAmount` for one interaction. The bug below is that it grants an UNLIMITED allowance
/// (exactly the unbounded `increaseAllowance` the compromised Badger front-end injected), so the
/// spender can later pull the ENTIRE balance.
contract Challenge {
    function authorizeSpender(address token, address spender, uint256 actionAmount) external {
        // BUG: bumps the allowance to infinity; the unused allowance lets the spender drain all.
        actionAmount; // currently ignored
        IBadgerToken(token).increaseAllowance(spender, type(uint256).max);
    }
}
