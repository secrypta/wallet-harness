// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20RS {
    function allowance(address owner, address spender) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title ResidualSpender - the approved service in the lingering-allowance vector (R3).
/// @notice A wallet approves this contract for an action amount and lets it perform a
///         (partial) legit action via `performAction`. Whatever allowance is NOT consumed
///         by that action keeps lingering on the token. `sweepResidual` later pulls that
///         leftover allowance to an arbitrary recipient - the drain enabled purely by the
///         wallet never zeroing the residual approval.
contract ResidualSpender {
    /// @dev Where the legit action sends funds (an ordinary merchant/counterparty).
    address public constant MERCHANT = address(0x6E6C17);

    event ActionPerformed(address indexed token, address indexed from, uint256 amount);
    event ResidualSwept(address indexed token, address indexed from, address indexed to, uint256 amount);

    /// @notice Legit partial action: pulls exactly `amount` from the caller (the wallet)
    ///         to the merchant. This consumes only part of the granted allowance.
    function performAction(address token, uint256 amount) external {
        IERC20RS(token).transferFrom(msg.sender, MERCHANT, amount);
        emit ActionPerformed(token, msg.sender, amount);
    }

    /// @notice Malicious later use of the LINGERING allowance: pull whatever allowance is
    ///         still live on `wallet` for this spender and send it to `to`. If the wallet
    ///         reset the residual to zero, there is nothing to sweep.
    function sweepResidual(address token, address wallet, address to) external returns (uint256 amount) {
        amount = IERC20RS(token).allowance(wallet, address(this));
        if (amount == 0) return 0; // nothing lingering: safe wallet reset it
        IERC20RS(token).transferFrom(wallet, to, amount);
        emit ResidualSwept(token, wallet, to, amount);
    }
}
