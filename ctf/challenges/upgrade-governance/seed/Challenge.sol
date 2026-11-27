// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - an upgradeable wallet that routes operations through a swappable logic.
/// @notice This is the VULNERABLE version. Your job is to fix `setImplementation` so the
///         upgrade-governance vector no longer works, WITHOUT breaking legitimate upgrades.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this
///         name and arguments. You may change only the body (and use the `pendingImpl` /
///         `pendingEta` storage already declared below).
///
/// The intended use: the owner can upgrade the wallet's `implementation` over time. The bug
/// below is that a new implementation takes effect INSTANTLY - so one compromised owner key
/// can swap in a hostile implementation and drain the wallet in the same transaction.
contract Challenge {
    address public implementation;
    address public pendingImpl;
    uint256 public pendingEta;

    uint256 public immutable DELAY;

    constructor(address implementation_, uint256 delay_) {
        implementation = implementation_;
        DELAY = delay_;
    }

    function setImplementation(address newImpl) external {
        // BUG: the swap is instant. No delay, no guardian - a single key changes the code now.
        implementation = newImpl;
    }

    /// @notice Run an operation through the current implementation (delegatecall).
    ///         Not part of the puzzle - do not change this.
    function execute(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = implementation.delegatecall(data);
        require(ok, "execute: delegatecall failed");
        return ret;
    }
}
