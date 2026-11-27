// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the upgrade-governance vector.
/// @notice A two-step, same-signature timelock: the first `setImplementation(x)` SCHEDULES x
///         with an eta `now + DELAY`; a later `setImplementation(x)`, once the eta has passed,
///         APPLIES it. An instant single-key swap is impossible (the first call only schedules,
///         so hostile logic is never active in the same transaction), while a legitimate
///         upgrade still takes effect after the delay.
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
        // FIX: apply only if this exact impl was already scheduled and its delay has elapsed;
        //      otherwise (re)schedule it. No upgrade can take effect in the call that asks for it.
        if (newImpl == pendingImpl && pendingEta != 0 && block.timestamp >= pendingEta) {
            implementation = newImpl;
            pendingImpl = address(0);
            pendingEta = 0;
        } else {
            pendingImpl = newImpl;
            pendingEta = block.timestamp + DELAY;
        }
    }

    /// @notice Run an operation through the current implementation (delegatecall).
    ///         Not part of the puzzle - do not change this.
    function execute(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = implementation.delegatecall(data);
        require(ok, "execute: delegatecall failed");
        return ret;
    }
}
