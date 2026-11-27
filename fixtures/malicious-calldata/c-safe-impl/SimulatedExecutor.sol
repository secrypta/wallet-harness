// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20View {
    function balanceOf(address owner) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

/// @title SimulatedExecutor - malicious-calldata tier (c): a reference implementation of the
///        canonical "simulate the net effect, then commit" wallet guard.
/// @notice This is the defense modern wallets apply against hidden/mislabeled calldata
///         (transaction simulation + state-diff inspection, e.g. Fire / Blockaid / Pocket
///         Universe / Wallet Guard). It does NOT trust the presented action label. Instead
///         it DRY-RUNS the action in a sub-call that always reverts (so its state changes
///         roll back), reads the resulting net effect on the wallet's assets, and only
///         COMMITS the action for real if that effect is benign (no new allowance to the
///         counterparty, no balance outflow). A hidden `approve`/`transfer` is caught by the
///         simulation and the action is rejected before it ever takes hold - and the guard
///         does not need to know the hidden effect in advance, it is detected by net effect.
contract SimulatedExecutor {
    error HiddenAllowanceGrant();
    error HiddenBalanceOutflow();
    error SimulationUnexpected();

    /// @notice Execute `module.connect()` only if simulating it shows a benign net effect
    ///         on `asset` with respect to the counterparty `module`.
    function executeSimulated(address module, address asset) external {
        uint256 allowanceBefore = IERC20View(asset).allowance(address(this), module);
        uint256 balanceBefore = IERC20View(asset).balanceOf(address(this));

        // Phase 1 - DRY RUN: measure the post-action state inside a reverting sub-call.
        (uint256 allowanceAfter, uint256 balanceAfter) = _simulate(module, asset);

        // Reject if the real effect does not match a benign action.
        if (allowanceAfter > allowanceBefore) revert HiddenAllowanceGrant();
        if (balanceAfter < balanceBefore) revert HiddenBalanceOutflow();

        // Phase 2 - COMMIT: the simulation was benign, apply for real.
        (bool ok, ) = module.delegatecall(abi.encodeWithSignature("connect()"));
        require(ok, "SimulatedExecutor: commit failed");
    }

    /// @dev Runs the action in `probe` (which always reverts), decoding the net state it
    ///      measured just before rolling back.
    function _simulate(address module, address asset)
        internal
        returns (uint256 allowanceAfter, uint256 balanceAfter)
    {
        try this.probe(module, asset) {
            revert SimulationUnexpected(); // probe must revert
        } catch (bytes memory data) {
            if (data.length != 64) revert SimulationUnexpected();
            (allowanceAfter, balanceAfter) = abi.decode(data, (uint256, uint256));
        }
    }

    /// @notice Simulation body: performs the action, measures the net state, then reverts
    ///         with the measurement so all state changes (including any hidden grant) are
    ///         rolled back. Only self-callable.
    function probe(address module, address asset) external {
        require(msg.sender == address(this), "SimulatedExecutor: not self");
        (bool ok, ) = module.delegatecall(abi.encodeWithSignature("connect()"));
        require(ok, "SimulatedExecutor: sim call failed");
        uint256 allowanceAfter = IERC20View(asset).allowance(address(this), module);
        uint256 balanceAfter = IERC20View(asset).balanceOf(address(this));
        bytes memory payload = abi.encode(allowanceAfter, balanceAfter);
        assembly {
            revert(add(payload, 0x20), mload(payload))
        }
    }
}
