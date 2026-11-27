// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AuditedLibModule - a benign, allow-listed delegate library (guard fixture).
/// @notice Stands in for an audited library a wallet legitimately delegatecalls (e.g. a
///         batching/multicall helper). Its `ping()` performs no asset or slot-0 effect, so
///         it is safe to run in the wallet's context. Used to prove the SafeAccount /
///         GuardedExecutor delegatecall allow-list is not vacuous: an allow-listed delegate
///         still executes.
contract AuditedLibModule {
    event Pinged(address account);

    function ping() external {
        emit Pinged(address(this)); // address(this) == the delegatecalling wallet
    }
}
