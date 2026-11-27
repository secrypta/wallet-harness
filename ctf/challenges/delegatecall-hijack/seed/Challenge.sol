// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - a smart wallet that executes owner-approved operations.
/// @notice This is the VULNERABLE version. Your job is to fix `execute` so the
///         delegatecall-hijack vector no longer works, WITHOUT breaking the legitimate flow.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this
///         name and arguments. You may change only the body.
///
/// The intended use: the wallet runs operations. `operation = 0` is a plain CALL;
/// `operation = 1` is a DELEGATECALL, which is only meant for the one audited batch library
/// (`trustedLib`, set at deploy). The bug below is that a DELEGATECALL is run against ANY
/// target the caller names, so attacker code executes in THIS wallet's storage context and
/// can move the wallet's assets (or overwrite its implementation/owner slot) - the classic
/// delegatecall-hijack.
contract Challenge {
    uint8 internal constant CALL = 0;
    uint8 internal constant DELEGATECALL = 1;

    /// @notice The one audited library this wallet is allowed to delegatecall into. Immutable.
    address public immutable trustedLib;

    constructor(address trustedLib_) {
        trustedLib = trustedLib_;
    }

    function execute(address target, bytes calldata data, uint8 operation)
        external
        returns (bytes memory)
    {
        // BUG: any target may be delegatecalled. A hostile library then runs as this wallet.
        bool ok;
        bytes memory ret;
        if (operation == DELEGATECALL) {
            (ok, ret) = target.delegatecall(data);
        } else {
            (ok, ret) = target.call(data);
        }
        require(ok, "execute: inner call failed");
        return ret;
    }
}
