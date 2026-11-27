// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the delegatecall-hijack vector.
/// @notice A DELEGATECALL runs the target's code in THIS wallet's storage context, so the
///         target must be trusted absolutely. Restrict delegatecall to the one audited,
///         allow-listed library (`trustedLib`); any other delegatecall target is rejected.
///         Plain CALLs keep working, and the legitimate batch library still runs - only the
///         hijack path (delegatecall to an attacker contract) is closed.
contract Challenge {
    uint8 internal constant CALL = 0;
    uint8 internal constant DELEGATECALL = 1;

    address public immutable trustedLib;

    constructor(address trustedLib_) {
        trustedLib = trustedLib_;
    }

    function execute(address target, bytes calldata data, uint8 operation)
        external
        returns (bytes memory)
    {
        bool ok;
        bytes memory ret;
        if (operation == DELEGATECALL) {
            // FIX: only the audited, allow-listed library may run in this wallet's context.
            require(target == trustedLib, "delegatecall: target not allow-listed");
            (ok, ret) = target.delegatecall(data);
        } else {
            (ok, ret) = target.call(data);
        }
        require(ok, "execute: inner call failed");
        return ret;
    }
}
