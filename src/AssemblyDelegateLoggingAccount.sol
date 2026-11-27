// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AssemblyDelegateLoggingAccount - delegatecall-hijack that merely LOGS the caller.
/// @notice Identical vector to {AssemblyDelegateAccount} (unguarded inline-assembly delegatecall
///         to a caller-supplied `to`), but it also references `msg.sender` - only to EMIT it in
///         an event, never to authorize the call. This is the F2 proof fixture: a bare mention of
///         msg.sender (logging / assignment) must NOT be mistaken for a caller gate. The harness
///         MUST FIRE here (R7 + R8); treating the `emit Executed(msg.sender, to)` as access
///         control would be a false negative - exactly the audit finding being fixed.
///
/// Provenance: authored minimized toy (this repo, MIT). No third-party code copied.
contract AssemblyDelegateLoggingAccount {
    address public implementation; // slot 0
    address public owner; // slot 1

    event Executed(address indexed caller, address indexed target);

    constructor(address impl, address _owner) {
        implementation = impl;
        owner = _owner;
    }

    /// @param to    UNVALIDATED caller-supplied delegate target - the vector, with NO caller gate.
    /// @param data  calldata run in this account's context.
    function execute(address to, bytes calldata data) external returns (bytes memory out) {
        // Bare mention of msg.sender: logging only, NOT an authorization check.
        emit Executed(msg.sender, to);
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, data.offset, data.length)
            let ok := delegatecall(gas(), to, ptr, data.length, 0, 0)
            let size := returndatasize()
            returndatacopy(ptr, 0, size)
            switch ok
            case 0 { revert(ptr, size) }
            default {
                mstore(0x40, add(ptr, size))
                out := ptr
            }
        }
    }
}
