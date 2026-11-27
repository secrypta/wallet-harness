// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AssemblyDelegateSafeAccount - the SAFE control for the assembly delegatecall path.
/// @notice Same inline-assembly `delegatecall(gas(), delegate, ...)` as {AssemblyDelegateAccount},
///         but the entry point is caller-gated (`onlyOwner`). This mirrors the real safe primitive
///         Solady `ERC4337.delegateExecute(..)` guards with `onlyEntryPointOrOwner`: a delegate-
///         execute that only the account's own owner/entry-point can invoke is a trusted-owner
///         account-abstraction feature, not an open hijack. The harness MUST stay SILENT here
///         (0 false positives), exactly as it does on the real vendored Solady/ERC-4337 accounts
///         and the OpenZeppelin `Proxy._delegate` (getter-bound target) in the safe corpus.
///
/// Provenance: authored minimized toy (this repo, MIT); models the caller-gated assembly delegate-
///         execute that the real ERC-4337 account corpus uses. No third-party code copied.
contract AssemblyDelegateSafeAccount {
    address public implementation; // slot 0
    address public owner; // slot 1

    constructor(address impl, address _owner) {
        implementation = impl;
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// @notice Caller-gated delegate-execute: only the owner can direct the delegatecall, so the
    ///         target is not attacker-settable from an arbitrary caller.
    function delegateExecute(address delegate, bytes calldata data)
        external
        onlyOwner
        returns (bytes memory out)
    {
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, data.offset, data.length)
            let ok := delegatecall(gas(), delegate, ptr, data.length, 0, 0)
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
