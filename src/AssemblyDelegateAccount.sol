// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AssemblyDelegateAccount - delegatecall-hijack in the INLINE-ASSEMBLY (Yul) form.
/// @notice Same vector as {VulnerableAccount}, but the delegatecall is emitted as a Yul
///         `delegatecall(gas(), to, ...)` inside an `assembly { }` block - the form every real
///         proxy / Safe{Wallet} `execute` / ERC-4337 account / Furucombo `Proxy._exec` actually
///         uses (the Solidity high-level `to.delegatecall(data)` almost never appears in deployed
///         router/account code). `execute` forwards an UNCHECKED, caller-supplied `to` as a
///         delegatecall, so a phished/hostile `to` runs in this account's own storage + asset
///         context and sweeps it - a whole-account takeover.
///
/// Provenance: authored minimized toy (this repo, MIT). It models the assembly delegatecall
///         mechanism common to the delegatecall-hijack incident class (Furucombo $14M proxy
///         `_exec`, Safe{Wallet} `execute`); no third-party code copied. Added to exercise the
///         committed gate against the REAL assembly form, not only the high-level form.
contract AssemblyDelegateAccount {
    address public implementation; // slot 0 - logic pointer, overwritable by a hostile delegate
    address public owner; // slot 1

    constructor(address impl, address _owner) {
        implementation = impl;
        owner = _owner;
    }

    /// @param to    UNVALIDATED caller-supplied delegate target - this is the vector.
    /// @param data  calldata run in this account's context.
    function execute(address to, bytes calldata data) external returns (bytes memory out) {
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, data.offset, data.length)
            // delegatecall to an attacker-settable `to`: no allow-list, no guard.
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
