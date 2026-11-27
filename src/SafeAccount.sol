// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeAccount - smart-contract wallet with the DEFENSIVE execution policy (toy).
/// @notice Same proxy layout as VulnerableAccount (slot 0 = `implementation`), but
///         `execTransaction` enforces the core delegatecall-hijack mitigation: a
///         `delegatecall` (operation 1) is allowed ONLY to an allow-listed, audited
///         library. A delegatecall to any other target reverts, so an attacker contract
///         can never run in this account's storage to swap slot 0 or sweep assets. Plain
///         `call`s (operation 0) are unrestricted, as normal.
contract SafeAccount {
    address public implementation; // slot 0 - logic/masterCopy pointer
    address public owner; // slot 1
    mapping(address => bool) public allowedDelegate; // slot 2 - audited delegate libraries

    error DelegatecallToUntrusted(address target);

    constructor(address impl, address _owner) {
        implementation = impl;
        owner = _owner;
    }

    /// @notice Allow-list an audited delegate library (owner-only in a real wallet;
    ///         kept open here for test setup - the policy under test is the exec guard).
    function allowDelegate(address target, bool ok) external {
        allowedDelegate[target] = ok;
    }

    function execTransaction(address to, bytes calldata data, uint8 operation) external {
        bool ok;
        if (operation == 1) {
            if (!allowedDelegate[to]) revert DelegatecallToUntrusted(to);
            (ok, ) = to.delegatecall(data);
        } else {
            (ok, ) = to.call(data);
        }
        require(ok, "exec failed");
    }
}
