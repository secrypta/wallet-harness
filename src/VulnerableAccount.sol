// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableAccount - smart-contract wallet with the UNSAFE execution policy.
/// @notice A proxy-style account whose logic pointer lives in slot 0 (`implementation`,
///         the Safe/Gnosis `masterCopy` analogue). `execTransaction` forwards an
///         owner-approved action either as a `call` (operation 0) or a `delegatecall`
///         (operation 1). It does NOT restrict delegatecall targets: a transaction whose
///         `operation` flag is flipped to 1 against an attacker contract runs that contract
///         IN THIS ACCOUNT'S STORAGE, letting it overwrite slot 0 (the logic pointer) and
///         move the account's assets - a whole-account takeover. The `operation` flag is
///         the hidden teeth behind a benign-looking "transfer".
contract VulnerableAccount {
    address public implementation; // slot 0 - the logic/masterCopy pointer
    address public owner; // slot 1

    constructor(address impl, address _owner) {
        implementation = impl;
        owner = _owner;
    }

    /// @param to      target of the action.
    /// @param data    calldata forwarded to `to`.
    /// @param operation 0 = call, 1 = delegatecall. UNCHECKED - this is the vector.
    function execTransaction(address to, bytes calldata data, uint8 operation) external {
        bool ok;
        if (operation == 1) {
            // delegatecall: `to` runs in THIS account's context (storage + assets).
            (ok, ) = to.delegatecall(data);
        } else {
            (ok, ) = to.call(data);
        }
        require(ok, "exec failed");
    }
}
