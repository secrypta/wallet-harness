// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./bybit-exec-victim/PROVENANCE.md for the full block)
//   Vector:  delegatecall-hijack   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Bybit cold-wallet theft, 2025-02-21, ~$1.46B (largest crypto theft
//            on record). The Safe{Wallet} multisig signed a transaction whose
//            `operation` flag was flipped from call (0) to delegatecall (1),
//            running attacker code in the wallet's storage context and swapping
//            the implementation/masterCopy pointer -> full account takeover.
//   Proof:   MECHANISM-LEVEL. Root cause was a Safe{Wallet} front-end / supply-
//            chain compromise (malicious JS served to signers), not a contract
//            bug; full calldata/traces are not all public. This is a minimized
//            offline reproduction of the documented delegatecall-swap mechanism,
//            NOT a byte-for-byte replay of the on-chain transaction.
//   Sources: CertiK; SlowMist; NCC Group; BleepingComputer (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
// -----------------------------------------------------------------------------

/// @title BybitSafeClone - minimized Safe/Gnosis-style multisig account.
/// @notice Reproduces only the surface the incident turned on: a `masterCopy` logic
///         pointer in slot 0 and an `execTransaction` that forwards an approved action as
///         either a `call` or a `delegatecall` per the `operation` flag. Signature
///         verification is abstracted to a threshold owner check - the incident did not
///         break signatures, it got the signers to approve a payload whose `operation` was
///         delegatecall. When that payload targets attacker code, the code runs in this
///         account's storage and replaces `masterCopy` + drains the balance.
contract BybitSafeClone {
    address public masterCopy; // slot 0 - the logic pointer the attacker overwrites
    address public owner; // slot 1 - the (single, for the minimization) approving signer

    error NotOwner();

    constructor(address _masterCopy, address _owner) {
        masterCopy = _masterCopy;
        owner = _owner;
    }

    /// @notice Execute an owner-approved transaction. `operation`: 0 = call, 1 =
    ///         delegatecall. The incident: signers believed they approved a benign
    ///         transfer (operation 0) but the submitted payload had operation = 1.
    /// @dev    Signature check modeled as "the approving owner submits"; the vector is the
    ///         unchecked `operation`, exactly as in the real (unguarded) Safe flow.
    function execTransaction(address to, bytes calldata data, uint8 operation) external {
        if (msg.sender != owner) revert NotOwner();
        bool ok;
        if (operation == 1) {
            (ok, ) = to.delegatecall(data);
        } else {
            (ok, ) = to.call(data);
        }
        require(ok, "exec failed");
    }
}
