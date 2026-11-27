// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./guarded-exec-safe/PROVENANCE.md for the full block)
//   Vector:  delegatecall-hijack   Tier: c-safe-impl   Expected: BLOCKED
//   Nature:  REFERENCE-IMPL of the canonical post-Bybit mitigation - a Safe-style
//            transaction guard + implementation-slot invariant. NOT a vendored
//            third-party library (delegatecall-hijack has no single canonical lib
//            to vendor) and NOT a lightly-edited toy: it implements the documented
//            defense (allow-list delegatecall targets; assert the logic pointer is
//            unchanged after every user transaction). Honestly marked reference-impl.
//   Sources: Safe transaction-guard pattern; post-Bybit guidance (CertiK/SlowMist/
//            NCC Group). License: MIT (this repo).
// -----------------------------------------------------------------------------

/// @title GuardedExecutor - reference-impl of the canonical delegatecall-hijack defense.
/// @notice Two independent, defense-in-depth checks the real mitigation prescribes:
///         (1) a transaction GUARD that permits `delegatecall` (operation 1) only to an
///             allow-listed, audited library - an unknown target reverts before it can run;
///         (2) an implementation-slot INVARIANT - slot 0 (the logic/masterCopy pointer) is
///             snapshotted before execution and asserted unchanged after; any write to it
///             (even via a mistakenly allow-listed or storage-colliding delegate) reverts
///             the whole transaction, rolling back the hijack.
///         A genuine attacker delegatecall (unknown target) is stopped by (1); were it ever
///         reached, (2) still catches the slot-0 takeover. Plain calls are unrestricted and
///         an allow-listed benign delegate still runs - so BLOCKED is never vacuous.
contract GuardedExecutor {
    address public implementation; // slot 0 - logic/masterCopy pointer (invariant target)
    address public owner; // slot 1
    mapping(address => bool) public allowedDelegate; // slot 2

    error DelegatecallToUntrusted(address target);
    error ImplementationSlotChanged(address before, address nowValue);

    constructor(address impl, address _owner) {
        implementation = impl;
        owner = _owner;
    }

    function allowDelegate(address target, bool ok) external {
        allowedDelegate[target] = ok;
    }

    function execTransaction(address to, bytes calldata data, uint8 operation) external {
        address implBefore = implementation; // slot-0 snapshot (pre-check)

        bool ok;
        if (operation == 1) {
            if (!allowedDelegate[to]) revert DelegatecallToUntrusted(to); // guard
            (ok, ) = to.delegatecall(data);
        } else {
            (ok, ) = to.call(data);
        }
        require(ok, "exec failed");

        // Invariant: a normal user transaction must never move the logic pointer.
        if (implementation != implBefore) {
            revert ImplementationSlotChanged(implBefore, implementation);
        }
    }
}
