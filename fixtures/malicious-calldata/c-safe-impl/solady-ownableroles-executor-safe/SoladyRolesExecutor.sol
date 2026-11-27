// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the malicious-calldata vector.
//
// The safety-relevant machinery is UNMODIFIED Solady v0.1.22:
//   source : github.com/Vectorized/solady (tag v0.1.22, commit 65e87c72)
//   license: MIT (see ../../../vendor/solady/LICENSE and ../../../vendor/PROVENANCE.md)
//
// Solady `OwnableRoles` is a canonical owner + bitmap-roles authorization mixin. This executor
// exposes `execute(target, value, data)` - a genuine arbitrary-external-call sink, exactly the
// shape the malicious-calldata vector abuses (Socket 2024: a caller supplies the target +
// calldata and the contract runs it against a victim's standing approval). It is safe because
// the sink is gated by `onlyOwnerOrRoles(EXECUTOR_ROLE)`: only the owner or an explicitly
// role-granted operator may reach it, so an unauthorized attacker cannot inject a
// `transferFrom(victim, attacker, ...)` against an approval the victim granted this executor.
//
// Distinct from the other malicious-calldata safe fixtures (self-only multicalls, and the OZ
// TimelockController role+delay executor): here the gate is Solady's owner/role authorization
// (no delay, no self-only restriction) - a different real primitive and mechanism.
//
// NOTE (per the wal methodology): this is a genuine gated arbitrary-call executor. If a future
// static malicious-calldata detector flags it as VULNERABLE, that is a real detector false
// positive on legitimate role-gated execution - to be recorded as a finding, NOT masked by
// altering this fixture. The only authored code is this thin executor over Solady OwnableRoles.

import {OwnableRoles} from "../../../vendor/solady-accounts/auth/OwnableRoles.sol";

/// @title SoladyRolesExecutor - an arbitrary-call executor gated by Solady OwnableRoles.
contract SoladyRolesExecutor is OwnableRoles {
    /// @dev Role bit required to reach the execution sink.
    uint256 public constant EXECUTOR_ROLE = 1 << 0;

    uint256 public execs; // count of successful executions (benign self-metric)

    constructor(address owner_) {
        _initializeOwner(owner_);
    }

    /// @notice Arbitrary external call, gated by owner-or-role. An unauthorized caller cannot
    ///         inject calldata against a standing approval; the sink is unreachable to them.
    function execute(address target, uint256 value, bytes calldata data)
        external
        onlyOwnerOrRoles(EXECUTOR_ROLE)
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        execs += 1;
        return ret;
    }
}
