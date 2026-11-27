// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC7821} from "../../vendor/solady-accounts/accounts/ERC7821.sol";
import {Ownable} from "../../vendor/solady-accounts/auth/Ownable.sol";

/// @title SoladyErc7821Wallet - owner-gated batch-execution account built on the UNMODIFIED
///        Solady `ERC7821` (the EIP-7702 batch-execution interface) + Solady `Ownable`.
///        Real-safe (tier c) vehicle for the eip7702-delegation vector.
/// @notice Under EIP-7702 an EOA delegates to contract code that can execute batched calls on
///         its behalf; the danger is an executor that lets an UNAUTHORIZED party run arbitrary
///         calls (and sweep the account). Solady's `ERC7821` is a batch-executor MIXIN and, by
///         design, leaves authorization to the integrator (its NatSpec: "If `opData` is empty,
///         the implementation SHOULD require that `msg.sender == address(this)`"). The canonical
///         safe usage gates execution behind ownership. Here the batch-decoding/execution is
///         unmodified Solady `ERC7821` and the authorization is unmodified Solady `Ownable`
///         (`onlyOwner` / `_checkOwner`, reverting `Unauthorized()`); both are vendored
///         byte-identical (fixtures/vendor/solady-accounts/, see fixtures/vendor/PROVENANCE.md).
///         The only authored code is the `_execute` override wiring the two together. A
///         non-owner's batch (a malicious 7702 delegate / arbitrary caller) reverts and cannot
///         drain, so the harness must stay silent (BLOCKED).
///
///         Wiring note: Solady `ERC7821`'s default `_execute` auth requires
///         `msg.sender == address(this)` (the pure 7702 self-call pattern) and otherwise expects
///         the integrator to override `_execute` to supply its own authorization. The canonical
///         owner-gated usage - adopted here - overrides `_execute` to require ownership before
///         dispatching to Solady's unmodified batch runner `_execute(calls, bytes32(0))`.
contract SoladyErc7821Wallet is ERC7821, Ownable {
    constructor(address owner_) {
        _initializeOwner(owner_);
    }

    /// @dev Gate the real Solady batch executor behind real Solady ownership. Only the owner
    ///      may execute a batch; every other caller reverts with `Unauthorized()`.
    function _execute(
        bytes32 mode,
        bytes calldata executionData,
        Call[] calldata calls,
        bytes calldata opData
    ) internal override {
        _checkOwner(); // real Solady Ownable: reverts `Unauthorized()` if msg.sender != owner()
        mode = mode; // silence unused-parameter warnings
        executionData = executionData;
        opData = opData;
        _execute(calls, bytes32(0)); // Solady's unmodified batch runner
    }
}
