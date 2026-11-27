// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the malicious-calldata vector.
//
// The safety-relevant machinery is UNMODIFIED OpenZeppelin v5.1.0:
//   source : github.com/OpenZeppelin/openzeppelin-contracts (tag v5.1.0, commit 69c8def5)
//   license: MIT (see ../../../vendor/oz/LICENSE and ../../../vendor/PROVENANCE.md)
// OpenZeppelin `Multicall.multicall` batches calls by `Address.functionDelegateCall` to
// `address(this)` ONLY - it can invoke this contract's own functions, never a caller-chosen
// external target. The Socket-style arbitrary-external-call injection (caller supplies both
// the call TARGET and the CALLDATA, and the contract runs it against a victim's standing
// approval) is therefore structurally impossible: there is no external-call sink to inject.
//
// The only code authored here on top of the unmodified OZ base is this thin router: one safe
// self-operation (`poke`) to prove the batch path works (so BLOCKED is not vacuous), and NO
// entrypoint that forwards a caller-chosen target/calldata. It changes none of OZ's logic.

import {Multicall} from "../../../vendor/oz/utils/Multicall.sol";

/// @title OZMulticallRouter - a router that batches only its OWN operations via OZ Multicall.
/// @notice There is deliberately no `performAction(target, data)` / arbitrary-call entrypoint.
///         Anything routed through `multicall` self-delegatecalls this contract, so an injected
///         `transferFrom(victim, attacker, ...)` cannot reach an external token - the standing
///         approval a user grants this router is not spendable by caller-supplied calldata.
contract OZMulticallRouter is Multicall {
    uint256 public pokes; // a benign self-operation the user legitimately batches

    /// @notice The only state-changing operation reachable through `multicall` on this router.
    function poke() external {
        pokes += 1;
    }
}
