// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the malicious-calldata vector (independent codebase).
//
// The safety-relevant machinery is UNMODIFIED Solady v0.1.22:
//   source : github.com/Vectorized/solady (tag v0.1.22, commit 65e87c72)
//   license: MIT (see ../../../vendor/solady/LICENSE and ../../../vendor/PROVENANCE.md)
// Solady `Multicallable.multicall` applies `delegatecall` with THIS contract to each payload -
// i.e. it can only invoke this contract's own functions, never a caller-chosen external
// target. As with the OpenZeppelin variant, the Socket-style arbitrary-external-call injection
// has no sink to inject into. Solady is a DIFFERENT, independent implementation the wal
// detectors were never tuned against, so a clean verdict here is a genuine holdout precision
// signal, not "our own safe code passing our own harness".
//
// The only code authored here on top of the unmodified Solady base is this thin router: one
// safe self-operation (`poke`) and NO caller-chosen target/calldata entrypoint.

import {Multicallable} from "../../../vendor/solady-accounts/utils/Multicallable.sol";

/// @title SoladyMulticallableRouter - batches only its OWN operations via Solady Multicallable.
contract SoladyMulticallableRouter is Multicallable {
    uint256 public pokes;

    function poke() external {
        pokes += 1;
    }
}
