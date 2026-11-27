// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the malicious-calldata vector.
//
// The safety-relevant machinery is UNMODIFIED OpenZeppelin v5.1.0:
//   source : github.com/OpenZeppelin/openzeppelin-contracts (tag v5.1.0, commit 69c8def5)
//   license: MIT (see ../../../vendor/oz/LICENSE and ../../../vendor/PROVENANCE.md)
//
// OZ `TimelockController` is a canonical, widely-deployed arbitrary-call executor: its
// `execute(target, value, payload, predecessor, salt)` performs a low-level call to any
// `target` with any `payload`. That is exactly the arbitrary-external-call shape the
// malicious-calldata vector abuses (Socket 2024: a caller supplies the target + calldata and
// the contract runs it against a victim's standing approval). TimelockController is safe NOT
// because the sink is absent, but because reaching it is gated:
//   * `schedule(...)` requires `PROPOSER_ROLE`;
//   * `execute(...)` requires `EXECUTOR_ROLE` AND the operation to have been scheduled and the
//     min-delay to have elapsed (`_beforeCall` reverts otherwise).
// So an attacker who holds neither role cannot inject `transferFrom(victim, attacker, ...)`:
// `execute` of an unscheduled call reverts, and `schedule` reverts for lack of PROPOSER_ROLE.
//
// This file authors NO logic - it only re-exports the unmodified OZ `TimelockController` so
// the fixture has a local subject symbol. The test drives the real contract directly.
//
// Distinct from `upgrade-governance/c-safe-impl/oz-timelock-safe`: there the subject is a UUPS
// wallet whose UPGRADE authority happens to be a timelock (the upgrade-governance vector);
// here the TimelockController ITSELF is the executor that holds a victim's standing approval,
// and the vector is arbitrary-external-call injection against that approval.

import {TimelockController} from "../../../vendor/oz/governance/TimelockController.sol";

// Re-export marker: the subject is OZ's unmodified TimelockController (imported above).
