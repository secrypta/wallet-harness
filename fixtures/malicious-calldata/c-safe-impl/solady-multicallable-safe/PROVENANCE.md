# Fixture provenance

```
Fixture:      malicious-calldata/c-safe-impl/solady-multicallable-safe
Vector:       malicious-calldata
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady `utils/Multicallable.sol` - a widely-used MIT batch-call mixin, an
              independent codebase (not OpenZeppelin). `multicall(bytes[])` applies
              `delegatecall` with THIS contract to each payload, so it can only invoke this
              contract's own functions, never a caller-chosen external target. The
              arbitrary-external-call-injection vector (Socket 2024) has no sink here.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/utils/Multicallable.sol -> vendored byte-identical at
              fixtures/vendor/solady-accounts/utils/Multicallable.sol (see fixtures/vendor/PROVENANCE.md)
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ./SoladyMulticallableRouter.sol (concrete router over the unmodified Solady
              Multicallable; adds only a benign self-op `poke` - changes none of Solady's logic).

Why holdout: Solady is a DIFFERENT, independent implementation the wal detectors were never
             tuned against, so a clean verdict here is a genuine precision signal on unseen safe
             code - not "our own safe code passing our own harness".

Behavior:    test/RealSafeMaliciousCalldata.t.sol - a victim grants the router a standing
             approval; a legitimate self-op (`poke`) via `multicall` succeeds (non-vacuous); an
             injected `transferFrom(victim, attacker, ...)` routed through `multicall` cannot
             reach the external token (self-delegatecall only), so the approval is never spent.
             The verdict is derived from the real outcome (victim balance intact), not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.
Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN).
```
