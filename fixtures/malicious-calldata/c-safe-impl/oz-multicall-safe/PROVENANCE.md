# Fixture provenance

```
Fixture:      malicious-calldata/c-safe-impl/oz-multicall-safe
Vector:       malicious-calldata
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin Contracts `utils/Multicall.sol` - a widely-used MIT batch-call
              mixin. `multicall(bytes[])` runs each payload via
              `Address.functionDelegateCall(address(this), ...)`, i.e. a self-delegatecall:
              it can only invoke THIS contract's own functions, never a caller-chosen external
              target. The malicious-calldata / arbitrary-external-call-injection vector (Socket
              2024: caller supplies the call target + calldata and the contract runs it against
              a user's standing approval) has no sink here - there is no external-call entrypoint.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              file utils/Multicall.sol -> vendored byte-identical at
              fixtures/vendor/oz/utils/Multicall.sol (see fixtures/vendor/PROVENANCE.md)
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in
              fixtures/vendor/oz/LICENSE.
Source code:  ./OZMulticallRouter.sol (concrete router over the unmodified OZ Multicall; adds
              only a benign self-op `poke` and NO caller-chosen target/calldata entrypoint -
              changes none of OZ's batch logic).

Why holdout: real OpenZeppelin library code exercised as an independent precision check: the
             harness must stay silent (BLOCKED) on a canonical self-only multicall. A VULNERABLE
             here would be a real false positive and recorded as such, not suppressed.

Behavior:    test/RealSafeMaliciousCalldata.t.sol - a victim grants the router a standing
             (unlimited) approval; a legitimate self-op (`poke`) via `multicall` succeeds
             (non-vacuous); an injected `transferFrom(victim, attacker, ...)` routed through
             `multicall` cannot reach the external token (self-delegatecall only), so the
             approval is never spent. The verdict is derived from the real outcome (victim
             balance intact), not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.
Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN).
```
