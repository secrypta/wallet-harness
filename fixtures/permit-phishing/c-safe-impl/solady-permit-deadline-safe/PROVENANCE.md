# Fixture provenance

```
Fixture:      permit-phishing/c-safe-impl/solady-permit-deadline-safe
Vector:       permit-phishing
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady ERC20 - an independent, widely-used MIT EIP-2612 implementation.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/tokens/ERC20.sol -> vendored byte-identical at fixtures/vendor/solady/ERC20.sol
              (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  reuses approve-drainer/c-safe-impl/SoladyERC20Fixture.sol (a concrete token over the
              UNMODIFIED Solady ERC20; the permit/deadline logic under test is Solady's own).

Distinct property: solady-permit-safe proves the SIGNATURE property (a forged permit is rejected).
             THIS fixture proves the DEADLINE property on the same independent codebase: Solady
             `permit` checks the deadline first and reverts `PermitExpired()` before any
             allowance is set. Proving the deadline defense on a SECOND, independent impl (Solady,
             not OZ) is a genuine precision check, not padding of a single codebase.

Behavior:    test/RealSafePermitRound4.t.sol signs a FULL-balance permit with a deadline already
             in the past and submits it - real Solady code reverts PermitExpired. Confirms the
             allowance stays 0 and a drain reverts. The verdict is derived from the real outcome,
             not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
