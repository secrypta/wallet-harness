# Fixture provenance

```
Fixture:      permit-phishing/c-safe-impl/solady-permit-bounded-safe
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
Source code:  reuses approve-drainer/c-safe-impl/SoladyERC20Fixture.sol (concrete token over the
              unmodified Solady ERC20; the permit/allowance logic under test is Solady's own).

Distinct property: proves the BOUNDED-VALUE property of Solady permit on the independent Solady
             codebase. A permit signed for exactly the action amount grants precisely that
             allowance; the spender can use it for the action but a full-balance transferFrom
             reverts (InsufficientAllowance). This is the analogue of oz-permit-safe (OZ
             bounded-value) proven on Solady, and is distinct from solady-permit-safe (forged
             signature), solady-permit-deadline-safe (expired deadline) and
             solady-permit-nonce-replay-safe (nonce/replay).

Behavior:    test/RealSafeSoladyPermitRound5Holdout.t.sol signs a bounded permit (value = action
             amount), submits it, confirms the bounded spend works, then shows a full-balance
             transferFrom reverts and the balance is intact. Verdict derived from the real outcome,
             not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
