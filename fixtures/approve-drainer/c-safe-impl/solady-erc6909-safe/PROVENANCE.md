# Fixture provenance

```
Fixture:      approve-drainer/c-safe-impl/solady-erc6909-safe
Vector:       approve-drainer
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl + distinct allowance model
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady ERC6909 - an independent, widely-used MIT EIP-6909 multi-token implementation.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/tokens/ERC6909.sol -> vendored byte-identical at
              fixtures/vendor/solady/ERC6909.sol
              sha256 95a71e603f48e503a9d2c386de4c2760d8f15830b08a1461c7caaa47481c34db
              (self-contained, no imports; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  SoladyERC6909Fixture.sol - adds only the required metadata overrides
              (name/symbol/tokenURI) + a test-only mint over the unmodified Solady ERC6909. No
              change to the per-id allowance accounting under test.

Why holdout / distinct: EIP-6909 is a DIFFERENT allowance model from the ERC-20 fixtures - a
             per-token-id allowance plus an operator flag - and Solady's ERC6909 is an independent
             codebase the wal detectors were never tuned against. A clean verdict is a genuine
             precision signal on an unseen safe surface.

Behavior:    test/RealSafeSoladyApproveRound5Holdout.t.sol mints a holder a balance of one token id,
             grants a spender a BOUNDED per-id allowance (10 units), confirms the spender can move
             exactly that many via transferFrom, then attempts to pull the full remaining id
             balance - Solady ERC6909 reverts InsufficientPermission (allowance is not max and the
             amount exceeds it). The verdict is derived from the real outcome, not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
