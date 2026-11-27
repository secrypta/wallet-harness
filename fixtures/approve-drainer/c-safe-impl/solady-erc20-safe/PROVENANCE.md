# Fixture provenance

```
Fixture:      approve-drainer/c-safe-impl/solady-erc20-safe
Vector:       approve-drainer
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady ERC20 - an independent, widely-used MIT ERC-20 implementation.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/tokens/ERC20.sol -> vendored byte-identical at
              fixtures/vendor/solady/ERC20.sol (see fixtures/vendor/PROVENANCE.md)
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ../SoladyERC20Fixture.sol (concrete token over the unmodified Solady ERC20;
              adds only name()/symbol() + a test-only mint - no change to allowance logic).

Why holdout: The existing c-safe-impl fixtures use OpenZeppelin and Uniswap Permit2. Solady is
             a DIFFERENT, independent codebase that wal was never written or tuned against, so a
             clean verdict here is an honest precision signal on unseen safe code - not "our own
             safe code passing our own harness".

Behavior:    test/RealSafeSoladyHoldout.t.sol grants a BOUNDED allowance (10e18), confirms the
             spender can move exactly that much, then attempts to pull the full remaining
             balance. Solady's allowance accounting reverts the over-draw. The verdict is
             derived from the real outcome (balance stays intact), not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
