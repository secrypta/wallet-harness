# Fixture provenance

```
Fixture:      approve-drainer/c-safe-impl/solady-erc4626-safe
Vector:       approve-drainer
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady ERC4626 - an independent, widely-used MIT tokenized-vault implementation.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/tokens/ERC4626.sol -> vendored byte-identical at
              fixtures/vendor/solady-accounts/tokens/ERC4626.sol (see fixtures/vendor/PROVENANCE.md).
              Underlying asset is the unmodified Solady ERC20 (fixtures/vendor/solady/ERC20.sol).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  SoladyVaultFixture.sol - adds only asset()/name()/symbol() over the unmodified Solady
              ERC4626. No change to the share-allowance accounting under test.

Why holdout / distinct: the existing approve-drainer ERC-4626 fixture (oz-erc4626-safe) is
             OpenZeppelin. Solady ERC4626 is a DIFFERENT, independent codebase the wal detectors
             were never tuned against, so a clean verdict is an honest precision signal, not "our
             own safe code passing our own harness".

Behavior:    test/RealSafeSoladyApproveRound5Holdout.t.sol deposits assets to mint vault SHARES to
             a holder, grants a spender a BOUNDED share allowance (10 shares), confirms the spender
             can move exactly that many shares, then attempts to pull the full remaining share
             balance - Solady's ERC-20 allowance accounting (inherited by the ERC4626 share token)
             reverts the over-draw. The verdict is derived from the real outcome (shares intact),
             not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
