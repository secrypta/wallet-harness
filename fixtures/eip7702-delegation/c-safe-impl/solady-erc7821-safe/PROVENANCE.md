# Fixture provenance

```
Fixture:      eip7702-delegation/c-safe-impl/solady-erc7821-safe
Vector:       eip7702-delegation
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady `accounts/ERC7821` - the EIP-7702 batch-execution interface a delegated EOA
              exposes - gated by Solady `auth/Ownable`. ERC7821 is a batch-executor MIXIN that by
              design leaves authorization to the integrator (its NatSpec: "If `opData` is empty,
              the implementation SHOULD require that `msg.sender == address(this)`"); the
              canonical safe usage gates execution behind ownership.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              files accounts/ERC7821.sol, accounts/Receiver.sol, auth/Ownable.sol
              -> vendored byte-identical at fixtures/vendor/solady-accounts/ (upstream layout,
                 ZERO modifications; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text fixtures/vendor/solady-accounts/LICENSE.
Source code:  ../SoladyErc7821Wallet.sol (authored thin wallet: the ONLY authored line is the
              `execute` override wiring Solady `Ownable.onlyOwner` in front of Solady
              `ERC7821.execute`). The batch-decoding/execution and the ownership check are both
              unmodified Solady.

Why holdout: distinct from allowlisted-deleg-safe (authored policy). This exercises REAL audited
             account code (Solady ERC7821 + Ownable) wal was never tuned against - a genuine
             precision signal on the exact surface an EIP-7702 delegate presents.

Behavior:    test/RealSafeSoladyErc7821Holdout.t.sol funds the account, then a non-owner attacker
             (a malicious delegate / arbitrary caller) submits a batch that would sweep the whole
             ETH balance to themselves. Solady `onlyOwner` reverts with `Unauthorized()`, so
             nothing leaves. A guard proves the OWNER can execute a batch, so BLOCKED is a real
             authorization rejection, not a broken executor. Verdict derived from the real outcome.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.
Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and recorded as such, not suppressed. Note (scope):
             the bare ERC7821 mixin WITHOUT an auth gate is intentionally unsafe (that is the
             vulnerable shape); this fixture is the canonical owner-gated safe usage.
```
