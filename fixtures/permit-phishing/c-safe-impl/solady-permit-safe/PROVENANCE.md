# Fixture provenance

```
Fixture:      permit-phishing/c-safe-impl/solady-permit-safe
Vector:       permit-phishing
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady ERC20 EIP-2612 `permit` - an independent, widely-used MIT implementation.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/tokens/ERC20.sol -> vendored byte-identical at
              fixtures/vendor/solady/ERC20.sol (see fixtures/vendor/PROVENANCE.md)
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ../SoladyERC20Fixture.sol (concrete token over the unmodified Solady ERC20).

Why holdout: The existing permit c-safe-impl fixture uses OpenZeppelin ERC20Permit. Solady's
             permit is a DIFFERENT, independent implementation wal was never tuned against.
Paired with: the lixir-permit-victim vuln holdout, which replays a BROKEN permit (accepted any
             dummy signature whose ecrecover was nonzero). This fixture shows a CORRECT permit
             rejecting that exact forgery - the recall/precision contrast on the permit check.

Behavior:    test/RealSafeSoladyHoldout.t.sol submits a FORGED permit (a dummy v/r/s, non-expired
             deadline) attempting to grant the attacker a full allowance. Solady's `permit`
             requires the recovered signer to equal the owner, so it reverts (InvalidPermit); no
             allowance is granted and the subsequent transferFrom cannot drain. The verdict is
             derived from the real outcome (no allowance, balance intact), not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
