# Fixture provenance

```
Fixture:      permit-phishing/c-safe-impl/solady-permit-nonce-replay-safe
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
              unmodified Solady ERC20; the permit/nonce logic under test is Solady's own).

Distinct property: proves the NONCE / anti-REPLAY property of Solady permit, on the independent
             Solady codebase. `permit` consumes the owner's nonce on first use (nonces[owner]++);
             replaying the identical captured signature recomputes the digest with the new nonce,
             so the recovered signer no longer equals the owner and Solady reverts InvalidPermit.
             Models the "capture the phished permit signature and resubmit it" sub-attack: it can
             work at most once and a replay cannot re-grant allowance. Distinct from
             solady-permit-safe (forged signature) and solady-permit-deadline-safe (expired
             deadline), and from the OZ oz-permit-nonce-replay-safe (independent codebase).

Behavior:    test/RealSafeSoladyPermitRound5Holdout.t.sol signs a bounded permit, submits it once
             (allowance set, nonce bumped 0 -> 1), then REPLAYS the identical signature - real
             Solady reverts. Confirms the replay granted no new allowance and the balance beyond
             the single bounded spend is intact. Verdict derived from the real outcome, not
             hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
