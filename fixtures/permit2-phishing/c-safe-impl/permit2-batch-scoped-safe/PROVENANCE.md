# Fixture provenance

```
Fixture:      permit2-phishing/c-safe-impl/permit2-batch-scoped-safe
Vector:       permit2-phishing
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Uniswap Permit2 - the canonical AllowanceTransfer implementation (PermitBatch path).
Source:       https://github.com/Uniswap/permit2  commit cc56ad0f3439c502c246fc5cfcc3db92bb8b7219
              Compiled VERBATIM from fixtures/vendor/permit2/src/ (exact pragma 0.8.17; its two
              solmate token-plumbing imports repointed to an MIT shim - the safety logic is
              untouched; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022 Uniswap Labs; full text in fixtures/vendor/permit2/LICENSE.
Source code:  reuses scoped-permit2-safe/Permit2SafeToken.sol (two instances); the Permit2 contract
              is deployed by artifact via forge-std `deployCode`.

Distinct property: proves the PermitBatch (multi-token) path of real Permit2 is still amount-bound.
             A single signature authorizes bounded amounts across TWO tokens at once; the spender
             can pull up to each bounded amount, but a full-balance transferFrom on either token
             reverts InsufficientAllowance. Models the canonical safe multi-token Permit2 usage
             (bounded per-token amounts), as opposed to a phished UNBOUNDED batch. Distinct from
             the single-permit fixtures (expiration, sigdeadline, lockdown, invalidateNonces,
             sigtransfer, scoped).

Behavior:    test/RealSafePermit2Round5Holdout.t.sol signs a PermitBatch granting bounded amounts
             over two tokens, submits it, confirms each bounded spend works, then shows a
             full-balance pull on each token reverts. Verdict derived from the real outcome, not
             hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
