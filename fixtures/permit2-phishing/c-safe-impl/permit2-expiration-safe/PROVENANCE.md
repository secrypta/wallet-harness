# Fixture provenance

```
Fixture:      permit2-phishing/c-safe-impl/permit2-expiration-safe
Vector:       permit2-phishing
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Uniswap Permit2 - the canonical AllowanceTransfer implementation.
Source:       https://github.com/Uniswap/permit2  commit cc56ad0f3439c502c246fc5cfcc3db92bb8b7219
              Compiled VERBATIM from fixtures/vendor/permit2/src/ (exact pragma 0.8.17; its two
              solmate token-plumbing imports repointed to an MIT shim - the safety logic, i.e.
              allowance accounting, signature verification, nonce and EXPIRATION handling, is
              untouched; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022 Uniswap Labs; full text in fixtures/vendor/permit2/LICENSE.
Source code:  reuses scoped-permit2-safe/Permit2SafeToken.sol (a minimal ERC-20 the wallet
              approves to Permit2); the Permit2 contract itself is deployed by artifact via
              forge-std `deployCode` so the test stays in the 0.8.24 compile subgraph.

Distinct property: the existing Permit2 c-safe targets cover lockdown (revoke an already-granted
             allowance), invalidateNonces (pre-empt a phished signature), SignatureTransfer
             (one-time amount-bounded transfer) and a scoped-signature policy. THIS fixture proves
             the EXPIRATION defense: AllowanceTransfer stores a per-allowance `expiration`, and
             `_transfer` reverts `AllowanceExpired(expiration)` once `block.timestamp` passes it.
             Models the canonical safe Permit2 usage - a bounded amount with a short, near-term
             expiration - so even a granted allowance auto-revokes and cannot be drained later.

Behavior:    test/RealSafePermit2Round4.t.sol has the owner sign a BOUNDED (amount = action) permit
             with a short expiration, submits it, and confirms the spender can pull the bounded
             amount before expiry (authority is real). It then warps past the expiration and shows
             (1) a further transferFrom reverts AllowanceExpired, and (2) a full-balance pull is
             impossible (bounded + expired). The verdict is derived from the real outcome, not
             hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
