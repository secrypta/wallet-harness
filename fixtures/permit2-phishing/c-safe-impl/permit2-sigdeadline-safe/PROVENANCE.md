# Fixture provenance

```
Fixture:      permit2-phishing/c-safe-impl/permit2-sigdeadline-safe
Vector:       permit2-phishing
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Uniswap Permit2 - the canonical AllowanceTransfer implementation.
Source:       https://github.com/Uniswap/permit2  commit cc56ad0f3439c502c246fc5cfcc3db92bb8b7219
              Compiled VERBATIM from fixtures/vendor/permit2/src/ (exact pragma 0.8.17; its two
              solmate token-plumbing imports repointed to an MIT shim - the safety logic is
              untouched; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022 Uniswap Labs; full text in fixtures/vendor/permit2/LICENSE.
Source code:  reuses scoped-permit2-safe/Permit2SafeToken.sol; the Permit2 contract is deployed by
              artifact via forge-std `deployCode`.

Distinct property: the existing Permit2 c-safe targets cover allowance expiration, lockdown,
             invalidateNonces, SignatureTransfer and a scoped-signature policy. THIS fixture proves
             the SIGNATURE-DEADLINE defense: `AllowanceTransfer.permit` reverts
             `SignatureExpired(sigDeadline)` when `block.timestamp > permitSingle.sigDeadline`,
             BEFORE any allowance is written. Models a phished (even unbounded) permit signature
             that is submitted after its signature deadline has passed - it is rejected, so no
             allowance is ever set and the drain cannot proceed. Distinct from
             permit2-expiration-safe, which is the per-ALLOWANCE expiration checked at transfer
             time.

Behavior:    test/RealSafePermit2Round5Holdout.t.sol signs an UNBOUNDED phishing PermitSingle whose
             sigDeadline is already in the past, submits it (reverts SignatureExpired), and
             confirms no allowance exists and a full-balance transferFrom reverts. Verdict derived
             from the real outcome, not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
