# Fixture provenance

```
Fixture:      permit2-phishing/c-safe-impl/permit2-sigtransfer-safe
Vector:       permit2-phishing
Tier:         c-safe-impl
Split:        holdout
Expected:     safe                     # ground-truth label (matches meta `label`)

Nature:       PRECISION-SIDE safe holdout. No clean, independently-documented Permit2 *incident*
              reproducible at code level beyond the dev PEPE case was found at our provenance bar
              (two extended web passes; outlets conflate ERC-2612 permit vs Uniswap Permit2 and
              give conflicting figures). Permit2 is a Uniswap singleton - there is no "second
              canonical" implementation - so this vector's independent holdout exercises a
              DIFFERENT, previously-unexercised SAFE surface of the same real canonical contract.

Origin:       The canonical SAFE counterpart via Permit2's SignatureTransfer path
              (permitTransferFrom): a one-time, amount-bounded, deadline-scoped signature. The
              owner signs a PermitTransferFrom authorizing a specific spender to pull at most a
              bounded amount, once (unordered nonce). An over-draw reverts (InvalidAmount); a
              replay reverts (InvalidNonce); an expired permit reverts (SignatureExpired). This
              is unmodified Uniswap Permit2 logic.

Upstream:     - Uniswap Permit2: github.com/Uniswap/permit2,
                commit cc56ad0f3439c502c246fc5cfcc3db92bb8b7219, SPDX MIT.
                Core vendored byte-for-byte (SignatureTransfer.sol, PermitHash.sol,
                SignatureVerification.sol, EIP712.sol, ...); the ONLY deviation is two solmate
                import lines repointed to an MIT shim (see fixtures/vendor/PROVENANCE.md).

Independence: The dev scoped-permit2-safe fixture exercises the AllowanceTransfer path
              (permit + transferFrom, standing allowance). THIS holdout exercises the
              SignatureTransfer path (permitTransferFrom, one-shot signed transfer) - a distinct
              code path and safe mechanism (unordered nonce, per-signature amount) the detectors
              were not tuned against. Same vendored repo, different surface (disclosed).

Source code:  test/RealSafePermit2SigTransferHoldout.t.sol deploys the real Permit2 by artifact
              (deployCode, compiled at its exact pragma 0.8.17 via src/Permit2CompileAnchor.sol)
              and reuses the MIT vehicle
              fixtures/permit2-phishing/c-safe-impl/scoped-permit2-safe/Permit2SafeToken.sol
              (a plain ERC-20 at pragma >=0.8.0 sharing Permit2's 0.8.17 subgraph).
License:      MIT (this repo) + MIT (Uniswap Permit2).
Offline:      committed source only; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        The test shows a bounded permitTransferFrom genuinely transfers the signed amount
              (authority is real -> BLOCKED not vacuous), then shows an over-draw reverts
              (InvalidAmount) and a replay of the consumed nonce reverts - transferring nothing
              extra. Verdict derived from outcome (no over-draw). Expected: BLOCKED (TN). A false
              VULNERABLE here would be a real detector false positive and is reported, not
              suppressed.
```
