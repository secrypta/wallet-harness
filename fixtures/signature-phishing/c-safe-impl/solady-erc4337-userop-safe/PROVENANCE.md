# Fixture provenance

```
Fixture:      signature-phishing/c-safe-impl/solady-erc4337-userop-safe
Vector:       signature-phishing
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady ERC4337 + ERC4337Factory - canonical ERC-4337 smart-account (account
              abstraction) implementation and its minimal-proxy factory.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              files src/accounts/{ERC4337,ERC4337Factory}.sol + import closure -> vendored
              byte-identical at fixtures/vendor/solady-accounts/ (pristine upstream layout, zero
              modifications; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ../SoladyErc4337Fixture.sol (concrete ERC4337 account; overrides ONLY the required
              _domainNameAndVersion - otherwise the stock Solady account, deployed via its
              canonical ERC4337Factory which initializes the owner).

Why holdout: The existing signature-phishing holdouts do a DIRECT on-chain signature check (OZ
             SignatureChecker EOA path, Solady ERC-1271 contract signer, OZ ERC2771 meta-tx). This
             fixture exercises the canonical ERC-4337 ACCOUNT-ABSTRACTION userOp-validation surface
             (ERC4337._validateSignature, which checks the userOp signature against owner() via
             Solady SignatureCheckerLib/ECDSA) - a different real verifier wal was never tuned
             against.

Behavior:    test/RealSafeErc4337UserOpHoldout.t.sol deploys an account for the owner via the
             factory, then presents a userOp whose signature was forged by an attacker key.
             validateUserOp returns 1 (SIG_VALIDATION_FAILED), so the EntryPoint would never run
             its drain calldata; the test does not execute it and the account keeps its funds. A
             guard shows a genuine owner-signed userOp validates (0) and its executed call moves
             funds. The verdict is derived from the real outcome, not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
             Precision-side only (no independent vuln signature-phishing holdout at the bar).
```
