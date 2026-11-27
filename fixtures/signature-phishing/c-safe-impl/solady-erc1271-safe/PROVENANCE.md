# Fixture provenance

```
Fixture:      signature-phishing/c-safe-impl/solady-erc1271-safe
Vector:       signature-phishing
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady ERC1271 (ERC-7739 nested EIP-712 signature verification) - an independent,
              widely-used MIT smart-account signature implementation.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              files src/accounts/ERC1271.sol, src/utils/EIP712.sol, src/utils/SignatureCheckerLib.sol
              -> vendored at fixtures/vendor/solady/{ERC1271,EIP712,SignatureCheckerLib}.sol
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Vendor note:  the three files are byte-identical to upstream EXCEPT two import paths in ERC1271.sol
              repointed from ../utils/{EIP712,SignatureCheckerLib}.sol to ./{...}.sol (all three
              files live in one vendor dir here). Only those two import lines differ; the
              signature-verification logic is untouched. (Same kind of import-only repoint already
              documented for the vendored Permit2.)
Source code:  ../SoladyERC1271Fixture.sol (concrete wallet over the unmodified Solady ERC1271;
              adds only the two override hooks + a signature-gated withdraw).

Why holdout: The existing signature c-safe-impl fixture uses OpenZeppelin EIP712+ECDSA. Solady's
             ERC1271/ERC-7739 is a DIFFERENT, independent implementation wal was never tuned
             against, so a clean verdict here is an honest precision signal on unseen safe code.

Behavior:    test/RealSafeSoladyERC1271Holdout.t.sol funds the wallet and submits a FORGED 65-byte
             signature to authorize a full-balance withdrawal. Solady's ERC1271 `isValidSignature`
             does not validate it (returns the failure selector), so the withdrawal reverts and no
             ETH leaves the wallet. The verdict is derived from the real outcome (balance intact),
             not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
