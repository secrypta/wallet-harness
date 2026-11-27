# Fixture provenance

```
Fixture:      signature-phishing/c-safe-impl/oz-sigchecker-safe
Vector:       signature-phishing
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin Contracts `utils/cryptography/SignatureChecker` (ERC-1271-aware
              signature validation) over `utils/cryptography/EIP712` typed digests, with
              `ECDSA` (zero-address / malleability safe) underneath.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files utils/cryptography/{SignatureChecker,ECDSA,EIP712,MessageHashUtils}.sol,
                    interfaces/IERC1271.sol, utils/{ShortStrings,StorageSlot}.sol,
                    interfaces/IERC5267.sol
              -> vendored byte-identical at fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text fixtures/vendor/oz/LICENSE.
Vendor note:  the OZ files are byte-identical to the tagged release (already present in the
              repo from the permit/signature (c) work); nothing in vendor/oz is modified.
Source code:  ../OzSignatureCheckerWallet.sol (authored thin wallet: a typed Withdraw struct +
              replay nonce + a withdrawal gated on SignatureChecker.isValidSignatureNow over the
              OZ EIP712 digest). The signature-verification logic is unmodified OZ.

Why holdout: The existing signature c-safe-impl (oz-sig-safe) uses bare `ECDSA.recover` under a
             scoped-order policy. This fixture instead exercises OZ's higher-level
             `SignatureChecker` (the ERC-1271-aware canonical path), real published code wal was
             not tuned against, so a clean verdict is an honest precision signal.

Behavior:    test/RealSafeOzSignatureCheckerHoldout.t.sol funds the wallet, then submits a FORGED
             signature (signed by an attacker key, not the wallet's signer) authorizing a
             full-balance withdrawal. OZ SignatureChecker returns false, so the withdrawal
             reverts and no funds leave. A guard proves a genuine signer signature DOES withdraw,
             so BLOCKED is a real rejection, not vacuous. Verdict derived from the real outcome.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.
Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and recorded as such, not suppressed.
```
