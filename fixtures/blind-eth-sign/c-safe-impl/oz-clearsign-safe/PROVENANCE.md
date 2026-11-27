# Fixture provenance

```
Fixture:      blind-eth-sign/c-safe-impl/oz-clearsign-safe
Vector:       blind-eth-sign
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin Contracts `utils/cryptography/EIP712` (typed digest) + `ECDSA`
              (recovery, zero-address / malleability safe). A clear-signing wallet that
              authorizes only from a decodable EIP-712 typed signature and has NO raw-hash
              (`eth_sign`) entrypoint - the defensive direction for the blind-eth-sign vector.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files utils/cryptography/{EIP712,ECDSA,MessageHashUtils}.sol, utils/{ShortStrings,
                    StorageSlot}.sol, interfaces/IERC5267.sol
              -> vendored byte-identical at fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text fixtures/vendor/oz/LICENSE.
Vendor note:  OZ files byte-identical to the tagged release; nothing in vendor/oz is modified.
Source code:  ../OzClearSigningWallet.sol (authored thin wallet: typed Withdraw struct + replay
              nonce + a withdrawal gated on ECDSA.recover over the wallet's OWN EIP712 typed
              digest; no function accepts a bare hash). The EIP-712/ECDSA logic is unmodified OZ.

Why holdout: distinct from permit2-sigverify-safe (Uniswap Permit2) - this is OZ's EIP712+ECDSA
             clear-signing property on unseen real code, so a clean verdict is an honest
             precision signal.

Behavior:    test/RealSafeOzClearSignHoldout.t.sol models the eth_sign blind-signing attack: the
             victim blind-signs an attacker-chosen OPAQUE 32-byte hash (no prefix, no struct);
             the attacker replays that signature into a withdrawal. The wallet recovers only over
             its OWN reconstructed typed digest, so the blind signature recovers to a different
             address, authorization fails, and no funds leave. A guard proves a genuine
             clear-signed (typed) signature DOES withdraw. Verdict derived from the real outcome.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.
Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and recorded as such, not suppressed.
```
