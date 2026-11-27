# Fixture provenance

```
Fixture:      signature-phishing/c-safe-impl/oz-sig-safe
Vector:       signature-phishing
Tier:         c-safe-impl
Expected:     safe                     # ground-truth label (matches meta `label`)

Origin:       https://github.com/OpenZeppelin/openzeppelin-contracts
Reference:    release v5.1.0
Source code:  github.com/OpenZeppelin/openzeppelin-contracts @ 69c8def5f222ff96f2b5beff05dfba996368aa79
License:      MIT (Copyright (c) 2016-2024 Zeppelin Group Ltd) - see ../../../vendor/oz/LICENSE

Minimization: none for the safety-relevant code - the signature stack (EIP712, ECDSA,
              MessageHashUtils, ShortStrings, StorageSlot, IERC5267) is vendored
              byte-identical under ../../../vendor/oz/ (reused, already present from the
              permit (c) work; see ../../../vendor/PROVENANCE.md). Authored on top:
              src/SafeSettlement.sol - a scoped, decode-first settlement policy built on
              the unmodified OZ EIP712 + ECDSA.recover.
Offline:      committed source only; no network, no live RPC. Built/run in Docker.
Notes:        The EIP-712 digest and signature recovery (zero-address / malleability safe)
              are unmodified OZ. The policy accepts only a decodable, scoped order to an
              allow-listed counterparty (no blind-hash entrypoint; all-asset orders exceed
              the scoped cap). test/RealSafeSignature.t.sol proves a phishing all-asset /
              untrusted-recipient order reverts while a genuine scoped order settles, so the
              verdict BLOCKED is genuine, not vacuous. Expected verdict: BLOCKED (TN).
```
