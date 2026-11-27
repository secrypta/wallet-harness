# Fixture provenance

```
Fixture:      fake-airdrop/c-safe-impl/signature-voucher-safe
Vector:       fake-airdrop
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout
Expected:     safe

Origin:       OpenZeppelin EIP712 + ECDSA - the canonical primitives for an authority-signed
              airdrop voucher (a widely-used claim pattern alongside Merkle distributors).
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files utils/cryptography/{EIP712,ECDSA}.sol -> vendored byte-identical at
              fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in fixtures/vendor/oz/LICENSE.
Source code:  ../SignatureVoucherAirdrop.sol (authority-signed voucher distributor over unmodified
              OZ EIP712 + ECDSA; adds only the typed Claim struct, a claimed flag and the gated
              transfer - no change to the hashing/recovery logic).

Why holdout: The existing fake-airdrop holdouts both verify a MERKLE PROOF (oz-merkleproof-safe,
             solady-merkle-airdrop-safe). This fixture uses a different real inclusion mechanism -
             an AUTHORITY SIGNATURE over a typed EIP-712 voucher - so a fake-airdrop operator cannot
             mint itself a claim without the authority key. Unseen safe code wal was never tuned
             against.

Behavior:    test/RealSafeSignatureVoucherHoldout.t.sol has the authority sign a voucher that lets
             the rightful account claim its allocation (guard: authority is real), then has the
             fake-airdrop operator forge a voucher for themselves with their own key - ECDSA.recover
             != authority, so the claim reverts and nothing is transferred. Verdict derived from the
             real outcome (operator balance stays 0).
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
             Precision-side safe holdout (fake-airdrop is dry on code-level vuln incidents at the
             bar); stated plainly, not padded.
```
