# Fixture provenance

```
Fixture:      fake-airdrop/c-safe-impl/oz-merkleproof-safe
Vector:       fake-airdrop
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent canonical verifier; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin MerkleProof - the canonical Merkle inclusion verifier used by the
              widely-deployed OZ/Uniswap/OP-style Merkle airdrop distributor pattern.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files utils/cryptography/MerkleProof.sol (+ its only import utils/cryptography/Hashes.sol)
              -> vendored byte-identical at fixtures/vendor/oz/utils/cryptography/ (see
              fixtures/vendor/PROVENANCE.md). OZ uses relative imports, no repoint needed.
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in fixtures/vendor/oz/LICENSE.
Source code:  ../OzMerkleAirdropDistributor.sol (concrete distributor over the unmodified OZ
              MerkleProof; gates each claim on an inclusion proof against a fixed root - adds only
              the distributor wrapper, no change to the verification logic). Leaf uses OZ's standard
              double-hash convention: keccak256(bytes.concat(keccak256(abi.encode(account, amount)))).

Why holdout: The existing fake-airdrop c-safe-impl fixtures use Solady MerkleProofLib
             (solady-merkle-airdrop-safe) and an OZ ERC-20 as the asset (oz-safe-claim). This
             fixture delegates the INCLUSION CHECK to OpenZeppelin's canonical MerkleProof - a
             different canonical verifier wal was never tuned against, so a clean verdict is an
             honest precision signal on unseen safe code.

Behavior:    test/RealSafeOzMerkleAirdropHoldout.t.sol commits a 2-leaf tree (Alice, Bob), has
             the rightful account claim its exact committed allocation (guard: authority is real),
             then attempts (1) a claim by an account absent from the tree and (2) an inflated
             amount for an in-tree account. OZ MerkleProof rejects both (InvalidProof) and nothing
             unauthorized leaves the distributor. The verdict is derived from the real outcome
             (attacker balance stays 0, only the claimed allocation moved), not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
             No fabricated incident: this is a precision-side safe holdout (no code-level vuln
             fake-airdrop incident at the bar), stated plainly - not padded into a false positive.
```
