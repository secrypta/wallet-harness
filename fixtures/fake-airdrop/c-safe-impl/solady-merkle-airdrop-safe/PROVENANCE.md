# Fixture provenance

```
Fixture:      fake-airdrop/c-safe-impl/solady-merkle-airdrop-safe
Vector:       fake-airdrop
Tier:         c-safe-impl
Split:        holdout
Expected:     safe                     # ground-truth label (matches meta `label`)

Nature:       PRECISION-SIDE safe holdout. There is no clean, independently-documented
              fake-airdrop *incident* reproducible at code level at our provenance bar (two
              extended web passes over authoritative sources found only aggregate figures and
              secondary blogs with conflicting numbers - see the drain-bench README honesty
              section). So this vector's independent holdout is a genuinely-safe real
              implementation on which the harness MUST stay silent, not a vuln repro.

Origin:       The canonical SAFE counterpart of the fake-airdrop vector: a Merkle-gated airdrop
              distributor (the Uniswap/Optimism-style distributor pattern). Eligibility and
              amount are committed up front in a Merkle root; a claim must present an inclusion
              proof for the exact (account, amount) leaf. This is the opposite of the vector's
              unsafe shape (an open/attacker-controlled claim or a drainer "claim" that instead
              grants an approval). The inclusion check is delegated to UNMODIFIED Solady
              MerkleProofLib.

Upstream:     - Solady MerkleProofLib: github.com/Vectorized/solady, tag v0.1.22,
                commit 65e87c72a5ee4a6708946b25611ec5f980ceba70,
                src/utils/MerkleProofLib.sol, SPDX MIT.
                Vendored byte-identical at fixtures/vendor/solady-accounts/utils/MerkleProofLib.sol
                (see fixtures/vendor/PROVENANCE.md).

Independence: The dev fake-airdrop safe fixture (oz-safe-claim) uses OpenZeppelin as the asset;
              this holdout uses a DIFFERENT canonical source (Solady MerkleProofLib) under a
              distributor pattern the wal detectors were never tuned against - a real precision
              signal on unseen safe code.

Source code:  fixtures/fake-airdrop/c-safe-impl/MerkleAirdropDistributor.sol (authored here:
              the distributor shell + claim gating; the proof verification is unmodified Solady)
              + src/MockERC20.sol (repo primitive, the airdropped asset, read-only) +
              test/RealSafeMerkleAirdropHoldout.t.sol.
License:      MIT (this repo) + MIT (Solady).
Offline:      committed source only; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        The test builds a real 2-leaf Merkle tree, shows the rightful account claims its
              exact allocation (authority is real, so BLOCKED is not vacuous), then shows an
              account absent from the tree - and a forged/over-amount claim - revert
              (InvalidProof), transferring nothing. Verdict derived from outcome (no
              unauthorized tokens leave). Expected: BLOCKED (TN). A false VULNERABLE here would
              be a real detector false positive and is reported, not suppressed.
```
