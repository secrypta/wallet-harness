# Fixture provenance

```
Fixture:      create2-metamorphic/c-safe-impl/solady-libclone-safe
Vector:       create2-metamorphic
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady `utils/LibClone.sol` - the canonical MIT CREATE2 minimal-proxy deployer
              used across the ecosystem. `cloneDeterministic` deploys a fixed minimal-proxy at
              a pre-computable address; the clone has NO `selfdestruct`, so the code at that
              deterministic address can never be destroyed and redeployed as different code.
              The metamorphic precondition (CREATE2 + SELFDESTRUCT + redeploy at the same
              address, which a standing approval would then point at hostile logic) is absent.
              This is a PRECISION fixture: ubiquitous, legitimate CREATE2 usage (immutable
              clones) must NOT be flagged as a metamorphic-swap risk.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/utils/LibClone.sol -> vendored byte-identical at
              fixtures/vendor/solady-accounts/utils/LibClone.sol (see fixtures/vendor/PROVENANCE.md)
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ./LibCloneFactory.sol (thin factory over the unmodified Solady LibClone, plus two
              trivial implementations to clone; changes none of LibClone's logic).

Why holdout: Solady is an independent implementation the wal detectors were never tuned
             against. A naive create2-metamorphic detector could false-positive on any CREATE2;
             staying silent on canonical immutable clones is a genuine precision result.

Behavior:    test/RealSafeCreate2Metamorphic.t.sol - deploys a deterministic clone (works, at
             the predicted address; non-vacuous), then (a) redeploying the SAME (impl, salt)
             fails - CREATE2 to the occupied address reverts, there is no selfdestruct to vacate
             it; and (b) deploying DIFFERENT code at the same salt derives a DIFFERENT address
             (LibClone bakes the implementation into the init code), so hostile code can never
             occupy the approved clone's address. The code at the approved address is unchanged.
             Verdict derived from the real outcome, not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.
Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). This is a precision
             fixture on legitimate CREATE2 code, not a defense against an attack per se; it is
             labelled and scored as safe. (See corpus/create2-metamorphic.md for why no NEW
             tier-(b) metamorphic incident clears the offline bar on Cancun.)
```
