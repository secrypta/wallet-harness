# Fixture provenance

```
Fixture:      create2-metamorphic/c-safe-impl/solady-create3-safe
Vector:       create2-metamorphic
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady `utils/CREATE3.sol` - the canonical CREATE3 deterministic-deployment
              library. The deployed address depends ONLY on (salt, deployer), independent of
              the init code: a tiny CREATE2 proxy is placed at the deterministic slot and then
              CREATEs the target; neither has a `selfdestruct`. Once deployed, the address can
              never be destroyed and redeployed, and a second deploy at the same salt reverts
              (slot occupied). The metamorphic precondition (redeploy DIFFERENT code at the
              SAME address a prior approval points at) is absent.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/utils/CREATE3.sol -> vendored byte-identical at
                   fixtures/vendor/solady-accounts/utils/CREATE3.sol (self-contained, no
                   imports; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ./Create3Factory.sol (thin factory over the unmodified Solady CREATE3, plus two
              trivial implementations; changes none of CREATE3's logic.)
```

## Independent corroboration (the pattern, not an incident)
Safe-side PRECISION fixture - no incident to triangulate. The code-independent, non-destroyable
CREATE3 address is the documented behaviour of the Solady/Solmate/0xSequence CREATE3 pattern:
- Solady CREATE3 source header (self-documenting; modified from Solmate / 0xSequence).
- Solady repo: https://github.com/Vectorized/solady/blob/main/src/utils/CREATE3.sol

## Distinct from the other create2-metamorphic safe fixtures
`solady-libclone-safe` and `oz-clones-safe` use EIP-1167 clones whose address depends on the
init code (different code -> different address). CREATE3 derives the address from salt+deployer
only, so a redeploy at the same salt - even with different code - targets the SAME address and
still fails. A different deterministic-deploy mechanism.

## Why the harness must stay silent (BLOCKED)
The test deploys `PingImpl` via CREATE3 (works, non-vacuous), confirms the predicted address
matches, then (a) redeploys the same salt and (b) deploys DIFFERENT code at the same salt -
both fail (the deterministic slot is occupied and nothing self-destructs). The code at the
approved address is unchanged -> verdict BLOCKED, 0 false positives.
