# Fixture provenance

```
Fixture:      create2-metamorphic/c-safe-impl/oz-clones-safe
Vector:       create2-metamorphic
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin `proxy/Clones.sol` - the canonical CREATE2 minimal-proxy (EIP-1167)
              deployer used ecosystem-wide for factory patterns. `cloneDeterministic` deploys a
              fixed minimal proxy at a pre-computable address; the clone has NO `selfdestruct`,
              so the code at that deterministic address can never be destroyed and redeployed
              as different code. OZ also bakes the implementation address into the clone init
              code, so a different implementation derives a DIFFERENT address. The metamorphic
              precondition (CREATE2 + SELFDESTRUCT + redeploy different code at the same
              address) is absent. PRECISION fixture: legitimate, immutable CREATE2 clones must
              NOT be flagged as a metamorphic-swap risk.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              file proxy/Clones.sol (+ utils/Errors.sol) -> vendored byte-identical under
                   fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in
              fixtures/vendor/oz/LICENSE.
Source code:  ./OZClonesFactory.sol (thin factory over the unmodified OZ Clones library, plus
              two trivial implementations to clone; changes none of Clones' logic.)
```

## Independent corroboration (the pattern, not an incident)
Safe-side PRECISION fixture - no incident to triangulate. The immutability of an EIP-1167
minimal-proxy clone (no selfdestruct; implementation fixed in init code) is the documented
behaviour of OZ Clones and the EIP-1167 standard:
- OZ Clones docs: https://docs.openzeppelin.com/contracts/5.x/api/proxy#Clones
- EIP-1167 (minimal proxy): https://eips.ethereum.org/EIPS/eip-1167

## Distinct from the other create2-metamorphic safe fixtures
`solady-libclone-safe` uses Solady `LibClone.cloneDeterministic`; `codehash-pinned-safe` pins
a codehash. This fixture uses the OpenZeppelin `Clones` library - a different canonical
implementation of the same immutable-clone guarantee.

## Why the harness must stay silent (BLOCKED)
The test deploys a clone (works, non-vacuous), confirms the predicted address matches, then
(a) tries to redeploy the SAME (impl, salt) - CREATE2 to the occupied address fails (no
selfdestruct to vacate it); and (b) deploys DIFFERENT code at the same salt - it derives a
DIFFERENT address, never the approved clone's. The code at the approved address is unchanged
-> verdict BLOCKED, 0 false positives.
