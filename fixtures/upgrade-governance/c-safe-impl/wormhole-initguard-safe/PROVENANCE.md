# Fixture provenance

```
Fixture:      upgrade-governance/c-safe-impl/wormhole-initguard-safe
Vector:       upgrade-governance
Tier:         c-safe-impl (genuinely-safe code)
Split:        holdout                   # independent of the frozen v0.1 detectors
Expected:     safe                      # ground-truth label (matches meta `label`)
Pairs with:   upgrade-governance/b-incident/wormhole-uninit-impl-victim
              (the SAME system in its secure/post-fix state - the vulnerable->safe pair)

Nature:       Minimized clone, authored by us (MIT), of Wormhole's SECURE (post-fix) core
              implementation. It mirrors Wormhole's genuine re-initialization guard, which is
              DISTINCT from OpenZeppelin `Initializable`: Wormhole keys an initialization flag
              PER IMPLEMENTATION in `mapping(address => bool) initializedImplementations`
              (read by `isInitialized(impl)`, written by `setInitialized(impl)`), and its
              `initializer` modifier keys that flag on `ERC1967Upgrade._getImplementation()`.
              This standalone minimized logic contract keys the same flag on `address(this)`
              (the implementation an attacker targets when calling `initialize()` directly on
              the logic contract). We do NOT vendor Wormhole's files byte-identical: its UUPS
              core pulls in `@openzeppelin/.../ERC1967Upgrade.sol`, which exists only in OZ 4.x
              and would conflict with this repo's vendored OZ v5.1.0. Per M's round-6 direction,
              this is an own MIT clone of the real mechanism, attributed, not a vendored file.

Incident:     Wormhole uninitialized-implementation bug, disclosed 2022-02-24 by whitehat
              satya0x; $10,000,000 Immunefi bounty (one of the largest ever). An earlier bugfix
              had reverted the implementation's initialization, leaving the implementation
              contract UNINITIALIZED. Anyone could call `initialize()` on the implementation
              directly, seize the guardian set, and drive the guardian-only
              `submitContractUpgrade` - which delegatecalls a migration that could `selfdestruct`
              and brick the proxy, locking the bridge's funds. Never exploited (whitehat).
Uninit impl:  0x736d2a394f7810c17b3c6fed017d5bc7d60c077d
Fix:          A single transaction called `initialize()` on the implementation and set the
              Guardians, i.e. INITIALIZED (locked) the implementation. After that, the
              per-implementation `initializedImplementations` guard (present in Wormhole's
              design since 2021) makes the initialized implementation non-seizable: any further
              `initialize()` reverts "already initialized".
Fix tx:       0x9acb2b580aba4f5be75366255800df5f62ede576619cb5ce638cedc61273a50f
Note:         The durable guard pre-existed the incident; the incident was that the
              implementation had been left uninitialized, and the fix was to initialize it.
              This fixture models the SECURE (post-fix) state: the implementation ships
              initialized and the guard blocks re-initialization. We do NOT claim the guard was
              added as the fix.

Source code:  github.com/wormhole-foundation/wormhole, Apache-2.0
              ethereum/contracts/Implementation.sol  (blob 5bb98cf87b22d23b85f29a94d1c924db11a9c6c3)
              ethereum/contracts/Getters.sol          (blob 627b641509a7e2cbfc8148a59aa1628e1399d39e)
              ethereum/contracts/Setters.sol          (blob 17f8828278c075129d15e83fff71ea076440d0c4)
              at main commit c7029ab06566c707f6ba89539ce9b24bbfc009ef (fetched 2026-11-19).
License:      Apache-2.0 - Copyright 2022 Wormhole Project Contributors (mechanism attribution).
              Our clone file carries SPDX MIT (this repo). No Wormhole bytecode or source file
              is copied verbatim; only the documented mechanism is reproduced in minimized form.
```

## Sources (authoritative; facts agree across them)
  1. Immunefi - "Wormhole Uninitialized Proxy Bugfix Review" (disclosure, $10M bounty,
     uninitialized impl 0x736d2a39..., fix tx 0x9acb2b58..., selfdestruct-via-delegatecall)
     https://immunefi.com/blog/bug-fix-reviews/wormhole-uninitialized-proxy-bugfix-review/
  2. PortSwigger / The Daily Swig - "blockchain bridge Wormhole pays record $10m bug bounty"
     (same-day patch, satya0x, record bounty)
     https://portswigger.net/daily-swig/blockchain-bridge-wormhole-pays-record-10m-bug-bounty-reward
  3. Wormhole source (Apache-2.0): Implementation.sol `initializer` modifier +
     Getters.isInitialized / Setters.setInitialized over `initializedImplementations`
     https://github.com/wormhole-foundation/wormhole/blob/main/ethereum/contracts/Implementation.sol

## Why the harness must stay silent (BLOCKED)
The test runs the SAME takeover attempt as the incident fixture against this secure clone: the
implementation is first initialized (locked) by the legitimate setup (the step the incident
failed to do), then an attacker tries to `initialize()` it (reverts "already initialized") and
to `submitContractUpgrade` (reverts "not guardian"). The attacker seizes nothing and the
upgrade pointer is unchanged -> verdict BLOCKED. Non-vacuous: the legitimate guardian still
performs `submitContractUpgrade`, and a fresh (not-yet-initialized) implementation instance can
be initialized exactly once before the per-implementation guard locks it - proving the guard is
a real per-implementation one-shot, not dead code.

If a (future) static upgrade-governance detector flagged this as VULNERABLE, that would be a
genuine detector false positive on a guarded, initialized implementation - to be recorded as a
finding, NOT masked by altering this fixture.

## Distinct from existing upgrade-governance c-safe fixtures
- oz-timelock-safe / oz-accessmanager-safe / oz-governor-safe: gate the UPGRADE AUTHORITY
  (timelock / AccessManager / Governor vote) of a UUPS wallet. Here the mechanism is a
  per-implementation RE-INITIALIZATION guard on the logic contract itself (Wormhole's
  `initializedImplementations`), closing the uninitialized-implementation takeover - a
  different surface and a different, non-OZ mechanism.
