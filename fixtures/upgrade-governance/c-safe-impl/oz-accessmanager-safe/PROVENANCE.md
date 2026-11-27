# Fixture provenance

```
Fixture:      upgrade-governance/c-safe-impl/oz-accessmanager-safe
Vector:       upgrade-governance
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin `access/manager/AccessManager.sol` - the canonical role-and-delay
              authority. `canCall(caller, target, selector)` returns whether `caller` may
              invoke `selector` on `target` immediately and any required execution delay. The
              upgrade-governance vector (Audius-style) is a single key instantly swapping a
              protected implementation/admin pointer. Here the sensitive op defers to the real
              AccessManager: a key with no role is rejected (`immediate == false`); a key whose
              role carries an execution delay is also rejected for a direct call
              (`immediate == false, delay > 0`) and must route through the manager's scheduled
              `execute`. No instant single-key swap exists.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              file access/manager/AccessManager.sol (+ IAccessManager, IAccessManaged, Address,
                   Context, Multicall, Math, Time import closure) -> vendored byte-identical
                   under fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in
              fixtures/vendor/oz/LICENSE.
Source code:  ./OZAccessManagedVault.sol (thin managed vault: stores the manager `authority`
              and a protected `implementation` pointer, and enforces the UNMODIFIED OZ decision
              by requiring `authority.canCall(...).immediate`. The authorization logic - roles,
              delays, scheduling - is entirely OpenZeppelin's AccessManager.)
```

## Independent corroboration (the pattern, not an incident)
Safe-side PRECISION fixture - no incident to triangulate. The role+delay authorization it
relies on is the documented behaviour of OZ AccessManager:
- OZ AccessManager docs: https://docs.openzeppelin.com/contracts/5.x/access-control#access-management
- OZ AccessManager API: https://docs.openzeppelin.com/contracts/5.x/api/access#AccessManager

## Distinct from the other upgrade-governance safe fixtures
`oz-timelock-safe` (TimelockController + UUPS) and `solady-uups-timelock-safe` gate upgrades
with a TIMELOCK; this fixture gates with the role+delay AccessManager - a different canonical
governance primitive and a different authorization mechanism.

## Why the harness must stay silent (BLOCKED)
The test deploys a real `AccessManager`, points the vault's sensitive `setImplementation` at
it, proves an authorized governor can perform the op (non-vacuous), confirms a key with no
role is rejected, and confirms a delayed-role key cannot perform the swap directly (must
schedule). No unauthorized instant swap -> verdict BLOCKED, 0 false positives.
