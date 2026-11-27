# Fixture provenance

```
Fixture:      malicious-calldata/c-safe-impl/solady-ownableroles-executor-safe
Vector:       malicious-calldata
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady `auth/OwnableRoles.sol` - a canonical owner + bitmap-roles authorization
              mixin. The executor exposes `execute(target, value, data)` - a genuine
              arbitrary-external-call sink (the Socket-2024 shape) - gated by
              `onlyOwnerOrRoles(EXECUTOR_ROLE)`. Only the owner or an explicitly role-granted
              operator may reach it, so an unauthorized attacker cannot inject
              `transferFrom(victim, attacker, ...)` against a standing approval the victim
              granted the executor.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/auth/OwnableRoles.sol (+ auth/Ownable.sol) -> vendored byte-identical
                   under fixtures/vendor/solady-accounts/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ./SoladyRolesExecutor.sol (thin executor over the unmodified Solady OwnableRoles:
              adds an `EXECUTOR_ROLE` bit and an owner-or-role-gated `execute`; the
              authorization logic is entirely Solady's.)
```

## Independent corroboration (the pattern, not an incident)
Safe-side PRECISION fixture - no incident to triangulate. The owner/role authorization it
relies on is the documented behaviour of Solady OwnableRoles:
- Solady source header (self-documenting): owner + bitmap roles, `onlyOwnerOrRoles` modifier.
- Solady repo: https://github.com/Vectorized/solady/blob/main/src/auth/OwnableRoles.sol

## Distinct from the other malicious-calldata safe fixtures
`oz-multicall-safe` / `solady-multicallable-safe` are self-only multicalls (no external-call
sink). `oz-timelock-executor-safe` gates an arbitrary-call executor with role + schedule +
delay. This fixture gates with Solady owner/role authorization (no delay, no self-only
restriction) - a different real primitive and mechanism.

## Why the harness must stay silent (BLOCKED)
The test has a victim grant the executor a standing max approval, then has an unauthorized
attacker try to drain via `execute(token, 0, transferFrom(victim, attacker, ...))` - it
reverts (not owner, no role). The owner legitimately executes a benign call (non-vacuous). The
victim is never drained -> verdict BLOCKED.

If a (future) static malicious-calldata detector flagged this as VULNERABLE, that would be a
genuine detector false positive on legitimate role-gated execution - to be recorded as a
finding, NOT masked by altering this fixture.
