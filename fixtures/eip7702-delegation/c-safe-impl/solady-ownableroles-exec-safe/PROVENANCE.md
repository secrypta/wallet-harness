# Fixture provenance

```
Fixture:      eip7702-delegation/c-safe-impl/solady-ownableroles-exec-safe
Vector:       eip7702-delegation
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout
Expected:     safe

Origin:       Solady OwnableRoles - the independent bitmask role-based authorization base of
              Solady's smart-wallet stack.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/auth/OwnableRoles.sol (+ Ownable) -> vendored byte-identical at
              fixtures/vendor/solady-accounts/auth/ (pristine layout; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ../SoladyRolesDelegate.sol (a 7702-delegate over unmodified Solady OwnableRoles;
              adds only a one-time initialize, a role constant and the role-gated execute).

Why holdout: The existing eip7702 holdouts use OZ AccessControl (oz-accesscontrol-exec-safe),
             plain Solady Ownable (solady-erc7821-safe), and init-time auth (solady-initguard-safe).
             This fixture exercises Solady's independent BITMASK role system (onlyRolesOrOwner) - a
             different real authorization mechanism wal was never tuned against.

Behavior:    test/RealSafeSoladyRolesDelegateHoldout.t.sol initializes the owner, grants EXECUTOR_ROLE
             to a relayer, then has an attacker with neither owner nor role attempt execute (reverts
             Unauthorized). Guards confirm both the owner and the role-holder CAN execute. Verdict
             derived from the real outcome (delegate balance intact under the attacker).
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
