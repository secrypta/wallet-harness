# Fixture provenance

```
Fixture:      eip7702-delegation/c-safe-impl/solady-handover-safe
Vector:       eip7702-delegation
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout
Expected:     safe

Origin:       Solady Ownable - the two-step ownership-handover mechanism of Solady's auth base.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/auth/Ownable.sol -> vendored byte-identical at
              fixtures/vendor/solady-accounts/auth/Ownable.sol (pristine; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ../SoladyHandoverDelegate.sol (a 7702-delegate over unmodified Solady Ownable; adds
              only a one-time initialize and an owner-gated execute).

Why holdout: The existing eip7702 holdouts test init-time auth (solady-initguard-safe), role-gated
             execution (solady-ownableroles-exec-safe) and call-time owner/role checks. This fixture
             tests a different security PROPERTY: the two-step ownership-handover takeover defense -
             an attacker's requestOwnershipHandover only registers a pending request, and
             completeOwnershipHandover/transferOwnership are onlyOwner, so no one-step takeover.

Behavior:    test/RealSafeSoladyHandoverHoldout.t.sol has an attacker request a handover, fail to
             complete it (onlyOwner) and fail to execute (not owner); ownership and funds stay put.
             A guard runs the legitimate two-step handover (new owner requests, current owner
             completes) and shows the new owner CAN execute. Verdict derived from the real outcome.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
