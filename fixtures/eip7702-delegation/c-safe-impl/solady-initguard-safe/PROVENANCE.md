# Fixture provenance

```
Fixture:      eip7702-delegation/c-safe-impl/solady-initguard-safe
Vector:       eip7702-delegation
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady Ownable - the account-abstraction ownership/auth base of Solady's smart-wallet
              stack (solady-accounts/), including its initialization-hijack guard.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/auth/Ownable.sol -> vendored byte-identical at
              fixtures/vendor/solady-accounts/auth/Ownable.sol (pristine upstream layout, zero
              modifications; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ../SoladyInitGuardDelegate.sol (a 7702-delegate account over the unmodified Solady
              Ownable; overrides ONLY _guardInitializeOwner() => true to opt into Solady's reinit
              guard, and adds a one-time initialize() + an owner-gated execute() - no change to the
              guard or onlyOwner logic).

Why holdout: The existing eip7702 c-safe-impl holdouts - solady-erc7821-safe (Solady ERC7821 batch
             executor + Ownable) and oz-accesscontrol-exec-safe (OZ AccessControl executor) - test
             CALL-TIME authorization (a non-owner / non-role call reverts). This fixture tests a
             DIFFERENT property: INIT-TIME authorization, i.e. the reinit-hijack defense, on real
             Solady code wal was never tuned against - so a clean verdict is an honest precision
             signal on unseen safe code and a genuinely distinct sub-mechanism.

Behavior:    test/RealSafeSoladyInitGuardHoldout.t.sol initializes the delegate once for the
             legitimate owner, then (1) has the attacker attempt a re-initialize (reverts
             AlreadyInitialized via Solady's guard) and (2) attempt a non-owner execute (reverts
             Unauthorized). Ownership stays with the first owner and no funds move. A guard confirms
             the real owner CAN execute (authority is real). The verdict is derived from the real
             outcome (delegate balance intact, owner unchanged), not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
