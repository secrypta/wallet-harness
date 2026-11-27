# Fixture provenance

```
Fixture:      delegatecall-hijack/c-safe-impl/guarded-exec-safe
Vector:       delegatecall-hijack
Tier:         c-safe-impl
Expected:     safe

Nature:       REFERENCE-IMPL of the canonical post-Bybit mitigation - a Safe-style
              transaction guard plus an implementation-slot invariant. Honestly flagged:
              this is NOT a vendored third-party library. delegatecall-hijack has no single
              canonical library to vendor (the defense is a wallet/guard policy), so tier
              (c) implements the documented pattern directly. It is NOT a lightly-edited
              toy: it enforces two independent, real mitigations.
Defense:      (1) transaction guard - delegatecall (operation 1) permitted only to an
              allow-listed audited library; unknown target reverts before executing.
              (2) implementation-slot invariant - slot 0 (logic/masterCopy pointer) is
              snapshotted and asserted unchanged after every user transaction; any write to
              it reverts the whole tx (defense-in-depth, catches an allow-listed or storage-
              colliding delegate that moves the pointer).
Reference:    Safe transaction-guard mechanism; post-Bybit hardening guidance
              (CertiK / SlowMist / NCC Group). Source base authored in this repo (MIT).
License:      MIT (this repo).
Offline:      pure unit test, no fork/RPC. Built/run in Docker.
Notes:        test/RealSafeDelegatecall.t.sol: the Bybit-style delegatecall-swap payload is
              BLOCKED by the guard; a separate test shows the slot invariant rolling back an
              allow-listed hijack. Guards: a plain call and an allow-listed benign delegate
              still run, so BLOCKED is not vacuous. Expected: BLOCKED (TN).
```
