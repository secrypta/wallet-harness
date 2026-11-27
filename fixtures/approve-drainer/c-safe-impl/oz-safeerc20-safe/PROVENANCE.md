# Fixture provenance

```
Fixture:      approve-drainer/c-safe-impl/oz-safeerc20-safe
Vector:       approve-drainer
Tier:         c-safe-impl
Expected:     safe                     # ground-truth label (matches meta `label`)
Split:        holdout                  # authored after wal detectors froze at v0.1

Origin:       https://github.com/OpenZeppelin/openzeppelin-contracts
Reference:    release v5.1.0
Source code:  github.com/OpenZeppelin/openzeppelin-contracts @ 69c8def5f222ff96f2b5beff05dfba996368aa79
License:      MIT (Copyright (c) 2016-2024 Zeppelin Group Ltd) - see ../../../vendor/oz/LICENSE

Minimization: none for the safety-relevant code - OZ SafeERC20 (forceApprove,
              safeDecreaseAllowance) and ERC20 with its `_spendAllowance` check are vendored
              byte-identical under ../../../vendor/oz/ (see ../../../vendor/PROVENANCE.md).
              Authored on top: SafeErc20AllowanceFlow (a policy wrapper that grants exactly
              the action amount via SafeERC20.forceApprove and resets it to zero afterwards)
              and the OZERC20Fixture token (OZ ERC20 + a test-only mint). No OZ logic changed.
Offline:      committed source only; no network, no live RPC. Built/run in Docker.
Notes:        SafeERC20.forceApprove is the canonical OZ way to set/reset an exact allowance
              without an unlimited standing approve. test/RealSafeApproveRound2.t.sol
              (test_approveDrainer_ozSafeErc20_blocked) proves the bounded spend succeeds, a
              full-balance transferFrom reverts on OZ's allowance check, and the residual
              allowance is revoked to zero - so BLOCKED is genuine, not vacuous.
              Expected verdict: BLOCKED (TN).
```
