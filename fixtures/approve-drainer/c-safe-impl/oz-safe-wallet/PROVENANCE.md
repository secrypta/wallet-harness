# Fixture provenance

```
Fixture:      approve-drainer/c-safe-impl/oz-safe-wallet
Vector:       approve-drainer
Tier:         c-safe-impl
Expected:     safe                     # ground-truth label (matches meta `label`)

Origin:       https://github.com/OpenZeppelin/openzeppelin-contracts
Reference:    release v5.1.0
Source code:  github.com/OpenZeppelin/openzeppelin-contracts @ 69c8def5f222ff96f2b5beff05dfba996368aa79
License:      MIT (Copyright (c) 2016-2024 Zeppelin Group Ltd) - see ../../../vendor/oz/LICENSE

Minimization: none for the safety-relevant code - OZ ERC20 and its dependency closure are
              vendored byte-identical under ../../../vendor/oz/ (see ../../../vendor/PROVENANCE.md).
              Authored on top (in ../): OZERC20Fixture (concrete subclass adding only a
              test-only `mint`) and SafeAllowanceFlow (bounded-approve wallet policy). No
              OZ logic changed.
Offline:      committed source only; no network, no live RPC. Built/run in Docker.
Notes:        The allowance accounting that blocks the drain is unmodified OZ
              `_spendAllowance`. test/RealSafe.t.sol proves a full-balance transferFrom
              reverts while a bounded spend (= action amount) succeeds, so the verdict
              BLOCKED is genuine, not vacuous. Expected verdict: BLOCKED (TN).
```
