# Fixture provenance

```
Fixture:      eip7702-delegation/c-safe-impl/oz-accesscontrol-exec-safe
Vector:       eip7702-delegation
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin Contracts `access/AccessControl.sol` gating an arbitrary-call delegate
              executor - the surface an EIP-7702 delegate presents - with role-based access
              control. A DIFFERENT real authorization library than the Solady-Ownable ERC7821
              fixture (solady-erc7821-safe): role-based vs single-owner, so the detectors see two
              distinct real auth patterns on the same vector.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files access/{AccessControl,IAccessControl}.sol (+ already-vendored utils/Context,
                    introspection/{ERC165,IERC165}, utils/Strings)
              -> vendored byte-identical under fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text fixtures/vendor/oz/LICENSE.
Source code:  ../OzAccessControlExecutorWallet.sol (authored thin wallet: a receive() + an
              `execute` wrapper gated by OZ `onlyRole(EXECUTOR_ROLE)`). The authorization logic
              is unmodified OZ AccessControl.

Why holdout: distinct from solady-erc7821-safe (Solady Ownable). This exercises OZ AccessControl
             role authorization, real code wal was never tuned against, so a clean verdict is an
             honest precision signal on a second real auth pattern for this vector.

Behavior:    test/RealSafeOzAccessControlExecHoldout.t.sol funds the account; an attacker without
             EXECUTOR_ROLE calls execute() to sweep the whole balance. OZ `onlyRole` reverts with
             `AccessControlUnauthorizedAccount`, so nothing leaves. A guard proves a role-holder
             CAN execute, so BLOCKED is a real authorization rejection, not a broken executor.
             Verdict derived from the real outcome.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.
Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and recorded as such, not suppressed.
```
