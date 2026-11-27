# Fixture provenance

```
Fixture:      set-approval-for-all/c-safe-impl/oz-safe-operator
Vector:       set-approval-for-all
Tier:         c-safe-impl
Expected:     safe                     # ground-truth label (matches meta `label`)

Origin:       https://github.com/OpenZeppelin/openzeppelin-contracts
Reference:    release v5.1.0
Source code:  github.com/OpenZeppelin/openzeppelin-contracts @ 69c8def5f222ff96f2b5beff05dfba996368aa79
License:      MIT (Copyright (c) 2016-2024 Zeppelin Group Ltd) - see ../../../vendor/oz/LICENSE

Minimization: none for the safety-relevant code - OZ ERC721 and its dependency closure are
              vendored byte-identical under ../../../vendor/oz/ (see ../../../vendor/PROVENANCE.md).
              Authored on top (in ../): OZERC721Fixture (concrete subclass adding only a
              test-only `mint`) and SafeOperatorFlow (scoped-approve wallet policy). No
              OZ logic changed.
Offline:      committed source only; no network, no live RPC. Built/run in Docker.
Notes:        The authorization that blocks the sweep is unmodified OZ `transferFrom` /
              `_isAuthorized`. test/RealSafe.t.sol proves sweeping any non-scoped token
              reverts while the single scoped token is movable, so the verdict BLOCKED is
              genuine, not vacuous. Expected verdict: BLOCKED (TN).
```
