# Fixture provenance

```
Fixture:      approve-drainer/c-safe-impl/oz-erc4626-safe
Vector:       approve-drainer
Tier:         c-safe-impl
Expected:     safe                     # ground-truth label (matches meta `label`)
Split:        holdout                  # authored after wal detectors froze at v0.1

Origin:       https://github.com/OpenZeppelin/openzeppelin-contracts
Reference:    release v5.1.0
Source code:  github.com/OpenZeppelin/openzeppelin-contracts @ 69c8def5f222ff96f2b5beff05dfba996368aa79
License:      MIT (Copyright (c) 2016-2024 Zeppelin Group Ltd) - see ../../../vendor/oz/LICENSE

Minimization: none for the safety-relevant code - OZ ERC4626 (and the ERC20 it inherits, with
              its `_spendAllowance` allowance check) are vendored byte-identical under
              ../../../vendor/oz/ (see ../../../vendor/PROVENANCE.md). Authored on top:
              OZERC4626Fixture (a concrete vault naming its share token + underlying asset,
              plus a test-only share mint). No OZ logic changed.
Offline:      committed source only; no network, no live RPC. Built/run in Docker.
Notes:        An ERC-4626 vault share is a real ERC-20; a bounded approve on the shares is
              decremented by OZ's own `_spendAllowance`, so a spender cannot move more shares
              than granted. test/RealSafeApproveRound2.t.sol
              (test_approveDrainer_ozErc4626Shares_blocked) proves the bounded share spend
              succeeds and a full-balance share transferFrom reverts - BLOCKED is genuine.
              Exercises the detector's silence on a real vault token, a distinct contract
              surface from a plain ERC20. Expected verdict: BLOCKED (TN).
```
