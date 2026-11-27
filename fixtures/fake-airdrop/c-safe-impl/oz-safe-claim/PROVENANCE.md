# Fixture provenance

```
Fixture:      fake-airdrop/c-safe-impl/oz-safe-claim
Vector:       fake-airdrop
Tier:         c-safe-impl
Expected:     safe                     # ground-truth label (matches meta `label`)

Origin:       https://github.com/OpenZeppelin/openzeppelin-contracts
Reference:    release v5.1.0
Source code:  github.com/OpenZeppelin/openzeppelin-contracts @ 69c8def5f222ff96f2b5beff05dfba996368aa79
License:      MIT (Copyright (c) 2016-2024 Zeppelin Group Ltd) - see ../../../vendor/oz/LICENSE

Minimization: none for the safety-relevant code - the REAL asset is unmodified OZ ERC20 and
              its dependency closure, vendored byte-identical under ../../../vendor/oz/
              (see ../../../vendor/PROVENANCE.md; nothing in vendor/ is touched by this
              fixture). Authored on top (in ../): OZRealAsset, a concrete OZ ERC20 subclass
              adding only a test-only `mint`. The bait token (../../../src/GiftToken.sol)
              and the drainer (../../../src/MaliciousSpender.sol) are this repo's own toys.
Offline:      committed source only; no network, no live RPC. Built/run in Docker.
Notes:        The allowance accounting that blocks the drain is unmodified OZ
              `_spendAllowance`. test/RealSafeAirdrop.t.sol: a safe claim grants no drainable
              allowance on the real asset, so a full-balance drain reverts while the bait
              stays untouched; a guard shows a bounded spend succeeds and a full drain
              reverts, so BLOCKED is genuine, not vacuous. Expected verdict: BLOCKED (TN).
```
