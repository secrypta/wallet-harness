# Fixture provenance

```
Fixture:      permit-phishing/c-safe-impl/oz-permit-safe
Vector:       permit-phishing
Tier:         c-safe-impl
Expected:     safe                     # ground-truth label (matches meta `label`)

Origin:       https://github.com/OpenZeppelin/openzeppelin-contracts
Reference:    release v5.1.0
Source code:  github.com/OpenZeppelin/openzeppelin-contracts @ 69c8def5f222ff96f2b5beff05dfba996368aa79
License:      MIT (Copyright (c) 2016-2024 Zeppelin Group Ltd) - see ../../../vendor/oz/LICENSE

Minimization: none for the safety-relevant code - OZ ERC20Permit and its dependency closure
              (EIP712, ECDSA, Nonces, MessageHashUtils, ShortStrings, StorageSlot,
              IERC20Permit, IERC5267) are vendored byte-identical under ../../../vendor/oz/
              (see ../../../vendor/PROVENANCE.md). Authored on top: OZERC20PermitFixture
              (concrete subclass adding only a test-only `mint`). No OZ logic changed.
Offline:      committed source only; no network, no live RPC. Built/run in Docker.
Notes:        The permit signature/nonce/deadline checks and allowance accounting that
              bound the spender are unmodified OZ `permit` + `EIP712` + `ECDSA`.
              test/RealSafePermit.t.sol signs a permit for exactly the action amount and
              proves a full-balance transferFrom reverts while the bounded spend succeeds,
              so the verdict BLOCKED is genuine, not vacuous. Expected verdict: BLOCKED (TN).
```
