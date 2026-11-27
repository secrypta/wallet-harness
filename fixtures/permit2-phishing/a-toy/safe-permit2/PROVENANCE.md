# Fixture provenance

```
Fixture:      permit2-phishing/a-toy/safe-permit2
Vector:       permit2-phishing
Tier:         a-toy
Expected:     safe

Origin:       Synthetic toy authored in this repo (MIT). Same ToyPermit2 AllowanceTransfer
              flow as vulnerable-permit2; the owner signs a BOUNDED permit instead.
Source code:  ../../../../src/ToyPermit2.sol + src/MockERC20.sol
License:      MIT (this repo). No third-party source.
Offline:      pure unit test, no fork/RPC. Built/run in Docker.
Notes:        test/Permit2Phishing.t.sol: owner signs a PermitSingle bounded to the action
              amount with a short expiration; a full-balance transferFrom reverts
              (InsufficientAllowance) -> BLOCKED. Guard: the bounded amount is genuinely
              pullable, so BLOCKED is not vacuous. Expected: BLOCKED.
```
