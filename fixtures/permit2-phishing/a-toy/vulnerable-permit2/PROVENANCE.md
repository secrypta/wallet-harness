# Fixture provenance

```
Fixture:      permit2-phishing/a-toy/vulnerable-permit2
Vector:       permit2-phishing
Tier:         a-toy
Expected:     vuln

Origin:       Synthetic toy authored in this repo (MIT). Models Uniswap Permit2
              AllowanceTransfer (shared allowance contract, off-chain PermitSingle signature).
Source code:  ../../../../src/ToyPermit2.sol + src/MockERC20.sol
License:      MIT (this repo). No third-party source (the REAL Permit2 is vendored in tier c).
Offline:      pure unit test, no fork/RPC. Built/run in Docker.
Notes:        test/Permit2Phishing.t.sol: owner signs an UNBOUNDED PermitSingle (amount=max,
              far expiration) to the attacker; attacker permit()+transferFrom drains the
              balance. Verdict from the real outcome. Expected: VULNERABLE.
```
