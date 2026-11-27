# Fixture provenance

```
Fixture:      delegatecall-hijack/a-toy/vulnerable-exec
Vector:       delegatecall-hijack
Tier:         a-toy
Expected:     vuln

Origin:       Synthetic toy authored in this repo (MIT). Models a proxy-style account whose
              execTransaction forwards an action as call or delegatecall per an unchecked
              `operation` flag.
Source code:  ../../../../src/VulnerableAccount.sol + src/AccountTakeoverModule.sol
License:      MIT (this repo). No third-party source.
Offline:      pure unit test, no fork/RPC. Built/run in Docker.
Notes:        test/DelegatecallHijack.t.sol flips operation to delegatecall(1) against the
              attacker module, which overwrites slot 0 (logic pointer) and sweeps the
              balance. Verdict from the real outcome (pointer swapped + funds gone).
              Expected: VULNERABLE.
```
