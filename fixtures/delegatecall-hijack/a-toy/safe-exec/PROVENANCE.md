# Fixture provenance

```
Fixture:      delegatecall-hijack/a-toy/safe-exec
Vector:       delegatecall-hijack
Tier:         a-toy
Expected:     safe

Origin:       Synthetic toy authored in this repo (MIT). Same account layout as
              vulnerable-exec, but execTransaction allow-lists delegatecall targets.
Source code:  ../../../../src/SafeAccount.sol + src/AuditedLibModule.sol (benign delegate)
License:      MIT (this repo). No third-party source.
Offline:      pure unit test, no fork/RPC. Built/run in Docker.
Notes:        test/DelegatecallHijack.t.sol: delegatecall to the non-allow-listed attacker
              module reverts (pointer + assets intact) -> BLOCKED. Guards: a plain call
              (operation 0) and an allow-listed benign delegate still run, so BLOCKED is
              not vacuous. Expected: BLOCKED.
```
