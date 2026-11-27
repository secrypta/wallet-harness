# Challenge: delegatecall-hijack

**Vector:** delegatecall-hijack - a smart-contract wallet that `delegatecall`s an
attacker-chosen target runs that target's code **in its own storage context**, so the
attacker can move the wallet's assets (or overwrite its implementation/owner slot) and seize
the whole account.

**The contract** (`src/Challenge.sol`) is a wallet that executes owner-approved operations.
`operation = 0` is a plain `CALL`; `operation = 1` is a `DELEGATECALL`. A legitimate
delegatecall use is the wallet's one audited batch library (`trustedLib`, think Safe's
MultiSend). As written, `execute` will `delegatecall` **any** target the caller names - so a
hostile library runs as the wallet and sweeps its balance.

## Your task

Fix `execute` so that:

1. **The drain is blocked** - a `delegatecall` to a target that is *not* the audited
   `trustedLib` must not run (it cannot be allowed to execute as the wallet).
2. **The feature still works** - a `delegatecall` to `trustedLib` (the legitimate batch
   helper) must still succeed, and plain `CALL`s are unaffected.

Keep the function **signature unchanged** (`execute(address target, bytes data, uint8
operation)`); the grader calls it exactly like that. Change only the body.

> Hint: the danger of `delegatecall` is *whose code* runs in your storage. Blocking *all*
> delegatecall would stop the hijack but break the trusted batch feature - the grader checks
> both. Think about an allow-list for delegatecall targets (`trustedLib` is exposed as a
> public immutable).

## Check your fix

```
ctf/ctf.sh solve delegatecall-hijack
```

A hidden exploit test runs in Docker and reports a `GATE` verdict with a `security` and a
`functionality` line. You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
