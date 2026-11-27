# Challenge: eip7702-delegation

**Vector:** eip7702-delegation - under EIP-7702 an account (EOA) can delegate its code to a
contract, so that contract runs *as the account* and can move all of the account's assets. A
delegate that exposes a batch-execute entry point with **no caller authorization** lets
anyone drive the account's code - a single call drains everything. (This mirrors a real
reserve-pool drain where a delegated admin account's `batch` executor was fully public.)

**The contract** (`src/Challenge.sol`) is such a delegate: `batch(targets, payloads)` makes
the account perform an arbitrary list of calls. As written there is **no check on who may
call it**, so an attacker can make the account transfer its whole balance to themselves.

## Your task

Fix `batch` so that:

1. **The drain is blocked** - only the account's owner may drive the batch executor; an
   attacker's call must revert.
2. **The feature still works** - the owner can still batch-execute legitimate calls.

Keep the function **signature unchanged** (`batch(address[] targets, bytes[] payloads)`); the
grader calls it exactly like that. Change only the body.

> Hint: the delegate stores the account `owner` at construction. Gate the executor on the
> caller. Making `batch` always revert would stop the drain but also break the feature - the
> grader checks both sides.

## Check your fix

```
ctf/ctf.sh solve eip7702-delegation
```

A hidden exploit test runs in Docker and reports a `security` and a `functionality` line.
You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
