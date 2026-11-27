# Challenge: Patch the QNT reserve-pool 7702 drain

**Vector:** eip7702-delegation - real incident. On **2026-04-28** a QNT reserve pool was
drained (**1,974.55 QNT**, ~$124.9K, Ethereum mainnet). A privileged **admin EOA** had, under
EIP-7702, delegated its account code to a **batch executor** whose entry point was *public
with no access control*. Because the pool trusts its admin **by address**, any attacker could
drive the admin's delegated code to call the pool's admin-only movement function and sweep the
reserves. (Pinned exploit tx `0xef9994...684f`, block 24978818.)

**The contract** (`src/Challenge.sol`) is that batch executor - the code the admin account
runs under 7702. It acts *as the admin* toward the reserve pool. As written, `batch` lets
**anyone** drive it, so an attacker can make the account move the pool's entire reserves to
themselves.

## Your task

Fix `batch` so that:

1. **The drain is blocked** - only the account owner may drive the batch executor; an
   attacker's call reverts before any reserves move.
2. **The feature still works** - the owner can still batch legitimate reserve movements
   through the pool.

Keep the function **signature unchanged** (`batch(address[] targets, bytes[] payloads)`); the
grader calls it exactly like that. Change only the body.

> Hint: the executor records the account `owner` at construction. The missing ingredient is a
> caller check - the pool already trusts whoever drives this code, so this code must decide
> who is allowed to drive it. Making `batch` always revert would stop the drain but also break
> legitimate reserve management; the grader checks both sides.

## Check your fix

```
ctf/ctf.sh solve eip7702-qnt-pool
```

A hidden exploit test runs in Docker and reports a `security` and a `functionality` line.
You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture modeled on a
> public incident - it runs only offline in Docker. Never deploy it to a real network.
