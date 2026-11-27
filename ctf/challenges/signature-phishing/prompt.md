# Challenge: signature-phishing

**Vector:** signature-phishing - a wallet authorizes asset movement with an **off-chain
signature** (a marketplace/settlement order) rather than a transaction. If the signed digest
does not bind every field of the order, one signature the owner produced for a small, scoped
trade can be lifted onto a different order that drains the whole balance.

**The contract** (`src/Challenge.sol`) is a settlement wallet. The owner signs an order
`{token, amount, recipient, nonce}`; anyone may relay it via `fillOrder`, which checks the
signature and then transfers `amount` of `token` to `recipient`. The bug is in
**`hashOrder`**: the digest it signs/verifies omits `amount` and `recipient`, so a signature
over a 10-token order to the marketplace is equally valid for a full-balance order to an
attacker.

## Your task

Fix **`hashOrder`** so that:

1. **The drain is blocked** - a signature made for one order cannot be replayed with a
   different `amount` or `recipient`.
2. **The feature still works** - a legitimately signed order settles for exactly its amount
   and recipient.

Keep the function **signatures unchanged** (`fillOrder(...)` and `hashOrder(...)`); the grader
calls both by name and arguments. Change only the body of `hashOrder`.

> Hint: the digest must commit to *everything the order authorizes*. If `amount` and
> `recipient` are not inside the hashed struct, the signature says nothing about them.

## Check your fix

```
ctf/ctf.sh solve signature-phishing
```

A hidden exploit test runs in Docker and reports a `security` and a `functionality` line.
You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
