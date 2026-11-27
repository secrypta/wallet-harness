# Challenge: malicious-calldata

**Vector:** malicious-calldata - the user approves a transaction by its *presented* intent
("pay the merchant"), but the raw **calldata**'s real effect is something else: a transfer
to the attacker, or for far more than intended. The label is cosmetic; the calldata is the
truth.

**The contract** (`src/Challenge.sol`) is a payments wallet. Its one sanctioned action is to
pay its fixed `merchant` up to `maxPayment` of a token. It does this by executing a piece of
calldata against the token. As written, `execute` runs **whatever calldata it is handed**
without decoding it - so calldata that reads as `transfer(attacker, entireBalance)` drains
the wallet just as readily as the intended `transfer(merchant, amount)`.

## Your task

Fix `execute` so that:

1. **The drain is blocked** - calldata whose real effect is a transfer to anyone other than
   the sanctioned `merchant`, or for more than `maxPayment`, must be rejected.
2. **The feature still works** - a legitimate `transfer(merchant, amount)` for
   `amount <= maxPayment` must still go through.

Keep the function **signature unchanged** (`execute(address target, bytes data)`); the grader
calls it exactly like that. Change only the body.

> Hint: don't trust the *presented* action - decode the calldata and check its *real* effect.
> The first 4 bytes are the selector; the rest are the ABI-encoded arguments. `token`,
> `merchant` and `maxPayment` are exposed as public immutables. Rejecting everything stops
> the drain but breaks the merchant payment - the grader checks both.

## Check your fix

```
ctf/ctf.sh solve malicious-calldata
```

A hidden exploit test runs in Docker and reports a `GATE` verdict with a `security` and a
`functionality` line. You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
