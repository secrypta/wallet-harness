# Challenge: address-poisoning

**Vector:** address-poisoning - wallets show addresses truncated (`0x1234...cdef`), and users
often copy a destination from their **transaction history**. An attacker plants a look-alike
vanity address (same truncated prefix/suffix as a real counterparty, different in the middle)
in the victim's history via a zero-value or dust transfer. Later the victim copies the
poisoned address - it "looks right" - and sends real funds straight to the attacker.

**The contract** (`src/Challenge.sol`) is a wallet that keeps an address book of verified
counterparties (`trust(...)`) and sends tokens with `send`. As written, `send` transfers to
**whatever destination it is handed**, so a poisoned look-alike pulled from history is paid
just like a real counterparty.

## Your task

Fix `send` so that:

1. **The drain is blocked** - a destination that is not a verified counterparty (e.g. a
   look-alike planted in history) cannot be paid.
2. **The feature still works** - a verified counterparty can still be paid up to `amount`.

Keep the function **signature unchanged** (`send(address token, address to, uint256 amount)`);
the grader calls it exactly like that. Change only the body. The verified address book
(`verified` / `trust`) is already there for you to use.

> Hint: compare the *full* destination against the verified book, never a truncated form.
> Rejecting every send would stop the drain but also break the feature - the grader checks
> both sides.

## Check your fix

```
ctf/ctf.sh solve address-poisoning
```

A hidden exploit test runs in Docker: it trusts a real counterparty, then tries to pay a
poisoned look-alike that was never verified, and separately pays the verified counterparty.
You pass only when the `security` and `functionality` lines are both OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
