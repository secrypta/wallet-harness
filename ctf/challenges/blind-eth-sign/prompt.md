# Challenge: blind-eth-sign

**Vector:** blind-eth-sign - the wallet acts on an **opaque 32-byte hash** that the caller
hands it, instead of a digest derived from the action itself. The owner was tricked into
blind-signing that hash (it looked like an innocuous "verify" step); because the contract
never checks that the hash commits to *what is actually executed*, the same signature
authorizes any transfer an attacker names.

**The contract** (`src/Challenge.sol`) lets the owner authorize a transfer by signature:
`executeWithSig(signedHash, sig, to, amount, nonce)` recovers the signer from `signedHash`
and, if it is the owner, sends `amount` of the wallet's asset to `to`. The bug is that
`signedHash` is supplied by the caller and is **never tied to `(to, amount, nonce)`** - so a
signature the owner produced once can be replayed with an attacker's `to`/`amount`.

## Your task

Fix `executeWithSig` so that:

1. **The drain is blocked** - a signature cannot authorize a transfer whose `to`/`amount`
   the signer did not actually commit to.
2. **The feature still works** - the owner's authorized transfer (the exact `to`/`amount`
   the owner signed for) still executes.

Keep the function **signature unchanged**; the grader calls it by this name and arguments.
Change only the body. The contract already exposes `actionDigest(to, amount, nonce)` - the
structured digest the signature *should* be checked against.

> Hint: never trust a digest handed to you by the caller. Derive the digest from the action
> (`actionDigest(to, amount, nonce)`) and verify the signature against *that*. The
> `signedHash` argument should stop mattering.

## Check your fix

```
ctf/ctf.sh solve blind-eth-sign
```

A hidden exploit test runs in Docker and reports a `security` and a `functionality` line.
You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
