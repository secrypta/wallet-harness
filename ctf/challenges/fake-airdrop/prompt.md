# Challenge: fake-airdrop

**Vector:** fake-airdrop - an unsolicited "gift" token lures the victim into a claim flow
that does not actually act on the gift. The distinctive signal is the **mismatch**: the
asset the claim approves is not the worthless gift you think you are unlocking, but your
**real, valuable** holdings - which an attacker then drains.

**The contract** (`src/Challenge.sol`) is a wallet that received an unsolicited `giftToken`.
To "finalize" the claim, a `claimHelper` needs permission to move the gift token. As written,
`claimGift` also approves the helper on the wallet's **real asset** - so the helper can walk
off with the valuable balance while the gift sits untouched.

## Your task

Fix `claimGift` so that:

1. **The drain is blocked** - the claim must not grant the helper any spendable allowance on
   the real asset.
2. **The feature still works** - the helper can still move the `giftToken` to finalize the
   claim.

Keep the function **signature unchanged** (`claimGift(address giftToken, address realToken,
address claimHelper)`); the grader calls it exactly like that. Change only the body.

> Hint: a legitimate claim only ever needs to touch the thing being claimed. Approving
> nothing at all would stop the drain but also break the claim - the grader checks both
> sides. Approve the *gift*, not the *real asset*.

## Check your fix

```
ctf/ctf.sh solve fake-airdrop
```

A hidden exploit test runs in Docker and reports a `security` and a `functionality` line.
You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
