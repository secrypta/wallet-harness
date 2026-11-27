# Challenge: Patch the Hedgey Finance stale-approval drain

**Incident.** Hedgey Finance ClaimCampaigns drain, 2024-04-19 (~$44.7M; ETH attack tx
`0x2606d459...595739`, block 19687890, moved 1,303,910.12 USDC). `createLockedCampaign` granted a
standing ERC-20 approval to a campaign-supplied "locker" address that was **never validated**,
and when a campaign was cancelled the contract returned the campaign's own deposit but **did not
revoke** that approval. The residual, unrevoked allowance let the attacker's contract
`transferFrom` the ClaimCampaigns contract's **pooled balance** - funds from other campaigns.

**Vector:** approve-drainer - a standing/stale approval to an attacker-controlled spender,
drained by `transferFrom`.

**The contract** (`src/Challenge.sol`) is the minimized ClaimCampaigns contract. On create it
approves the (unvalidated) `locker` for the campaign amount. On cancel it refunds the creator -
but leaves the approval standing. The locker is already recorded per campaign for you.

## Your task

Fix `cancelCampaign` so that:

1. **The drain is blocked** - after a campaign is cancelled, its locker can no longer move the
   contract's pooled balance (the standing approval must not survive the cancel).
2. **The feature still works** - cancelling a campaign still refunds the creator's own deposit.

Keep the function **signature unchanged** (`cancelCampaign(bytes16 id)`); the grader calls it
exactly like that. Change only the body. The campaign's `locker` is available as
`campaigns[id].locker`.

> Hint: the deposit is returned, but something granted at create-time is never undone here.
> Making cancel revert would stop the drain but also break the refund - the grader checks both
> sides.

## Check your fix

```
ctf/ctf.sh solve approve-drainer-hedgey
```

A hidden exploit test runs in Docker: an attacker creates a campaign with their own contract as
locker, cancels it, then tries to drain the pooled balance via the leftover approval - while a
legitimate creator cancels and must still get their deposit back. You pass only when the
`security` and `functionality` lines are both OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable, minimized reproduction of a real
> incident for training - it runs only offline in Docker. Never deploy it to a real network.
