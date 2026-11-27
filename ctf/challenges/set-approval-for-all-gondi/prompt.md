# Challenge: Patch the Gondi Purchase Bundler drain

**Vector:** set-approval-for-all - real incident. On **2026-03-09** the Gondi NFT-lending
platform was drained (**~$230K, ~78 NFTs** across ~40 txs, Ethereum mainnet). Many users held
a standing `setApprovalForAll(bundler, true)` from legitimate "Sell & Repay" use. A newly
shipped **Purchase Bundler** exposed a `buy` entry point with **no `msg.sender` restriction**:
the attacker called it naming *other users'* idle NFTs, and the bundler dutifully pulled them
with the victims' lingering operator approval and forwarded them to the attacker. (Example tx
`0x83bac5...6a06`, block 24618641.)

**The contract** (`src/Challenge.sol`) is that bundler. `buy` pulls `tokenId` of `nft` from
`nftOwner` (who has a standing operator approval to the bundler) and sends it to `recipient`.
Because it never checks who is calling, anyone can drain any approving owner's NFTs.

## Your task

Fix `buy` so that:

1. **The drain is blocked** - a caller cannot pull NFTs belonging to someone else via that
   someone's standing operator approval.
2. **The feature still works** - an owner can still route *their own* NFT through the bundler
   to a recipient (the legitimate Sell & Repay flow).

Keep the function **signature unchanged** (`buy(address nft, uint256 tokenId, address nftOwner,
address recipient)`); the grader calls it exactly like that. Change only the body.

> Hint: the standing operator approval makes the bundler *able* to move the owner's NFT - so
> the bundler itself must decide *who is allowed to ask it to*. Dropping the transfer entirely
> would stop the drain but also break the legitimate flow; the grader checks both sides.

## Check your fix

```
ctf/ctf.sh solve set-approval-for-all-gondi
```

A hidden exploit test runs in Docker and reports a `security` and a `functionality` line.
You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture modeled on a
> public incident - it runs only offline in Docker. Never deploy it to a real network.
