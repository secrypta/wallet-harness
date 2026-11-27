# Challenge: Patch the NFTTrader reentrant swap drain

**Vector:** set-approval-for-all - real incident. On **2023-12-16** the NFTTrader.org peer-to-peer
swap marketplace was drained (**~$3M**). Many users held a standing
`setApprovalForAll(marketplace, true)` from earlier legitimate swaps. Settlement mutated swap
state through a counterparty-editing path that had **no reentrancy protection** and was
reachable from inside an ERC-721 transfer callback fired mid-settlement. The attacker opened a
swap of their own NFT and, during settlement, **re-entered to set a victim as the counterparty**;
the marketplace then pulled the victim's NFTs with the victim's lingering operator approval.
(Real tx `0xec7523...b393d`, block 18799488.)

**The contract** (`src/Challenge.sol`) is that marketplace. `completeSwap` transfers the
opener's NFT to the counterparty (via `safeTransferFrom`, which calls the recipient back) and
then pulls the counterparty's NFT to the opener. Because it re-reads the counterparty from
storage **after** the callback, a reentrant `editCounterparty` call can swap in a victim before
the second leg runs.

## Your task

Fix `completeSwap` so that:

1. **The drain is blocked** - a reentrant mid-settlement change of the counterparty cannot
   redirect the second transfer onto a victim.
2. **The feature still works** - a normal swap between two consenting parties still completes
   (both NFTs change hands).

Keep the function **signature unchanged** (`completeSwap(uint256 swapId)`); the grader calls it
exactly like that. Change only the body.

> Hint: the counterparty read *after* the external callback is attacker-controlled. Decide who
> the counterparty is *before* you make the call that can re-enter, and act on that decision.
> (Classic checks-effects-interactions.)

## Check your fix

```
ctf/ctf.sh solve set-approval-for-all-nfttrader
```

A hidden exploit test runs in Docker and reports a `security` and a `functionality` line.
You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture modeled on a
> public incident - it runs only offline in Docker. Never deploy it to a real network.
