# Challenge: set-approval-for-all

**Vector:** set-approval-for-all - a blanket NFT operator approval lets a marketplace or
operator move the *entire* collection, not just the token you meant to list.

**The contract** (`src/Challenge.sol`) is a wallet holding NFTs #1, #2 and #3. It wants to
let an `operator` move a single `tokenId`. As written, it calls `setApprovalForAll`, which
hands the operator every token it owns.

## Your task

Fix `authorizeOperator` so that:

1. **The drain is blocked** - the operator cannot move any token other than the one it was
   authorized for.
2. **The feature still works** - the operator can still move the authorized `tokenId`.

Keep the function **signature unchanged** (`authorizeOperator(address nft, address operator,
uint256 tokenId)`). Change only the body.

> Hint: ERC-721 has a per-token approval as well as the collection-wide one.

## Check your fix

```
ctf/ctf.sh solve set-approval-for-all
```

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
