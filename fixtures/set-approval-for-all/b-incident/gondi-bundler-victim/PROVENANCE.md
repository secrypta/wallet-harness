# Fixture provenance

```
Fixture:      set-approval-for-all/b-incident/gondi-bundler-victim
Vector:       set-approval-for-all
Tier:         b-incident
Split:        holdout
Expected:     vuln
Proof level:  INCIDENT-LEVEL (confirmed public tx + addresses, on-chain verified; minimized mechanism reproduction)

Origin:       Gondi NFT-lending platform drain, 2026-03-09 (~$230K, ~78 NFTs across ~40 attacker
              txs, Ethereum mainnet). Gondi is a peer-to-peer NFT lending protocol. A recently
              shipped "Purchase Bundler" (part of the Sell & Repay flow) exposed a `buy` entry point
              with NO `msg.sender` restriction; the bundled execution (`_buy`) then moved NFTs
              WITHOUT checking the caller's relation to them, and the internal `onlyLoanContract`
              guard on the post-transfer hook was bypassed because the chain started at the
              unrestricted `buy`. Many users had a standing `setApprovalForAll(bundler, true)` from
              legitimate use; the attacker called `buy` with crafted executionData naming those
              users' IDLE (non-collateral) NFTs, and the bundler pulled them with the victims'
              lingering operator approval and forwarded them to the attacker. NFTs locked as active
              loan collateral were not taken. No private keys were stolen. Gondi disabled the Sell &
              Repay feature and moved to make affected users whole.
```

## Confirmed on-chain identifiers (public, Ethereum mainnet)

- Example attack tx:   `0x83bac5d4b222b97f9734637c072589da648941b8a884ce1a61324dc0449e6a06`
- Attacker (EOA):      `0x8d171c74c85cd2ec9f38143dd5d8a7c89df47051` (labeled "GONDI Exploiter")
- Vulnerable bundler:  `0xe95e3cfc4939d6d98dbda31aafe950c3ee84d73c` (tx `to`)
- Example victim:      `0xfaa9dccf86f5cd4db872377c18368b5d58bc7b38`
- Example collection:  `0xfbeef911dc5821886e1dda71586d90ed28174b7d` (Art Blocks)
- Block:               24,618,641
- Timestamp:           2026-03-09 08:12:11 UTC

## On-chain verification (read-only JSON-RPC, publicnode; offline fixture - no live-contract calls)

- `eth_getTransactionByHash` -> `from` = attacker EOA `0x8d171c...`, `to` = bundler `0xe95e3c...`,
  `blockNumber` = `0x177a691` (24,618,641), `value` = 0.
- `eth_getBlockByNumber(0x177a691)` -> `timestamp` = 1773043931 = **2026-03-09T08:12:11Z**, which
  matches the ~08:12 UTC start reported by the write-ups.
- `eth_getTransactionReceipt` -> `status` = `0x1`; 78 ERC-721 `Transfer`
  (`0xddf252ad...`) logs. Per tokenId the flow is two hops:
  victim `0xfaa9dccf...` -> bundler `0xe95e3c...` -> attacker `0x8d171c...`
  (39 NFTs delivered to the attacker in this single tx), confirming the bundler pulled each NFT with
  the victim's standing operator approval and forwarded it to the caller. Example Art Blocks token
  ids in the pinned tx: 54218, 110378, 109977, 67494, 67493, ...

## Sources (independent, cross-checked; facts converge and match on-chain)

- The Block - "NFT platform Gondi moves to make users whole after $230,000 contract exploit":
  https://www.theblock.co/post/392909/nft-platform-gondi-moves-users-whole-230000-contract-exploit
  (Etherscan showed 78 NFTs drained across ~40 txs into an address labeled "GONDI Exploiter")
- Cointelegraph - "Gondi disables smart contract bug after $230K exploit":
  https://cointelegraph.com/news/nft-platform-gondi-secure-after-230k-hack
  (Gondi: the Sell & Repay contract was the affected component; one wallet lost ~$108K)
- Revoke.cash exploits database - Gondi entry:
  https://revoke.cash/exploits
  (flaw in the recently-updated Purchase Bundler; it let an attacker take NFTs from wallets that had
  approved it, unless the NFTs were in an active loan)
- AutoSec security-events writeup:
  https://blog.autosec.dev/security-events/NFT-lending-agreement-Gondi-was-hacked/
  (attacker's calls bypassed authorization checks and used users' historical approvals)
- Three Sigma-style technical breakdown (DEV Community, cryip) - root-cause detail:
  https://dev.to/cryip/gondi-nft-lending-platform-hack-a-detailed-report-489c
  (unrestricted `buy` in PurchaseBundler.sol; `_buy` ran without checking the caller; the
  `onlyLoanContract` guard on `_afterPrincipalTransfer` was bypassed; example tx cited above)

Note on a conflicting outlet: breakingblockchain.news framed the issue as a front-end vulnerability
with contracts "not breached". This is contradicted by Gondi's own statement (Sell & Repay contract
affected, per Cointelegraph), Revoke.cash (Purchase Bundler contract flaw) and AutoSec (on-chain
authorization bypass using historical approvals), plus the on-chain evidence above (the drain
executed through the bundler contract `0xe95e3c...` via `transferFrom` on victims' operator grants).
The contract-level account is adopted here.

## Why this is a legitimate addition (not a duplicate)

Distinct incident, protocol, year and code bug from the other `set-approval-for-all` b-incidents:
`monkeydrainer-victim` (2022 drainer-as-a-service), `nfttrader-operator-victim` (2023-12 reentrant
`editCounterPart`), `premint-operator-victim` (2022-07 front-end injection). Gondi is a 2026
unrestricted-entry-point / missing-caller-authorization bug in an NFT lending bundler. All share the
vector's root condition - a lingering `setApprovalForAll` operator grant abused to sweep NFTs - but
through different code paths.

## Fixture code

`../GondiBundlerClone.sol` + `test/GondiBundlerIncident.t.sol` are original MIT code authored in this
repo. They reproduce the documented mechanism only; no Gondi on-chain bytecode and no third-party PoC
code (DeFiHackLabs / write-ups, used as reference for facts, are not vendored) are copied. The test
derives the verdict from the real outcome (the victim's NFT ends up owned by the attacker).
