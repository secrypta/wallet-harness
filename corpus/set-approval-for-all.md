# Vector: set-approval-for-all (NFT operator-for-all)

**Class:** token-allowance abuse (NFT) - **Chain:** EVM (ERC-721 / ERC-1155) - **Severity:** critical (whole-collection loss)
**Prior art:** NDSS'25 cat I-C (ice phishing: SetApprovalForAll); DASP-10 nearest: Access Control.

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** the NFT analogue of [[approve-drainer]]; reached by the same delivery vectors ([[fake-airdrop]], [[malicious-calldata]]). Distinct only in the token standard and the blanket-operator sink.

## What it is
ERC-721/1155 offer two very different ways to let someone else move your NFTs:
- `approve(operator, tokenId)` - **scoped** authority over exactly one token, cleared
  when that token transfers.
- `setApprovalForAll(operator, true)` - a **blanket, standing** authority over *every*
  token the owner holds, present and future, until explicitly revoked.

Marketplaces and dApps routinely request `setApprovalForAll` "to enable trading" even
when the immediate action touches a single token. A malicious or compromised operator can
then transfer the owner's **entire** collection at any later time - the authority is
standing, off-screen, and survives until revoked.

The danger is not the approval transaction itself but the **persistent, collection-wide,
third-party authority** it leaves behind. This is the NFT analogue of the unlimited
ERC-20 approve ([[approve-drainer]]): `setApprovalForAll` is to NFTs what
`approve(spender, type(uint256).max)` is to fungible tokens.

## Attack mechanics
1. Victim is induced to call `NFT.setApprovalForAll(operator, true)` (a fake "enable
   trading", "claim", "verify collection", or airdrop lure - see [[fake-airdrop]]).
2. `isApprovedForAll(victim, operator)` is now `true` for the whole collection. No
   per-token prompt, no amount, no expiry - one call covers all tokens, including ones
   minted later.
3. Any time afterwards, the operator (not the victim's wallet) sweeps the collection:
   for each `tokenId`, `NFT.transferFrom(victim, attacker, tokenId)` succeeds because the
   operator-for-all check passes. The whole collection leaves in a single transaction.

Key property for detection: the loss is bounded by the **scope of the authority granted**,
not by anything the victim does at sweep time. A per-token `approve` caps the loss to that
one token; `setApprovalForAll` caps it at "the entire collection, forever".

## Defensive signal (what a harness / wallet policy should catch)
A protected flow MUST surface at least one of:
- **Operator-for-all flag:** a `setApprovalForAll(operator, true)` to an operator that is
  not a known-trusted contract - blanket collection authority where the action needs one
  token.
- **Scoped authority:** authorize only the token the current action needs
  (`approve(operator, tokenId)`); no standing authority over the rest of the collection.
- **Standing-authority audit:** existing `isApprovedForAll` grants to arbitrary operators
  are discoverable and revocable (set back to `false`).

A protected target is one where the drain path is **not reachable** for the victim's
other assets - the authority was scoped to a single token, so `transferFrom` of any other
token reverts.

## Repro (toy targets - proven by test body, not prose)
- **Vulnerable target:** a toy ERC-721 + a `MaliciousOperator`. The wallet needs an
  operator for ONE token but grants `setApprovalForAll(operator, true)`. The operator
  sweeps 100% of the collection. Harness MUST report
  `set-approval-for-all: VULNERABLE`.
- **Protected target:** same flow but the wallet grants `approve(operator, actionTokenId)`
  on exactly the one token the action needs. The operator's attempt to sweep the other
  tokens reverts; the victim keeps every non-scoped token. Harness MUST report
  `set-approval-for-all: BLOCKED` with **zero false positives**.

**0-false-positive rule (important):** a wallet counts as "drained" only if a token
*other than the one legitimately scoped* leaves it. Moving the single in-scope token is
authorized by design and is NOT a drain - otherwise the protected target would be falsely
flagged. The test also includes a guard proving the scoped `approve` is genuinely usable
for its one token (so BLOCKED means "vector stopped", not "operator had no authority").

Validation bar (same as the project invariant): the harness fires on the vulnerable
target and stays silent on the protected one. The vector is proven by the test body,
never by this description.

## Real-case validation (required beyond toy)
All three tiers are shipped and benchmarked (same validation standard, [[real-cases]]): (a) the toy pair above; (b) a minimized reproduction of a real, public NFT operator-for-all drain (harness flags it); and (c) a genuinely safe real implementation (harness stays silent). Offline committed fixtures with provenance only - no live contracts.

> **Independent holdout (`split=holdout`):** `nfttrader-operator-victim` - the NFTTrader.org operator-approval drain (2023-12), an independent real-incident `b` case scored on the holdout split. See [[real-cases]] and `bench/README.md`.

Real-incident `b` cases for this vector: `monkeydrainer-victim` (Monkey Drainer phishing-as-a-service, 2022), `nfttrader-operator-victim` (NFTTrader.org reentrant settlement, 2023-12, fully tx-pinned), and `premint-operator-victim` - the **PREMINT** front-end injection (2022-07-17, ~275 ETH / ~$375K): injected JS presented a fake "wallet verification" whose real call was `setApprovalForAll` (selector `0xa22cb465`) to an attacker operator, which then swept victims' collections. Attacker EOA `0x0C9797805a22E507Bf48F35C72A67f001b7418d0` cross-confirmed by Beosin + CertiK + on-chain. See its `PROVENANCE.md`. A fourth, code-level case is `gondi-bundler-victim` - the **Gondi** NFT-lending "Purchase Bundler" drain (2026-03-09, ~$230K / ~78 NFTs across ~40 txs, Ethereum): the updated bundler exposed an unrestricted `buy` whose bundled execution never checked the caller's relation to the moved NFTs, so the attacker named victims' idle NFTs and the bundler pulled them through the victims' lingering `setApprovalForAll(bundler, true)` and delivered them to the attacker. Attacker EOA `0x8d171c74c85cd2ec9f38143dd5d8a7c89df47051`, bundler `0xe95e3cfc4939d6d98dbda31aafe950c3ee84d73c`, example tx `0x83bac5d4b222b97f9734637c072589da648941b8a884ce1a61324dc0449e6a06` (block 24,618,641) - on-chain verified (victim -> bundler -> attacker per tokenId) and cross-checked against The Block / Cointelegraph / Revoke.cash / AutoSec. See its `PROVENANCE.md`. A fifth code-level case is `magic-eden-pp2-victim` - the **Magic Eden / Limit Break "Payment Processor V2"** drain (2026-09-24, ~$2.8M; WETH + NFTs across Ethereum/Polygon/Base/..): the non-upgradeable processor handled ERC-2771 meta-transactions and trusted a forwarder-appended sender without authenticating it, so the attacker spoofed victims as the party that "agreed" to a zero-price trade and the processor pulled their NFTs through their lingering `setApprovalForAll(processor, true)` (left over from 2024 listings). Attacker EOA `0x0e9e147af2108e5354efb28740cade8e7422d1c7`, PP V2 `0x9A1D00bEd7CD04BCDA516d721A596eb22Aac6834`, example tx `0x9050e28ed880a960ddaa248373c104e41fa847cde7a3774d003a71c2f74193d3` (block 26,047,513) - on-chain verified (70 ERC-721 transfers victim -> attacker, 140 processor logs) and cross-checked against The Block / Revoke.cash / Cryptopolitan / Cryptotimes / 0xQuit. See its `PROVENANCE.md`.

Real-safe `c` holdouts for this vector: `oz-safe-operator` + `solady-erc721-safe` (ERC-721), and `oz-erc1155-safe` - the real OpenZeppelin v5.1.0 `ERC1155` operator-for-all surface: an un-approved operator's `safeBatchTransferFrom` sweep reverts in OZ's own `isApprovedForAll` check (BLOCKED), a different token standard the detector was never tuned against. See its `PROVENANCE.md`. `solady-erc1155-safe` adds the ERC-1155 operator-for-all surface on the independent Solady codebase (closing the {Solady}×{ERC-1155} cell): an un-approved operator's `safeTransferFrom` sweep reverts `NotOwnerNorApproved` (BLOCKED). See its `PROVENANCE.md`. `oz-erc721-operator-safe` fills the {OpenZeppelin}x{ERC-721} operator-for-all holdout cell: an operator never granted `setApprovalForAll` cannot sweep the holder's tokens (`ERC721InsufficientApproval`, BLOCKED). See its `PROVENANCE.md`. `erc721a-operator-safe` (round 6) adds a THIRD, independent ERC-721 codebase - ERC721A v4.3.0 (Chiru Labs, MIT), widely deployed across NFT collections with a materially different internal design (packed sequential ownership + batch mint): an operator never granted `setApprovalForAll` cannot sweep the holder's tokens (`TransferCallerNotOwnerNorApproved`, BLOCKED), real wild code the detector was never tuned against. See its `PROVENANCE.md`.

## Source base
Built fresh from a toy ERC-721 (`src/MockERC721.sol`) and a `MaliciousOperator`, modelled
on the [[approve-drainer]] vector's structure (vulnerable/safe wallet policy + a malicious
counterparty + a probe test that derives the verdict from the real on-chain outcome).
Draft of this spec authored by wal B from the task brief; edited by M. Related vectors:
[[approve-drainer]], [[permit-phishing]], [[fake-airdrop]].
