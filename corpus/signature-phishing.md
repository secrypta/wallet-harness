# Vector: signature-phishing (blind eth_sign / malicious typed-data)

**Class:** off-chain signature abuse - **Chain:** EVM - **Severity:** critical
**Prior art:** NDSS'25 cat II (NFT order scam - malicious order/free-buy params); DASP-10 nearest: Access Control.

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** shares the off-chain-signature surface with [[blind-eth-sign]] (raw hash) and [[permit-phishing]]/[[permit2-phishing]] (allowance signatures). Detection naturally spans this whole off-chain-signature family rather than one rule per spec.

## What it is
A wallet can sign off-chain messages that later authorize on-chain asset movement without
a separate transaction. Two dangerous shapes:
- **Blind `eth_sign`** of an arbitrary 32-byte hash - the user sees opaque hex, not a
  human-readable intent. That hash can be a transaction digest or an order the attacker
  then submits.
- **Malicious EIP-712 typed-data** - a structured message (e.g. a Seaport order, a bulk
  listing, a `PermitBatch`) that *looks* routine but authorizes transferring the user's
  assets to the attacker. One signature can cover many assets.

Distinct from [[permit-phishing]] (which is specifically EIP-2612 token allowance): this
vector is the broader "a signature, not a transaction, drained me" class - marketplace
order signatures and blind hashes.

## Attack mechanics
1. Phishing UI asks the victim to "sign to connect / verify / list" - producing either a
   blind `eth_sign` over a prepared digest, or a typed-data order granting the attacker the
   right to move the victim's tokens/NFTs.
2. The attacker submits the signature to the relevant contract (marketplace/settlement),
   which transfers the assets. The victim never sent a transaction.

## Defensive signal (what a harness / wallet policy should catch)
- **No blind `eth_sign`:** signing an opaque hash with no decodable intent is the flag;
  safe wallets refuse or hard-warn on raw `eth_sign`.
- **Decode typed-data:** surface what an EIP-712 order actually authorizes (assets, amounts,
  recipient, which marketplace), and flag bulk/`forAll`/all-asset orders to unknown parties.
- **Protected target:** signs only decodable, scoped messages to known settlement contracts
  - a blind hash or an all-asset order to an untrusted party is rejected, so the attacker's
  settlement reverts / has no authorization.

## Repro (toy targets - proven by test body)
Model a minimal settlement contract that executes a signed order (verify EIP-712 / recover
`eth_sign` hash, then move assets), + a `MaliciousRelayer`.
- **Vulnerable target:** wallet blind-signs the attacker's order/hash -> relayer settles and
  moves 100% -> `signature-phishing: VULNERABLE`.
- **Protected target:** wallet signs only a decodable, scoped order to a known settlement
  (or refuses the blind hash) -> the attacker's all-asset settlement reverts, assets intact ->
  `signature-phishing: BLOCKED`, 0 false positives. Guard: the scoped order is genuinely
  settleable, so BLOCKED means "vector stopped", not "signature invalid".

Verdict line: `[signature-phishing] target=<name> verdict=VULNERABLE|BLOCKED`.

## Real-case validation (required beyond toy - see [[real-cases]])
(b) Headline Seaport/Wyvern order-signature incidents reserved for this vector:
- `seaport-order-victim` - OpenSea migration phishing (Feb 2022) and Kevin Rose / Moonbirds
  (Jan 2023); victims signed off-chain orders, not a plain `setApprovalForAll`.
- `rtfkt-seaport-victim` - RTFKT / CloneX Seaport **bulk** private-listing phishing
  (2022-12-08). On-chain-confirmed drain tx `0xbf2542...122b69` to Seaport 1.1
  (`fulfillAvailableAdvancedOrders`, selector `0xa8174404`), ~21 CloneX / ~168 ETH; the
  victim blind-signed a bulk of zero-ETH private listings to the attacker's taker. Sources:
  Scam Sniffer case study + Harpie (via Cointelegraph) + on-chain. See its `PROVENANCE.md`.

(c) A canonical marketplace settlement (e.g. Seaport reference) used with a scoped, decodable
order the harness stays silent on. Offline committed fixtures with provenance only.

> **No independent *vulnerable* holdout** for this vector - precision-side only. The
> independent (`split=holdout`) case is real safe code the detector must stay silent on:
> `solady-erc1271-safe` (Solady ERC-1271 / ERC-7739 nested EIP-712, 0 FP) and
> `oz-sigchecker-safe` (real OpenZeppelin v5.1.0 `SignatureChecker`, the ERC-1271-aware canonical
> path - a forged signature is rejected, 0 FP). The one incident examined for a vuln holdout
> (Bebop JamSettlement) turned out to carry no victim signature and was relabelled
> `malicious-calldata`. A third safe holdout, `oz-erc2771-forwarder-safe`, covers the canonical
> ERC-2771 **meta-transaction** relay path (real OpenZeppelin v5.1.0 `ERC2771Forwarder`): a
> forged `ForwardRequest` claiming `from = victim` but signed by the attacker is rejected
> (`ERC2771ForwarderInvalidSigner`), 0 FP. A fourth, `solady-erc4337-userop-safe`, covers the
> canonical ERC-4337 account-abstraction userOp-validation surface (real Solady `ERC4337` via
> `ERC4337Factory`): a userOp whose signature was forged by a non-owner fails `_validateSignature`
> (returns 1), so the EntryPoint never executes it, 0 FP. See `bench/README.md`.

## Source base
New toy settlement + relayer (English, no external libs where feasible; if a reference
settlement is vendored for (c), keep its license + provenance). Related:
[[permit-phishing]], [[approve-drainer]], [[malicious-calldata]].
