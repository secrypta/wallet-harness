# Fixture provenance

```
Fixture:      set-approval-for-all/b-incident/magic-eden-pp2-victim
Vector:       set-approval-for-all
Tier:         b-incident
Split:        holdout
Expected:     vuln
Proof level:  INCIDENT-LEVEL (confirmed public tx + addresses, on-chain verified; minimized mechanism reproduction)

Origin:       Magic Eden / Limit Break "Payment Processor V2" drain, 2026-09-24 (~$2.8M total across
              chains; ~622 WETH + smaller tokens + NFTs worth $2.5M+; Ethereum, Polygon, Base,
              Arbitrum, ApeChain and others). Payment Processor V2 is a non-upgradeable trading
              contract built by Limit Break and used by Magic Eden in 2024; many wallets still held a
              standing `setApprovalForAll(processor, true)` (and WETH approvals) from listing then,
              even though Magic Eden stopped using it in October 2024. ROOT CAUSE: the contract
              handled meta-transactions via an ERC-2771-style trusted-forwarder pattern and TRUSTED
              the sender address appended to calldata by an approved forwarder WITHOUT authenticating
              it, so a caller routing through the trusted forwarder could spoof the acting party to be
              any victim. The attacker spoofed a victim as the counterparty who "agreed" to a
              zero-price trade; the processor then pulled the victim's NFTs with the victim's lingering
              operator approval and delivered them to the attacker. Victims signed nothing during the
              attack. V2 could not be paused or fixed. White-hats (0xQuit / Yuga Labs) used the same
              flaw to move 23,155+ NFTs (>$5.7M) into safekeeping.
```

## Confirmed on-chain identifiers (public, Ethereum mainnet)

- Example attack tx:   `0x9050e28ed880a960ddaa248373c104e41fa847cde7a3774d003a71c2f74193d3`
                       (deploy-and-drain; `to` = null / contract creation)
- Attacker (EOA):      `0x0e9e147af2108e5354efb28740cade8e7422d1c7` (the drained NFTs' `to`)
- Attacker contract:   `0x74002203ddfce44e5514b3945db4db17948c6d8e` (created in the tx)
- Payment Processor V2: `0x9A1D00bEd7CD04BCDA516d721A596eb22Aac6834` (appears in 140 logs of the tx)
- Example victim:      `0xddf2163205e63c5b17c81647be1b73f918535d38`
- Example collection:  `0x790b2cf29ed4f310bf7641f013c65d4560d28371`
- Block:               26,047,513
- Timestamp:           2026-09-24 13:07:59 UTC

## On-chain verification (read-only JSON-RPC, publicnode; offline fixture - no live-contract calls)

- `eth_getTransactionByHash` -> `from` = attacker EOA `0x0e9e14...`, `to` = null (contract creation),
  `blockNumber` = `0x18d7419` (26,047,513), `value` = 0.
- `eth_getBlockByNumber(0x18d7419)` -> `timestamp` = **2026-09-24T13:07:59Z**, matching the reported
  Sept 24, 2026 start of the exploit.
- `eth_getTransactionReceipt` -> `status` = `0x1`; created contract `0x74002203...6d8e`; 220 logs;
  140 of them emitted by Payment Processor V2 `0x9a1d00...6834` (the drain ran THROUGH the processor);
  70 ERC-721 `Transfer` (`0xddf252ad...`) logs for collection `0x790b2cf2...`, each
  `from` victim `0xddf2163205e63c5b17c81647be1b73f918535d38` -> `to` attacker
  `0x0e9e147af2108e5354efb28740cade8e7422d1c7`. This confirms the processor pulled the victim's NFTs
  with the victim's standing operator approval and delivered them to the attacker. Example token ids:
  10231, 10574, 18785, 21172, 23068, 23828, ...

## Sources (independent, cross-checked; facts converge and match on-chain)

- The Block - "Magic Eden legacy approvals leave $5.7 million in NFTs exposed to exploit before rescue":
  https://www.theblock.co/news/web3/2026-09-25-magic-eden-legacy-approvals-leave-5-7-million-in-nfts-exposed-to-exploit-before-rescue-416874
- Revoke.cash exploits database - Magic Eden / Limit Break entry (lists chains, amounts, the tx above
  in its sources): https://revoke.cash/exploits/magic-eden?chainId=1
- Cryptopolitan - "Magic Eden users can now reclaim NFTs rescued from Payment Processor exploit":
  https://www.cryptopolitan.com/magic-eden-users-can-now-reclaim-nfts/
- Cryptotimes - "Limit Break NFT Exploit: Yuga Labs' Quit Rescues 23,155 NFTs, Says 660 WETH Lost"
  (PP V2 address `0x9A1D00bEd7...6834`):
  https://www.cryptotimes.io/2026/09/25/limit-break-nft-exploit-yuga-labs-quit-rescues-23155-nfts-says-660-weth-lost/
- 0xQuit (Yuga Labs) technical breakdown - the forwarder-spoofing root cause and the white-hat
  rescue (widely cited across the above outlets).

## Why this is a legitimate addition (not a duplicate)

Distinct incident, contract, year and code bug from the other `set-approval-for-all` b-incidents:
`monkeydrainer-victim` (2022 drainer-as-a-service), `nfttrader-operator-victim` (2023-12 reentrant
`editCounterPart`), `premint-operator-victim` (2022-07 front-end injection), `gondi-bundler-victim`
(2026-03 unrestricted bundler entry). Magic Eden PP V2 is a 2026-09 ERC-2771 trusted-forwarder
sender-spoof. All share the vector's root condition - a lingering `setApprovalForAll` operator grant
abused to sweep NFTs - but through different code paths. Independent of the signature-phishing cases.

## Fixture code

`../PaymentProcessorClone.sol` + `test/MagicEdenPaymentProcessorIncident.t.sol` are original MIT code
authored in this repo. They reproduce the documented mechanism only (an ERC-2771-style spoofable
`_msgSender()` + settlement via a standing operator approval); no Payment Processor on-chain bytecode
and no third-party PoC code are copied. The test derives the verdict from the real outcome (the
victim's NFT ends up owned by the attacker).
