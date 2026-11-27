# Fixture provenance

```
Fixture:      signature-phishing/b-incident/rtfkt-seaport-victim
Vector:       signature-phishing
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)
Proof level:  INCIDENT-LEVEL (confirmed on-chain drain tx + addresses; minimized mechanism).

Origin:       RTFKT / CloneX "airdrop" phishing. An unsolicited fake RTFKT airdrop (delivered
              to ~883 addresses) lured holders to a site that asked them to sign what looked
              like a routine step. The signature was actually a BULK of Seaport private-listing
              orders selling the victim's CloneX NFTs to the attacker's taker for 0 ETH. A
              relayer bulk-fulfilled the signed orders and the NFTs left the victim ~1 minute
              after signing - no transaction sent by the victim. The holder had, like most
              who ever listed on OpenSea, already granted the marketplace operator approval;
              authority to move each tokenId then came purely from the victim's EIP-712 order
              signatures. This is the signature-phishing (order-signature) vector, distinct
              from the fake-airdrop vector (whose end state is an approval/permit on the real
              asset) - here the drain is the Seaport order signature itself.

Confirmed on-chain identifiers (Ethereum mainnet, verified via read-only RPC eth_getTransactionByHash / eth_getBlockByNumber):
              - Drain tx:        0xbf2542540ce22abe7a1822e15d67a50b73a7ba18e036bb305103e51606122b69
              - Block:           16143133, timestamp 2022-12-08 22:59:59 UTC, status success, 165 logs
              - to (Seaport 1.1): 0x00000000006c3852cbef3e08e8df289169ede581
              - selector:        0xa8174404 = fulfillAvailableAdvancedOrders (Seaport bulk fill)
              - from (relayer/originator): 0x4574043b6423953723356237042bf6df2304f297
              - Assets taker:    0xc0fdf4fa92f88b82ccbebfc80fbe4eb7e5a8e0ca
              - Example victim:  0xabeaa3375534d2931b2149067af3e7b8458d2f0c
              NOTE: the on-chain drain is dated 2022-12-08. Some write-ups mention "Dec 2021";
              that refers to the ORIGINAL legitimate RTFKT airdrop announcement, not this
              phishing drain. The 2022-12-08 date is taken from the block timestamp on-chain.

Reference (independent, authoritative - cross-checked, >= 2 sources + on-chain):
              - Scam Sniffer, "NFT airdrop phishing: a case study of how the victims are
                targeted and scam is conducted":
                https://drops.scamsniffer.io/nft-airdrop-phishing-case-study-how-the-victims-are-targeted-and-scam-is-conducted/
                (names the victim/attacker/taker addresses and the drain tx above; ~21 CloneX,
                ~168 ETH).
              - Harpie (blockchain security firm), reported via Cointelegraph, "New NFT private
                auction scam threatens OpenSea users" (Dec 2022): describes the same mechanism -
                a gas-free Seaport signature posing as a login step that is actually a private
                sale of the victim's NFTs to the scammer for 0 ETH.
                https://cointelegraph.com/news/new-nft-private-auction-scam-threatens-opensea-users
              - On-chain confirmation (this repo): the tx/addresses/date/selector above were
                read directly from Ethereum mainnet and match the Scam Sniffer account.

Source code:  ../SeaportBulkExchange.sol (authored minimized model, this repo, MIT). It is NOT
              a copy of Seaport's source; it models only the EIP-712 signed-order verification +
              zero-price settlement + bulk NFT transfer surface needed to replay the vector.
License:      MIT (this repo). No third-party marketplace code copied.

Minimization / honest scope:
              Pattern-level reproduction anchored to the on-chain-confirmed incident above.
              - EIP-712 requires a valid offerer signature; the real victim's private key is
                (rightly) not public, so the offerer is a key-derived stand-in (vm key 0xC10E)
                and the taker is a symbolic address. The incident tx/addresses are cited and
                on-chain-verified; the signature itself is reproduced, not replayed.
              - Seaport's full advanced-order model (zones, conduits, criteria, considerations)
                is reduced to the one element that carries the vector: a bulk of blind-signed
                private-listing orders authorizing NFT transfers to the attacker for 0 ETH.
Offline:      committed minimized model; no mainnet fork, no live RPC used in the test. The
              on-chain verification above was a read-only lookup, not a live-contract test.
              Built/run in Docker.
Notes:        test/RtfktSeaportIncident.t.sol: the victim grants routine operator approval,
              blind-signs a bulk of zero-price orders, the relayer bulk-fulfills them, and the
              whole collection changes owner to the taker while the victim receives 0 ETH; the
              verdict is derived from that real outcome. Expected verdict: VULNERABLE (TP).
```
