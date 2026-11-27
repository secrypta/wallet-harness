# Fixture provenance

```
Fixture:      signature-phishing/b-incident/seaport-order-victim
Vector:       signature-phishing
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)

Origin:       Off-chain marketplace order-signature phishing (Seaport / Wyvern), where
              victims signed an off-chain order (NOT a plain setApprovalForAll) and a
              relayer/taker fulfilled it, sweeping their NFTs.
Reference:    - OpenSea migration phishing, Feb 2022: users signed malicious off-chain
                Wyvern orders during the Wyvern->Seaport migration; ~$1.7M of NFTs moved.
                Widely documented (OpenSea statements; mainstream + security press).
              - Kevin Rose / Moonbirds, Jan 2023: the victim signed a malicious off-chain
                Seaport bulk order; ~$1.1M of NFTs (incl. Moonbirds/Autoglyphs) swept.
                Publicly documented (victim's own statements; security press).
Source code:  ../SeaportLikeExchange.sol (authored minimized model, this repo)
License:      MIT (this repo). No third-party marketplace code copied; only the EIP-712
              signed-order verification + NFT transfer surface is modeled.

Minimization / honest scope:
              This is a PATTERN-LEVEL reproduction anchored to the two public incidents
              above, not a byte-replay of a specific tx. Reasons, stated plainly so a
              reviewer is not misled:
              - EIP-712 requires a valid offerer signature; the real victims' private keys
                are (rightly) not public, so the offerer is a key-derived stand-in (vm key
                0xBAD5EA) and the taker/relayer is a symbolic address. The incident write-ups
                are cited at incident level; exact per-victim tx hashes are not pinned here.
              - Seaport's full order model (considerations, zones, conduits, bulk orders) is
                reduced to the one element that carries the vector: a blind off-chain order
                signature authorizing an NFT transfer to the attacker.
Offline:      committed minimized model; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/SeaportSignatureIncident.t.sol: the victim grants routine operator
              approval, blind-signs the order, the attacker fulfills it, and the NFT changes
              owner to the attacker; the verdict is derived from that real outcome.
              Expected verdict: VULNERABLE (TP).
```
