# Fixture provenance

```
Fixture:      address-poisoning/b-incident/wbtc-poison-victim
Vector:       address-poisoning
Tier:         b-incident
Split:        holdout
Expected:     vuln                     # ground-truth label (matches meta `label`)

Origin:       Address-poisoning ("dust") drain. The attacker had seeded the victim's transfer
              history with a look-alike entry whose truncated wallet display (leading/trailing
              bytes) matches the real counterparty the victim had previously paid. On
              2024-05-03 the victim copied the look-alike from history and sent ~1,155 WBTC
              (~$68M) to it. Because the FULL address differs, the funds went to the attacker.
              Unusually, after on-chain negotiation the attacker returned almost all of the
              value (in ETH) to the victim days later - this does not change the label: the
              transfer itself was misrouted to the attacker (vuln).

Reference:    - Cointelegraph: "WBTC address poisoner sends nearly all funds back to victim
                after negotiations" (cointelegraph.com/news/wbtc-address-poisoner-all-funds-negotiations)
              - The Block: "Victim loses over $71 million worth of WBTC in purported address
                poisoning attack" (theblock.co/post/292472)
              - CertiK (noted the attacker mimicked a 0.05 ETH transfer to seed history);
                PeckShield (tracked the swap of stolen WBTC into ~23,000 ETH).
              - Chainalysis: "Anatomy of an Address Poisoning Scam"
                (chainalysis.com/blog/address-poisoning-scam/) - campaign Feb 28-May 4 2024,
                $68M returned (unusual).

On-chain:     (Ethereum mainnet; public, reported by the sources above. No live RPC / fork is
              used by this fixture - the addresses are cited for provenance only.)
              - Victim:                0x1E227979f0b5BC691a70DEAed2e0F39a6F538FD5
              - Real counterparty:     0xd9A1b0B1e1aE382DbDc898Ea68012FfcB2853a91  (intended)
              - Poison look-alike:     0xd9A1C3788D81257612E2581A6ea0aDa244853a91  (attacker)
              - WBTC token (canonical):0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599  (8 decimals)
              The look-alike was crafted to share the displayed prefix (0xd9A1) AND suffix
              (853a91) with the real counterparty while differing in the full 20-byte address -
              the defining property of this vector, and a property verifiable directly from the
              two addresses above.

Source code:  test/WbtcAddressPoisonIncident.t.sol + src/AddressBook.sol,
              src/VulnerableSendWallet.sol, src/MockERC20.sol (this repo's own primitives,
              reused read-only - same as the dev usdt-poison fixture).
License:      MIT (this repo).

Minimization / honest scope:
              Pattern-level offline reproduction anchored to the WBTC incident, not a
              byte-replay of the on-chain tx:
              - The REAL victim / real-counterparty / look-alike addresses above are used
                verbatim as the three parties (unlike the dev usdt fixture, which uses
                representative literals). This is what makes the holdout independent and
                verifiable: the poisoning premise (shared truncated display, differing full
                address) holds on the actual incident addresses.
              - WBTC is 8-decimal; amounts are expressed as 1,155 * 1e8. MockERC20 is used as a
                generic balance primitive (its own decimals() are irrelevant - the test asserts
                on balances, not on decimals).
              - The specific transfer tx hash is not pinned (not needed for an offline
                pattern replay and not asserted); the incident is cited at event level with the
                public sources above.
Offline:      committed source only; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/WbtcAddressPoisonIncident.t.sol asserts the poisoning premise on the real
              addresses, then shows a wallet that trusts the truncated display paying the
              look-alike; the verdict is derived from the outcome (funds landed on the
              attacker look-alike). Expected: VULNERABLE (TP).
```
