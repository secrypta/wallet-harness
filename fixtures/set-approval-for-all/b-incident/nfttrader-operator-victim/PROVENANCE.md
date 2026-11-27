# Fixture provenance

```
Fixture:      set-approval-for-all/b-incident/nfttrader-operator-victim
Vector:       set-approval-for-all
Tier:         b-incident
Split:        holdout
Expected:     vuln
Proof level:  INCIDENT-LEVEL (confirmed public tx + addresses; minimized mechanism reproduction)

Origin:       NFTTrader.org drain, 2023-12-16 (~$3M, per hacked.slowmist.io). NFTTrader was an
              NFT peer-to-peer swap marketplace. Many users held a standing
              `setApprovalForAll(NFTTrader, true)` (blanket operator authority over an entire
              collection) from earlier legitimate swaps. The marketplace's swap settlement mutated
              swap state through `editCounterPart`, which lacked reentrancy protection and was
              reachable from inside an ERC-721 transfer callback fired mid-settlement. The attacker
              opened a swap offering their own NFT and, during settlement, re-entered to set a
              *victim* as the swap counterparty; the marketplace then transferred the victim's NFTs
              to the attacker using the victim's lingering operator approval. Blue-chip NFTs
              (e.g. Bored Ape / Mutant Ape, Art Blocks) were swept from victims who never agreed
              to the swap. (Specific collections per SlowMist / Ancilia; the CloneX example in an
              earlier draft was not confirmed for this incident and has been dropped.)

Confirmed on-chain identifiers (public, Etherscan):
              - Attack tx:          0xec7523660f8b66d9e4a5931d97ad8b30acc679c973b20038ba4c15d4336b393d
              - Attacker (EOA):     0xb1edf2a0ba8bc789cbc3dfbe519737cada034d2d
              - Attacker contract:  0x871f28e58f2a0906e4a56a82aec7f005b411f5c5
              - Vulnerable NFTTrader: 0xc310e760778ecbca4c65b6c559874757a4c4ece0
              - Example victim:     0x23938954bc875bb8309aef15e2dead54884b73db
              Block 18,799,488 (Ethereum mainnet), 2023-12-16 15:22:59 UTC (verified on Etherscan).

Reference (authoritative write-ups):
              - SlowMist (@SlowMist_Team): https://twitter.com/SlowMist_Team/status/1736005523550646535
              - Ancilia (@AnciliaInc):     https://twitter.com/AnciliaInc/status/1736263884217139333
              - 0xArhat analysis:          https://twitter.com/0xArhat/status/1736038250190651467
              - SlowMist hacked registry:  https://hacked.slowmist.io (NFTTrader, 2023-12, ~$3M)

Mechanism reference (for locating the incident + confirming the identifiers above):
              - SunWeb3Sec/DeFiHackLabs, commit 8f077a91403c81af315c8903519a3bd9723a1903,
                src/test/2023-12/NFTTrader_exp.sol, Apache-2.0. The DeFiHackLabs PoC is a
                mainnet-fork replay; it is NOT vendored here. See repo NOTICE for attribution.

Source code:  ./../NftTraderClone.sol (authored minimized reproduction, THIS repo, MIT). It is not
              a copy of the on-chain NFTTrader contract (unverified) nor of the DeFiHackLabs PoC; it
              reproduces only the documented root cause offline: lingering operator-for-all approval
              + an unguarded, reentrancy-reachable counterparty mutation during settlement.

Why vuln:    The victim's blanket `setApprovalForAll` to the marketplace is standing authority over
             the whole collection; the settlement bug makes it reachable by an attacker who never
             obtained the victim's consent. The minimized test drives the real outcome (the victim's
             NFT ends up owned by the attacker) and the harness reads VULNERABLE from that outcome.
```
