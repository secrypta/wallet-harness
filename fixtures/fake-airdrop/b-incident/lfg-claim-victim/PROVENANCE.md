# Fixture provenance

```
Fixture:      fake-airdrop/b-incident/lfg-claim-victim
Vector:       fake-airdrop
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)

Origin:       Fake-airdrop "claim" phishing: an unsolicited airdrop bait lures the victim to
              a claim flow that, instead of touching the gift, makes them grant an approval
              (or permit) on their REAL asset to the attacker's spender, which is then drained.
Reference:    - LFG fake-airdrop guide (2023): a victim (Nest CEO) lost ~$125K of stETH via a
                fake-airdrop claim that induced an approval on the real asset. Sources: The
                Block (2024-01-03); Scam Sniffer.
Source code:  test/LfgFakeAirdropIncident.t.sol + ../StEthLikeToken.sol (minimized real asset,
              this repo) + src/GiftToken.sol (bait) + src/MaliciousSpender.sol (drainer),
              the latter two reused read-only.
License:      MIT (this repo). No third-party code copied; StEthLikeToken models only the
              ERC-20 approve/transferFrom surface (18 decimals, as stETH).

Minimization / honest scope:
              Pattern-level reproduction anchored to the LFG 2023 incident. Proof is
              medium: the public sources name the victim and the ~$125K stETH loss but we do
              not pin an exact tx here; the incident is cited at incident level. VICTIM/
              ATTACKER are symbolic addresses; REAL_BALANCE (70e18) is representative of the
              cited ~$125K stETH. The vector mechanism (bait -> claim -> approval on the real
              asset -> drain) is reproduced faithfully.
Offline:      committed source only; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/LfgFakeAirdropIncident.t.sol: the victim holds the bait plus the real
              stETH-like asset, the claim grants an unlimited approval on the real asset, the
              attacker drains it, and the bait stays untouched; verdict derived from the
              outcome. Expected: VULNERABLE (TP).
```
