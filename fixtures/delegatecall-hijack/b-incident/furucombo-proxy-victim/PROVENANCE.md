# Fixture provenance

```
Fixture:      delegatecall-hijack/b-incident/furucombo-proxy-victim
Vector:       delegatecall-hijack
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       Furucombo "evil contract" drain, 2021-02-27, Ethereum mainnet, ~$15M across
              21 assets / 22 users. Furucombo's proxy let a caller submit a batch of
              "handlers" and executed each by DELEGATECALL (its combo-execution design).
              The whitelist of trusted handlers included the Aave V2 lending-pool proxy,
              whose implementation had been left UNINITIALIZED. The attacker called
              initialize() on that proxy to set its implementation to their own contract,
              then invoked the Furucombo proxy to delegatecall it. The attacker's code
              therefore ran in the Furucombo proxy's own storage/authority context and
              executed transferFrom against users who had granted the proxy standing
              approvals - "cascading trust".
Root cause:   A trusted (whitelisted) delegatecall target whose code was attacker-
              controllable because its initializer was unguarded (uninitialized upgradeable
              proxy). Not a bug in Furucombo's own arithmetic; the defect was trusting a
              target the attacker could repoint, and running it by delegatecall.

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Attack tx:  0x8bf64bd802d039d03c63bf3614afc042f345e158ea0814c74be4b5b14436afb9
              from  0xb624e2b10b84a41687caec94bdd484e48d76b212  (attacker EOA)
              to    0x17e8ca1b4798b97602895f63206afcd1fc90ca5f  (Furucombo proxy)
              block 11940588, timestamp 2021-02-27 17:07:12 UTC
  Setup tx:   0x6a14869266a1dcf3f51b102f44b7af7d0a56f1766e5b1908ac80a6a23dbaf449
              (initializes the malicious Aave implementation; per coinspect/cmichel replay)
  Aave V2 proxy (whitelisted, uninitialized): 0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9
  The on-chain from-address and block date match the independently-reported attacker EOA
  and incident date, cross-confirming the tx hash.

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. PeckShield - "The Furucombo Incident Analysis: Cascading Trust" (auditor post-mortem)
     https://peckshield.medium.com/the-furucombo-incident-analysis-cascading-trust-c90d22c7dda7
  2. Coinspect - Learn EVM Attacks, Furucombo case (tx hashes + addresses + block)
     https://www.coinspect.com/learn-evm-attacks/cases/furucombo/
  3. cmichel - "Replaying Ethereum Hacks - Furucombo" (independent technical replay)
     https://cmichel.io/replaying-ethereum-hacks-furucombo/
  4. OriginProtocol/security incident record 2021-02-27-Furucombo.md
     https://github.com/OriginProtocol/security/blob/master/incidents/2021-02-27-Furucombo.md
  5. Cointelegraph - "$15M exploit" coverage (mainstream media corroboration)
     https://cointelegraph.com/news/furucombo-to-issue-ioucombo-tokens-to-repay-victims-of-15m-attack
  Amount: reported $14M-$15M across sources (PeckShield >$14M; Furucombo post-mortem $15M /
  21 assets / 22 users). Representative figure used in the fixture; not asserted as exact.

Source code:  ./FurucomboProxyClone.sol (authored minimized clone + handler proxy + evil
              handler, this repo) + src/MockERC20.sol (the approved token).
License:      MIT (this repo). No third-party bytecode copied.
Minimization: Only the vector surface is modeled - a whitelisted-handler delegatecall and an
              unguarded initializer on the trusted handler (the live Aave proxy's two-hop
              storage-slot resolution is abstracted to a single implementation resolve +
              delegatecall). The cascading-trust / delegatecall-hijack mechanic is exact.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/FurucomboIncident.t.sol: attacker initializes the whitelisted handler to
              EvilHandler, then the Furucombo proxy delegatecalls it -> victim's standing
              approval spent. Expected: VULNERABLE (TP).
```
