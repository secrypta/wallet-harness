# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/dexible-selfswap-victim
Vector:       malicious-calldata
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       Dexible (DEX aggregator) exploit, 2023-02-17, Ethereum (+Arbitrum), ~$2M drained
              from 17 trader addresses (4 mainnet, 13 Arbitrum) that had approved Dexible as a
              spender. The v2 `selfSwap` path let a user supply a `router` address and
              arbitrary `routerData` (calldata) for a swap, with no on-chain check that the
              router was a legitimate DEX router. The attacker set the router to a victim's
              token and routerData to transferFrom(victim, attacker, amount); the call ran
              with msg.sender == Dexible, so the token honored it against the standing
              approval. Funds were sent to Tornado Cash.
Root cause:   Unvalidated caller-supplied call target + calldata executed by the contract
              (arbitrary external-call injection), with no router allowlist and no post-call
              guard - the plainest form of the class. Same approval-drain family as Socket /
              LI.FI / Transit / Rubic.

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Attack tx:  0x138daa4cbeaa3db42eefcec26e234fc2c89a4aa17d6b1870fc460b2856fd11a6  (Ethereum)
              from  0x684083f312ac50f538cc4b634d85a2feafaab77a  (attacker EOA)
              to    0x194fc30f9eeba9ad673413629b47fc00e71d90df  (attacker exploit contract)
              block 16646023, timestamp 2023-02-17 04:20:35 UTC
  The on-chain from/to/block match the attacker EOA and exploit contract documented by
  PeckShield / DeFiHackLabs, cross-confirming the tx hash.

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. PeckShield - incident alert (selfSwap arbitrary call; approvals abused; funds to TC)
     https://twitter.com/peckshield/status/1626493024879673344
  2. BlockApex - "Dexible Hack Analysis" (selfSwap path; no router verification; mechanism)
     https://blockapex.io/dexible-hack-analysis/
  3. Cryptonews - "DexibleApp aggregator hacked for $2M via 'selfSwap' function"
     https://cryptonews.net/news/security/20573513/
  4. Blockchain.News - "$2 Million Worth of Cryptocurrency Lost in Dexible Hack"
     https://blockchain.news/news/2-million-worth-of-cryptocurrency-lost-in-dexible-hack
  5. Quadriga Initiative case study - "Dexible DEX Aggregator SelfSwap Exploit"
     https://quadrigainitiative.com/casestudy/dexibledexaggregatorselfswapexploit.php
  Dexible's own post-mortem cited $2,047,635.17 from 17 addresses; a Quadriga case study put
  the ETH-side figure near $1.53M. Representative in the fixture, not asserted as exact.

Source code:  ./DexibleClone.sol (authored minimized clone of the vulnerable selfSwap path,
              this repo) + src/MockERC20.sol (the approved token).
License:      MIT (this repo). No third-party bytecode copied. DeFiHackLabs (Apache-2.0) used
              only as a reference for the attack tx / addresses; its PoC code was NOT vendored.
Minimization: Only the vulnerable surface is modeled - selfSwap that executes a caller-supplied
              router + calldata with no validation. The fee accounting and EIP-712 fill
              plumbing are omitted.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/DexibleIncident.t.sol: the attacker calls selfSwap with router=token and
              transferFrom(victim -> attacker) as calldata, draining the approval.
              Expected: VULNERABLE (TP).
```
