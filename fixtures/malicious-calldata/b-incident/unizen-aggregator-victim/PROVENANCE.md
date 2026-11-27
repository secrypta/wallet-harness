# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/unizen-aggregator-victim
Vector:       malicious-calldata
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       Unizen trade-aggregator exploit, 2024-03-08, Ethereum, ~$2.1M drained from users
              who had approved the aggregator proxy. Shortly after an upgrade (intended to
              lower gas costs and raise spending limits for some tokens), the aggregator's swap
              flow performed an arbitrary external call WITHOUT binding the token source to
              msg.sender or restricting the call to trusted DEX routers. The attacker supplied
              a call to a victim's token with transferFrom(victim, attacker, amount); the
              aggregator executed it as msg.sender and pulled the victim's standing approval.
              The approval risk persisted until users revoked. Unizen later committed to
              reimburse affected users.
Root cause:   Unvalidated caller-supplied external call in the swap flow, with no source-binding
              (token source not tied to msg.sender) and no trusted-router allowlist - a
              confused-deputy approval drain. Same class as Socket / LI.FI / Transit / Rubic /
              Dexible / Seneca; distinct incident/protocol. (The arbitrary-call surface was
              widened by an upgrade, but the drain is an approval pull, not a governance takeover,
              so it belongs to malicious-calldata, not upgrade-governance.)

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Attack tx:  0x923d1d63a1165ebd3521516f6d22d015f2e1b4b22d5dc954152b6c089c765fcd  (Ethereum)
              from  0x2ad8aed847e8d4d3da52aabb7d0f5c25729d10df  (attacker EOA)
              to    0xd3f64baa732061f8b3626ee44bab354f854877ac  (Unizen trade-aggregator proxy)
              block 19393770, timestamp 2024-03-08 23:49:35 UTC
  (One of several drain txs from the same attacker; the aggregator proxy is the victim contract.)
  The on-chain from/to match the attacker EOA and aggregator proxy documented by DeFiHackLabs /
  Smart Contracts Hacking, cross-confirming the tx hash.

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. Halborn - "Explained: The Unizen Hack (March 2024)" (unsafe external call; hack shortly
     after the aggregator upgrade; ~$2.1M)
     https://www.halborn.com/blog/post/explained-the-unizen-hack-march-2024
  2. Smart Contracts Hacking - "Unizen Hack (2024) - $2.1M" (arbitrary external call in swap
     flow; no source-binding to msg.sender; no trusted-route restriction; confused deputy)
     https://smartcontractshacking.com/hacks/unizen-hack-2024
  3. BlockSec / DeFiHackLabs - attack-tx references (attacker + aggregator addresses)
     https://app.blocksec.com/explorer/tx/eth/0x923d1d63a1165ebd3521516f6d22d015f2e1b4b22d5dc954152b6c089c765fcd
  Loss ~$2.1M across sources; representative in the fixture, not asserted as exact.

Source code:  ./UnizenAggregatorClone.sol (authored minimized clone of the vulnerable swap
              flow, this repo) + src/MockERC20.sol (the approved token).
License:      MIT (this repo). No third-party bytecode copied. DeFiHackLabs (Apache-2.0) used
              only as a reference for the attack tx / addresses; its PoC code was NOT vendored.
Minimization: Only the vulnerable surface is modeled - a swap that executes a caller-supplied
              call target + calldata with no source-binding and no router allowlist. The
              multi-DEX routing is omitted.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/UnizenAggregatorIncident.t.sol: the attacker calls swap with targetDex=token
              and transferFrom(victim -> attacker) as calldata, draining the approval.
              Expected: VULNERABLE (TP).
```
