# Fixture provenance

```
Fixture:      upgrade-governance/b-incident/poly-keeper-takeover-victim
Vector:       upgrade-governance
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       Poly Network exploit, 2021-08-10, Ethereum (also BNB Chain, Polygon), ~$611M -
              the largest DeFi hack at the time (most funds were later returned). The
              EthCrossChainManager executed inbound cross-chain messages by calling a target
              method with the manager's own authority. Nothing prevented a message from
              targeting the manager's OWN privileged storage contract (EthCrossChainData),
              whose keeper-management function (putCurEpochConPubKeyBytes) was callable only
              by its owner - which was the manager. The attacker crafted a message so that the
              manager called that function and REPLACED the bridge "keeper" (the role that
              authorizes withdrawals) with the attacker's key. As the new keeper, the attacker
              authorized withdrawals that drained the lock-proxy vaults across chains.
Root cause:   A privileged role (the keeper/authority that gates withdrawals) was reachable
              through an unguarded message-execution path, so it could be reassigned by an
              attacker-crafted message - a governance/admin takeover. The drain follows from
              seizing the privileged role, NOT from pulling user approvals (which is what
              distinguishes this from the malicious-calldata approval-drain fixtures).

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Keeper takeover tx (putCurEpochConPubKeyBytes):
    tx    0xb1f70464bd95b774c6ce60fc706eb5f9e35cb5f06e6cfe7c17dcda46ffd59581
    from  0xc8a65fadf0e0ddaf421f28feab69bf6e2e589963  (attacker)
    to    0x838bf9e95cb12dd76a54c9f9d2e3082eaf928270  (EthCrossChainManager)
    block 12996659
  Drain (asset release) tx:
    tx    0xad7a2c70c958fcd3effbf374d0acf3774a9257577625ae4c838e24b0de17602a
    from  0xc8a65fadf0e0ddaf421f28feab69bf6e2e589963
    to    0x838bf9e95cb12dd76a54c9f9d2e3082eaf928270  (EthCrossChainManager)
    block 12996671, timestamp 2021-08-10 09:51:02 UTC
  EthCrossChainData (keeper storage, owner == manager): 0xcf2afe102057ba5c16f899271045a0a37fcb10f2
  The on-chain sender (attacker) and target (manager) match the incident documented by
  SlowMist / Mudit Gupta / BlockSec, cross-confirming the tx hashes. (The takeover tx was
  served by one RPC endpoint and absent on another's index; cross-checked on cloudflare-eth.)

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. SlowMist - Poly Network hack analysis (manager executes arbitrary target; keeper
     replaced via putCurEpochConPubKeyBytes)
     https://slowmist.medium.com/the-root-cause-of-poly-network-being-hacked-ec2ee1b0c68f
  2. Mudit Gupta - "Poly Network Hack Analysis - Largest Crypto Hack" (keeper takeover flow)
     https://mudit.blog/poly-network-largest-crypto-hack/
  3. BlockSec - "The further analysis of the Poly Network attack" (selector/hash-collision
     trick used to reach putCurEpochConPubKeyBytes; keeper modified, not a key leak)
     https://blocksecteam.medium.com/the-further-analysis-of-the-poly-network-attack-6c459199c057
  4. CertiK - "PolyNetwork Hack Analysis"
     https://certik.medium.com/polynetwork-hack-analysis-a86513f2a730
  5. Valix Consulting - "Poly Network - In-Depth Analysis of the Biggest Heist in DeFi History"
     https://medium.com/valixconsulting/poly-network-in-depth-analysis-of-the-biggest-heist-in-defi-history-adb23f2576a7
  Loss ~$611M across sources (the largest at the time); most funds were later returned.
  Representative in the fixture, not asserted as exact.

Source code:  ./PolyNetworkClone.sol (authored minimized clone of the manager/storage/
              lock-proxy, this repo) + src/MockERC20.sol (the custodied asset).
License:      MIT (this repo). No third-party bytecode copied. DeFiHackLabs (Apache-2.0) used
              only as a reference for the attack tx hashes / addresses; its PoC code was NOT
              vendored.
Minimization: Only the governance/role-takeover surface is modeled - an unguarded executed
              message that reassigns the privileged keeper, after which the attacker authorizes
              a withdrawal that drains the vault. The header/Merkle verification and the
              multi-chain lock-proxy plumbing are abstracted.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/PolyNetworkIncident.t.sol: the attacker first cannot withdraw (not keeper),
              then crafts a message that reassigns the keeper role to themselves and drains the
              vault. Expected: VULNERABLE (TP).
```
