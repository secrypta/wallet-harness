# Fixture provenance

```
Fixture:      upgrade-governance/b-incident/nomad-reinit-root-victim
Vector:       upgrade-governance
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       Nomad Bridge exploit, 2022-08-01, Ethereum, ~$190M drained. A routine
              implementation UPGRADE of the Replica contract re-ran its initializer, which
              set the trusted/committed root to zero and left the ZERO root in the acceptable
              ("proven") state. Because any message whose Merkle proof was never run resolves
              to the zero root, every forged process() call now passed the root check, so
              anyone could submit a fabricated message and withdraw bridged funds. After the
              first drain, hundreds of copy-paste imitators followed, emptying the bridge.
Root cause:   An upgrade/initialization defect that disabled inbound-message authentication
              (trusted root re-initialized to a value that accepts un-proven messages). The
              drain is a direct consequence of the UPGRADE re-initializing trusted state
              incorrectly - an upgrade-introduced authorization bypass.

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Attacker's first probe (0.01 WBTC deposited to the bridge router):
    tx    0xed26708a7335116bdb0673f32ace7c2f329fe3cd349e200447210f1721f335f0
    from  0xa8c83b1b30291a3a1a118058b5445cc83041cd9d
    to    0x88a69b4e698a4b090df6cf5bd7b2d47325ad30a3  (Nomad BridgeRouter proxy)
    block 15258799
  Replica processes 100 WBTC out to the attacker (the drain):
    tx    0xa5fe9d044e4f3e5aa5bc4c0709333cd2190cba0f4e7f16bcf73f49f83e4a5460
    from  0xa8c83b1b30291a3a1a118058b5445cc83041cd9d
    to    0x5d94309e5a0090b165fa4181519701637b6daeba  (Nomad Replica proxy)
    block 15259101, timestamp 2022-08-01 21:32:31 UTC
  Nomad Replica logic (vulnerable, re-initialized): 0xb92336759618f55bd0f8313bd843604592e27bd8
  The on-chain sender/target/block match the incident documented by samczsun / Paradigm /
  CertiK, cross-confirming the tx hashes.

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. samczsun (paradigm) - thread diagnosing the zero-root / re-initialization bug
     https://twitter.com/samczsun/status/1554252024723546112
  2. ParadigmEng420 - incident thread (routine upgrade re-init; acceptable zero root)
     https://twitter.com/paradigmeng420/status/1554249610574450688
  3. CertiK - "Nomad Bridge Exploit Incident Analysis" (root cause + flow)
     https://www.certik.com/resources/blog/28fMavD63CpZJOKOjb9DX3-nomad-bridge-exploit-incident-analysis
  4. Beosin - incident alert
     https://twitter.com/BeosinAlert/status/1554303803218083842
  5. BlockSec - incident thread
     https://twitter.com/BlockSecTeam/status/1554335271964987395
  The Nomad audit (QSP-19, "Proving With An Empty Leaf") had flagged the empty-root class.
  Loss ~$190M across sources; representative in the fixture, not asserted as exact.

Source code:  ./NomadReplicaClone.sol (authored minimized clone of the re-initialized Replica,
              this repo) + src/MockERC20.sol (the custodied asset, standing in for WBTC).
License:      MIT (this repo). No third-party bytecode copied. DeFiHackLabs (Apache-2.0) used
              only as a reference for the attack tx hashes / addresses; its PoC code was NOT
              vendored.
Minimization: Only the upgrade-introduced defect is modeled - a re-initialization that marks
              the zero root acceptable, after which process() honors un-proven (forged)
              messages. The Merkle/optimistic-proof plumbing and cross-chain routing are
              abstracted; the zero "provenRoot" stands in for a message whose proof never ran.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/NomadReplicaIncident.t.sol: initialize() (the upgrade's re-init) marks the
              zero root acceptable; the attacker's forged message against the zero root drains
              the bridge. Expected: VULNERABLE (TP).
```
