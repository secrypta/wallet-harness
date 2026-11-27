# Fixture provenance

```
Fixture:      upgrade-governance/b-incident/beanstalk-governance-victim
Vector:       upgrade-governance
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       Beanstalk Farms flash-loan governance takeover, 2022-04-17, Ethereum mainnet.
              ~$182M protocol loss; the attacker netted ~$76-80M (24,830 ETH + 36M BEAN).
              Beanstalk's on-chain governance counted voting weight from CURRENTLY deposited
              stake (no flash-loan-resistant snapshot) and executed proposals IMMEDIATELY via
              an emergencyCommit path (no timelock). The attacker had pre-submitted a
              malicious BIP; in the attack tx they flash-borrowed ~$1B, converted it through
              Curve into whitelisted LP, deposited it to pass the ~2/3 supermajority instantly,
              then emergency-committed the BIP. The proposal's init contract was DELEGATECALLED
              by the Beanstalk diamond, running the attacker's code in the protocol's own
              context and transferring its assets out - all in one transaction.
Root cause:   Governance with no timelock/delay and no flash-loan resistance between acquiring
              voting power and executing a proposal, combined with proposal execution by
              delegatecall. Exactly the upgrade-governance defect: a single instantaneously-
              acquired majority can mutate/execute protocol logic with no guardian gate.

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Attack tx:  0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7
              from  0x1c5dcdd006ea78a7e4783f9e6021c32935a10fb4  (attacker EOA)
              to    null  (contract creation - deploys attack contract 0x79224bC0bf70EC34F0ef56ed8251619499a59dEf)
              block 14602790, timestamp 2022-04-17 12:24:16 UTC
  Propose BIP18 tx: 0x68cdec0ac76454c3b0f7af0b8a3895db00adf6daaf3b50a99716858c4fa54c6f
  Malicious proposal contract: 0xe5ecf73603d98a0128f05ed30506ac7a663dbb69
  Beanstalk (victim diamond):  0xc1e088fc1323b20bcbee9bd1b9fc9546db5624c5
  The on-chain from-address (attacker EOA, agreed by Beosin + CertiK) and the block date
  match the independently-reported incident, cross-confirming the tx hash.

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. CertiK - "Revisiting Beanstalk Farms Exploit" (lists attack tx + proposal + address)
     https://www.certik.com/blog/revisiting-beanstalk-farms-exploit
  2. Veridise - "Flash loan governance vulnerability: Beanstalk $182M" (mechanism + delegatecall)
     https://veridise.com/blog/audit-insights/flash_loan_governance_vulnerability_beanstalk_182m/
  3. Beosin - "Beosin's Analysis of the Beanstalk Exploit" (attacker address + attack contract)
     https://medium.com/@Beosin_com/beosins-analysis-of-the-beanstalk-exploit-6c2f4900af87
  4. Coindesk - "Attacker Drains $182M From Beanstalk Stablecoin Protocol" (media corroboration)
     https://www.coindesk.com/tech/2022/04/17/attacker-drains-182m-from-beanstalk-stablecoin-protocol
  5. Cointelegraph - "Beanstalk Farms loses $182M in DeFi governance exploit"
     https://cointelegraph.com/news/beanstalk-farms-loses-182m-in-defi-governance-exploit
  Amounts agree across sources: ~$182M protocol loss, ~$76-80M net to attacker (CertiK $76M;
  PeckShield 24,830 ETH + 36M BEAN). Representative figures in the fixture; not asserted exact.

Source code:  ./BeanstalkGovernanceClone.sol (authored minimized governance + stake token +
              malicious proposal init, this repo).
License:      MIT (this repo). No third-party bytecode copied.
Minimization: Only the vector surface is modeled - instantaneous-stake supermajority with no
              timelock, and proposal execution by delegatecall. The Diamond/Silo internals,
              Curve routing and real BIP vote accounting are omitted. The flash-acquired stake
              is modeled as an in-tx deposit (commented); the governance defect is exact.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/BeanstalkIncident.t.sol: attacker deposits a majority stake in-tx, proposes
              and emergency-commits a malicious init, which is delegatecalled and sweeps the
              protocol's balance. Expected: VULNERABLE (TP).
```
