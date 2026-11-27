# Fixture provenance

```
Fixture:      eip7702-delegation/b-incident/inferno-batch7702-victim
Vector:       eip7702-delegation
Tier:         b-incident
Split:        holdout
Expected:     vuln

Origin:       EIP-7702 wallet drain attributed to the Inferno Drainer family (Scam Sniffer flagged
              it 2025-05-24). After the Pectra upgrade enabled EIP-7702 (an EOA may "set code" /
              delegate to a contract), a phished victim's EOA was delegated and then emptied by a
              single malicious BATCHED transaction that swept multiple assets at once.
              IMPORTANT (per SlowMist's analysis): the delegate the victim's EOA pointed at was NOT
              a bespoke phishing contract but MetaMask's own EIP-7702 Delegator; the Inferno
              Drainer group crafted the malicious batch that ran through it (the victim likely
              approved the operation on a phishing site). The victim's EOA address was unchanged.
              Scam Sniffer reported the loss as ~$146,551 (other outlets round to ~$146.6K/$150K).

Reference:    - Scam Sniffer, 2025-05-24 (loss ~$146,551 via malicious batched 7702 transaction).
              - SlowMist (@SlowMist_Team) attribution to Inferno Drainer; notes the delegate was
                MetaMask's EIP-7702 Delegator, not a phishing address.
              - "EIP-7702 Phishing Attack", arxiv.org/pdf/2512.12174 (analysis of 7702 drain flows).
              - Context on the 7702 drain wave: CoinDesk / Wintermute, 2025-06-02.
              Proof level is CLASS-LEVEL: this fixture models the drain MECHANISM (a 7702-delegated
              account emptied by one atomic multi-asset batch), with an explicit 0xBAD placeholder
              delegate; it does not reproduce the MetaMask Delegator internals or specific on-chain
              identifiers. Dollar figures vary across write-ups.

Distinct-from: The dev b-incident for this vector (eip7702-delegation/.../crimeenjoyor-victim)
              models the single reusable, single-asset "CrimeEnjoyor" sweeper that Wintermute
              reported as the dominant 7702 delegate. This holdout is a DIFFERENT drainer family
              and a DIFFERENT mechanic emphasis: one phished delegation + one atomic multi-asset
              batch. It reuses none of the repo's toy src (new self-contained contracts).

Source code:  Self-contained fixture authored in this repo (MIT). No third-party source copied.
License:      MIT (this repo).

Minimization: InfernoBatchDrainerClone.sol: InfernoAccount (victim EOA, stores the delegate,
              `activate` delegatecalls it), InfernoBatchDrainer.drainBatch(recipient, Call[])
              iterating native + ERC-20 transfers, and a minimal MiniToken vehicle. Running via
              delegatecall in the account's context, address(this) is the account, so its own
              assets move. The test funds the account with ETH + two tokens and drains all three
              in one activation.

Offline:      Fully offline; no live RPC, no fork. Deterministic Foundry test in Docker.

Modeling:     EIP-7702 "code runs as the account" is modeled with an explicit delegatecall rather
              than vm.signAndAttachDelegation, so the fixture needs no Prague/Pectra EVM feature
              flag and stays deterministic - the same convention as the dev 7702 fixtures.

Harness:      MUST flag VULNERABLE (every asset leaves the account in one batched activation).
```
