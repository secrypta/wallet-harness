# Fixture provenance

```
Fixture:      delegatecall-hijack/b-incident/bybit-exec-victim
Vector:       delegatecall-hijack
Tier:         b-incident
Expected:     vuln

Origin:       Bybit cold-wallet theft, 2025-02-21, ~$1.46B - the largest crypto theft on
              record. Bybit's Safe/Gnosis multisig signed a transaction whose `operation`
              flag was flipped from call (0) to delegatecall (1). The payload ran attacker-
              deployed code in the wallet's storage context, replacing the implementation/
              `masterCopy` pointer and seizing the account; the cold wallet was then drained.
Root cause:   A Safe{Wallet} front-end / supply-chain compromise (malicious JavaScript
              served to Bybit's signers made a benign-looking transfer carry a delegatecall
              payload), NOT a smart-contract bug in Safe itself.
Reference:    CertiK; SlowMist; NCC Group; BleepingComputer incident write-ups.
              Proof level: MECHANISM-LEVEL (honestly flagged). Full calldata/traces were not
              all public; this is a minimized offline reproduction of the documented
              delegatecall-swap mechanism, NOT a byte-for-byte replay of the on-chain tx.
              Dollar figure and balances are representative/scaled, not exact.
Source code:  ../BybitSafeClone.sol (authored minimized Safe-style clone, this repo) +
              src/AccountTakeoverModule.sol (attacker delegate).
License:      MIT (this repo). No third-party bytecode copied.
Minimization: Only a slot-0 masterCopy pointer and an execTransaction with an `operation`
              flag are modeled - the exact surface the incident turned on. Signature
              verification is abstracted to a threshold owner check (the incident did not
              break signing; it got signers to approve a delegatecall payload).
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/BybitIncident.t.sol: owner submits an operation=delegatecall payload to
              the attacker module -> masterCopy replaced + balance swept. Verdict from the
              real outcome. Expected: VULNERABLE (TP).
```
