Fixture:      eip7702-delegation/b-incident/crimeenjoyor-victim
Vector:       eip7702-delegation
Tier:         b-incident
Expected:     vuln

Origin:       EIP-7702 account-delegation abuse, live since the Ethereum Pectra upgrade (2025).
              Wintermute documented a reusable sweeper contract nicknamed "CrimeEnjoyor" that
              accounted for the vast majority of malicious 7702 delegations observed: a victim
              with a phished SET_CODE "enable smart account" authorization delegates their EOA to
              the sweeper, which drains everything in one transaction.
Reference:    Wintermute "CrimeEnjoyor" analysis; Scam Sniffer reporting on 7702 drainers. Our own
              permit-phishing (b) USDC case (2026-03-16) also chained a 7702 delegation (poisoner
              0x9F68523efdc91ADbE53c3776Aa927f41aB4FE17E) - a concrete on-chain data point.
Source code:  reference-impl authored in this repo (MIT); no third-party code copied.
License:      MIT (this repo).

Minimization: VulnerableDelegationAccount + DelegationSweeper reproduce the drain mechanism:
              install an arbitrary delegate (the phished authorization), then run it in the
              account's own context so a single activation sweeps the whole balance.
Offline:      Fully offline; no live RPC, no fork. Deterministic Foundry test in Docker.
Notes:        The EIP-7702 "code runs as the account" semantics are modeled EXPLICITLY via
              delegatecall, NOT via vm.signDelegation / vm.attachDelegation, so the fixture is
              deterministic on any EVM/toolchain. Honest proof level: incident/class-level -
              dollar figures vary across secondary write-ups, so we reproduce the mechanism
              (one-signature full drain via a reusable sweeper), not a byte-for-byte tx replay.
              Harness MUST flag VULNERABLE.
