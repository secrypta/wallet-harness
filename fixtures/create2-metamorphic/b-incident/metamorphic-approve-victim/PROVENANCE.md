Fixture:      create2-metamorphic/b-incident/metamorphic-approve-victim
Vector:       create2-metamorphic
Tier:         b-incident
Expected:     vuln

Origin:       CREATE2 / metamorphic address abuse. Two documented patterns: (1) drainers
              pre-compute a fresh CREATE2 address per victim so each malicious signature targets
              an address with no reporting history (blocklist evasion); (2) metamorphic address
              reuse - deploy benign code, get approved, SELFDESTRUCT, redeploy malicious at the
              same address, spend the standing approval.
Reference:    Scam Sniffer, "Wallet Drainers Starts Using Create2 Bypass Wallet Security
              Alert" (2023-11-12, with SlowMist), drops.scamsniffer.io/wallet-drainers-starts-
              using-create2-bypass-wallet-security-alert/ ; CoinDesk 2023-11-13; BleepingComputer;
              MixBytes (metamorphic reuse). Pattern (1) totals ~$60M from ~99K victims / 6 months.
Incident tx:  A concrete public example cited in the Scam Sniffer report (Arbitrum):
              - Victim signature tx: 0x0b8d095c9ee0f27362240ed3f315afa12d6f88a6a0c15b99231bc14d4dd1fb96
                (arbiscan.io/tx/0x0b8d095c...fb96) - victim lost ~$927K in GMX after signing a
                `signalTransfer(address receiver)` to the GMX Reward Router; assets were routed
                to a pre-computed CREATE2 receiver.
              - Pre-computed CREATE2 receiver (GMX): 0xbD2BF58Be46619B7A22cE9457e1D51A10B82EB91.
              - Second CREATE2 receiver (sfrxETH drain, no prior history): 0x4d9f7773deb9cc44b34066f5e36a5ec98ac92d40.
              - Drainer's open-sourced CREATE2 factory (exposes calculateAddress / createAndCall):
                0x00004d035111f89dc358edc8d316fd2ad3f80000.
              All addresses/tx are public, verified against the Scam Sniffer primary report
              (which links the tx on Arbiscan). No live RPC was used.
Source code:  toy + reference-impl authored in this repo (MIT); no third-party code copied.
License:      MIT (this repo).

Minimization: MetamorphicSpender + BenignLogic/DrainerLogic reproduce "approve a benign-looking
              contract at a fixed address, then the code at that address becomes a drainer and
              spends the still-valid approval".
Offline:      Fully offline; no live RPC, no fork. Deterministic Foundry test in Docker.
Notes:        Cancun caveat (EIP-6780, 2024): the literal SELFDESTRUCT-then-redeploy-at-same-
              address trick no longer works on post-Cancun EVMs except within the creating tx, so
              we model code mutation at a fixed address with a swappable implementation
              (delegatecall); the effective code identity is the implementation codehash, which
              stands in for EXTCODEHASH(address). The fresh-CREATE2-address blocklist-evasion
              variant is unaffected by EIP-6780. Proof level: incident-level for variant (1)
              (concrete public tx + CREATE2 receiver + open-sourced drainer factory cited above);
              class-level for the variant (2) metamorphic SELFDESTRUCT-redeploy reuse (MixBytes),
              which is restricted post-Cancun. The fixture reproduces the shared mechanism
              (standing authority to an attacker-controlled CREATE2 address). Harness MUST flag
              VULNERABLE.
