# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/visor-delegated-transfer-victim
Vector:       malicious-calldata
Tier:         b-incident (minimized real public incident)
Split:        holdout                   # authored after v0.1 freeze; wal never tuned to it
Expected:     vuln                      # ground-truth label (matches meta `label`)

Incident:     Visor Finance (VISR) exploit, 2021-12-21, Ethereum, ~$8.2M (8,812,958 VISR).
Root cause:   The vVISR rewards hypervisor's `deposit` path trusted a CALLER-SUPPLIED contract
              (the "visor"): it invoked `visor.delegatedTransferERC20(...)` to pull the deposit
              and credited shares to `visor.owner()`, without restricting the target or
              verifying the hypervisor actually received tokens. The attacker passed their own
              contract whose `delegatedTransferERC20` was empty (moved nothing) and whose
              `owner()` returned the attacker, so the hypervisor minted shares for a deposit
              that never happened; the attacker then withdrew real pooled VISR.
Mechanism:    Arbitrary external call to a caller-chosen target + trust of its self-reported
              owner = the caller-supplied-callee shape of the malicious-calldata vector.
```

## On-chain artifacts (verified via read-only RPC, 2026-11-19)
- **Attack transaction:** `0x69272d8c84d67d1da2f6425b339192fa472898dce936f24818fda415c1c1ff3f`
  - `from` = `0x8efab89b497b887cdaa2fb08ff71e4b3827774b2` (attacker EOA)
  - `to`   = `0x10c509aa9ab291c76c45414e7cdbd375e1d5ace8` (attacker exploit contract)
  - `block` = 13849007 (2021-12-21)
  - Verified: `eth_getTransactionByHash` via public RPC; `from`/`to`/`block` confirmed.
- **RewardsHypervisor (vulnerable):** `0xc9f27a50f82571c1c8423a42970613b8dbda14ef`
  (matches the DeFiHackLabs reference, which forks mainnet at block 13849006, the block before
  the attack).

## Independent sources (>=3 authorities; facts cross-checked)
- Rekt.news - "Visor Finance Rekt": https://rekt.news/visor-finance-rekt
  (vulnerable `require()` in the vVISR rewards `deposit()`; attacker minted shares via their own
  contract after transferring ownership to themselves.)
- optimaginating - "Two vulnerabilities in one function" (Medium analysis):
  https://optimaginating.medium.com/two-vulnerabilities-in-one-function-the-analysis-of-visor-finance-exploit-a15735e2492
  (the call does not restrict the target, so the hacker can call any contract and take over the
  staking contract's execution; exploit tx `0x69272d8c...`; hypervisor `0xc9f2...14ef`.)
- CryptoBriefing - "$8.2M Lost as Visor Finance Suffers Latest DeFi Hack":
  https://cryptobriefing.com/8-2m-lost-visor-finance-suffers-latest-defi-hack/
- BeInCrypto - "Visor Finance Hacked For $8M": https://beincrypto.com/visor-finance-hacked-for-8m-in-latest-defi-exploit/
- Visor Finance post-mortem (vVISR staking contract):
  https://medium.com/visorfinance/post-mortem-for-vvisr-staking-contract-exploit-and-upcoming-migration-7920e1dee55a
  (8,812,958 VISR drained; fix = use a fixed `ERC20.transferFrom` instead of the caller-supplied
  `delegatedTransferERC20`.)

## What is authored here (MIT, no third-party bytecode)
`../VisorHypervisorClone.sol` is my own minimized reproduction: a hypervisor whose `deposit`
makes an arbitrary external call to a caller-chosen `visor` contract and credits shares to its
self-reported `owner()`, without verifying a real transfer. The real Uniswap-v3 position
accounting is abstracted to a 1:1 VISR share pool. No code or bytecode from Visor or any
analysis repo is copied; sources are reference only.

## Why the harness must flag it (VULNERABLE)
`test/VisorIncident.t.sol`: a legit user seeds real VISR into the pool; the attacker calls
`deposit(amount, evilVisor)` where `evilVisor.delegatedTransferERC20` is a no-op and
`evilVisor.owner()` is the attacker, minting free shares; the attacker then `withdraw`s the
legit user's pooled VISR. Verdict is derived from the real outcome -> VULNERABLE.
