# Fixture provenance

```
Fixture:      delegatecall-hijack/b-incident/parity-wallet-library-victim
Vector:       delegatecall-hijack
Tier:         b-incident
Split:        holdout                   # authored after wal froze at v0.1 (see honesty note)
Expected:     vuln                      # ground-truth label (matches meta `label`)

Origin:       Parity multisig wallet - first Parity hack (delegatecall-reachable unguarded init)
Reference:    Attacker:          0xB3764761E297D6f121e79C32A65829Cd1dDb4D32
              Example victim:    0xBEc591De75b8699A3Ba52F073428822d0Bfc0D7e (one Parity wallet)
              Attack txs:
                0x9dbf0326a03a2a3719c27be4fa69aacc9857fd231a8d9dcaede4bb083def75ec
                0xeef10fc5170f669b86c4cd0444882a96087221325f8bf2f55d6188633aa7be7c
              Amount drained:    82,189.93 ETH from the example wallet
                                 (~153,037 ETH / ~$30M across the affected wallets)
              Date: 2017-07-19
              Source: Etherscan (txs + verified code) + public post-mortems
                https://www.openzeppelin.com/news/on-the-parity-wallet-multisig-hack-405a8c12e8f7
                https://haseebq.com/a-hacker-stole-31m-of-ether/   (all public)
Source code:  ../ParityWalletClone.sol (authored minimized clone, this repo)
License:      MIT (this repo). No third-party code copied; only the delegatecall proxy + a shared
              library whose `initWallet` lacks an already-initialized guard are modeled. The full
              multiowned/daylimit logic is NOT reproduced.

Minimization: Modeled ParityWalletLibrary (unguarded `initWallet(owner)` + owner-gated `execute`)
              and ParityWalletProxy (holds ETH; forwards unknown calls to the library via
              delegatecall, aligning `owner` on slot 0). The real exploit called the library's
              init through the proxy to seize ownership, then withdrew; its exploited essence
              collapses to: initWallet -> execute drains the proxy. Multi-owner/day-limit
              accounting is irrelevant to the delegatecall-hijack bug and is omitted. The
              addresses above are used for fidelity (labels only, never a detection signal).
Offline:      committed minimized clone; no fork, no live RPC. Built/run in Docker.

Honesty:      Genuine `holdout` - authored after wal froze at v0.1 and NOT tuned to pass. The
              verdict is derived from the real outcome of the offline replay (the wallet's balance
              leaves it), not hardcoded. A vuln holdout tests whether the frozen harness
              methodology reproduces and flags a brand-new incident it never saw (recall).
              test/ParityWalletIncident.t.sol replays initWallet -> execute and reports the
              verdict. Expected: VULNERABLE (TP on split=holdout).
```
