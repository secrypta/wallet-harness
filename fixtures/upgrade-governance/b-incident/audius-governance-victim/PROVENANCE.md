# Fixture provenance

```
Fixture:      upgrade-governance/b-incident/audius-governance-victim
Vector:       upgrade-governance
Tier:         b-incident
Split:        holdout                   # authored after wal froze at v0.1 (see honesty note)
Expected:     vuln                      # ground-truth label (matches meta `label`)

Origin:       Audius governance takeover (callable proxy initialize -> malicious proposal drain)
Reference:    Attacker:          0xa0c7BD318D69424603CBf91e9969870F21B8ab4c   (rekt-confirmed)
              Attack contract:   0xbdbb5945f252bc3466a319cdcc3ee8056bf2e569   (attacker's custom
                                 governance deployment, per rekt)
              Governance proxy:  0x4DEcA517D6817B6510798b7328F2314d3003AbAC   (rekt-confirmed)
              AUDIO token:       0x18aAA7115705e8be94bfFEBDE57Af9BFc265B998
              Treasury transfer: 0x4227bca8ed4b8915c7eec0e14ad3748a88c4371d4176e716e8007249b9980dc9
                                 (moved 18,564,497 AUDIO out of the community treasury; rekt-confirmed)
              Uniswap dump:      0x82fc23992c7433fffad0e28a1b8d11211dc4377de83e88088d79f24f4a3f28b3
                                 (AUDIO -> ETH; rekt-confirmed)
              Earlier txs (initialize + proposal submit/vote): documented in the Audius official
                                 post-mortem's tx sequence (not independently re-verified here).
              Amount drained:    18,564,497 AUDIO (~$6M nominal), cashed out for ~705 ETH (~$1.08M)
                                 then laundered via Tornado Cash (rekt-confirmed).
              Date: 2022-07-23
              Source (authoritative write-up + official post-mortem):
                https://rekt.news/audius-rekt
                https://blog.audius.co/article/audius-governance-takeover-post-mortem-7-23-22
                All public.
Source code:  ../AudiusGovernanceClone.sol (authored minimized clone, this repo)
License:      MIT (this repo). No third-party code copied; only the unguarded `initialize`
              (governance controller settable by a single call, no re-init guard / timelock /
              guardian) + a governance-gated treasury `execute` + a minimal ERC-20 treasury are
              modeled. The full staking/delegate/proposal machinery is NOT reproduced.

Minimization: Modeled AudiusGovernanceClone with `initialize(controller)` callable by anyone and
              a controller-gated `execute(to, amount)` moving the custodied treasury token. The
              real exploit called the live Governance proxy's `initialize`, then submitted and
              self-evaluated a malicious proposal that transferred the treasury; its exploited
              essence collapses to: initialize(attacker) -> execute(drain). The proposal/vote
              lifecycle and token swap are irrelevant to the ungoverned-control bug and are
              omitted. Addresses are used for fidelity (labels only, never a detection signal).
Offline:      committed minimized clone; no fork, no live RPC. Built/run in Docker.

Honesty:      Genuine `holdout` - authored after wal froze at v0.1 and NOT tuned to pass. The
              verdict is derived from the real outcome of the offline replay (the treasury leaves
              the module), not hardcoded. A vuln holdout tests whether the frozen harness
              methodology reproduces and flags a brand-new incident it never saw (recall).
              test/AudiusGovernanceIncident.t.sol replays initialize -> execute and reports the
              verdict. Expected: VULNERABLE (TP on split=holdout).
```
