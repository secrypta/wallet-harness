# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/squid-multicall-victim
Vector:       malicious-calldata
Tier:         b-incident
Split:        holdout
Expected:     vuln
Proof level:  CLASS-LEVEL (see note)

Origin:       SquidMulticall approval exploit (2026-04-07). The Squid `SquidMulticall` helper
              exposed a PERMISSIONLESS `run(Call[])` that executes an attacker-supplied list of
              arbitrary external calls from the helper's own context. Users who had approved the
              helper (a common integration pattern - some approved it instead of the intended
              Squid Router) were drained: a bot called `run` with a crafted
              `transferFrom(victim, attacker, amount)`, and because the helper is the approved
              spender, the standing allowance was spent. ~$517K was taken across five chains
              (Arbitrum, Avalanche, Base, BNB Chain, Optimism). The Decurity timeline describes
              the BSC leg as one crafted `Call` moving 1 WETH out of a victim's wallet.

Reference (authoritative write-ups):
              - smartcontractshacking.com/hacks/squidmulticall-approval-exploitation-hack-2026
                (date 2026-04-07; ~$517K; 5 chains; permissionless run() -> transferFrom; root
                cause = arbitrary-call helper with no access control; classified Access Control).
              - Decurity DeFi exploit drain timeline (hack-drain-timeline.onrender.com) - BSC leg
                (MEV bot calls run() with a Call{target: WETH, data: transferFrom}, pulls 1 WETH).
              - Squid's own statement distinguishes this from the separate 2026-05-25
                SquidRouterModule / Gnosis Safe module event (~$3.2M) - NOT this fixture.

CLASS-LEVEL note (IMPORTANT - no fabrication):
              The specific on-chain transaction hash and the real attacker / victim / helper
              contract addresses are NOT reproduced here, because they could not be confirmed
              against an authoritative public write-up (the write-ups above document the date,
              scale, chains and mechanism, not a citable tx/address set). Rather than assert an
              unverified identifier, this fixture uses EXPLICIT PLACEHOLDERS (attacker=address(0xBAD),
              victim=address(0xBEEF)) - the same discipline as the CrimeEnjoyor / Inferno
              fixtures. Only the documented MECHANISM is reproduced; nothing invented is claimed
              as real on-chain data.

Source code:  ../SquidMulticallClone.sol (authored minimized clone, this repo).
License:      MIT (this repo). No third-party source copied; only the permissionless `run(Call[])`
              arbitrary-call forwarder + a minimal ERC-20 allowance surface are modeled. The full
              Squid router, call-type enum and bridging are NOT reproduced.

Minimization: MiniToken (standard allowance/transferFrom), SquidMulticallClone.run(Call[]) that
              forwards each attacker-supplied call, and a victim that approved the helper. The
              test replays approve(helper) -> run([transferFrom(victim, attacker, bal)]) and the
              verdict is derived from the real outcome (the victim's balance leaves it).

Offline:      committed minimized clone; no fork, no live RPC. Built/run in Docker.

Harness:      MUST flag VULNERABLE (the permissionless forwarder spends the victim's standing
              approval). Expected: VULNERABLE (TP on split=holdout).
```
