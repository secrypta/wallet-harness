# Fixture provenance

```
Fixture:      create2-metamorphic/b-incident/tornado-governance-victim
Vector:       create2-metamorphic
Tier:         b-incident
Split:        holdout
Expected:     vuln

Origin:       Tornado Cash governance takeover (2023-05-21). The attacker submitted a governance
              proposal whose logic lived at a deterministic address holding *benign* code at vote
              time - it mirrored an earlier, already-trusted "emergencyStop" proposal, so TORN
              holders voted it in. After approval the attacker SELFDESTRUCTed that code and
              redeployed *malicious* code at the SAME address (CREATE2 + CREATE/SELFDESTRUCT
              metamorphic reuse). Executing the still-approved proposal then wrote governance
              "locked balance" (vote weight) to ~100 attacker-controlled minion accounts
              (~10,000 TORN each), manufacturing roughly 1.2M votes against ~700k legitimate
              ones - a full governance takeover. The attacker drained TORN locked in governance
              and later (surprisingly) handed control back on 2023-05-26.

Reference:    - Official post-mortem: forum.tornado.ws/t/full-governance-attack-description/62
              - samczsun thread: x.com/samczsun/status/1660012956632104960
              - Coinspect "learn-evm-attacks" replication:
                github.com/coinspect/learn-evm-attacks/tree/master/test/Business_Logic/TornadoCash_Governance
              - pcaversaccio/tornado-cash-exploit (metamorphic PoC); rekt.news/tornado-gov-rekt;
                OpenZeppelin Apr-Jun 2023 security report; Composable Security analysis.

On-chain:     (Ethereum mainnet; all public, verified against the Coinspect replication - no live
              RPC used by this fixture)
              - Governance (victim): 0x5efda50f22d34f262c29268506c5fa42cb56a1ce
              - TORN token:          0x77777FeDdddFfC19Ff86DB637967013e6C6A116C
              - Attacker EOAs:       0x592340957ebc9e4afb0e9af221d06fdddf789de9
                                     0x092123663804f8801b9b086b03B98D706f77bD59
              - Factory + proposal deploy tx: 0x3e93ee75ffeb019f1d841b84695538571946fd9477dcd3ecf0790851f48fbd1a
              - Proposal submission tx:       0x34605f1d6463a48b818157f7b26d040f8dd329273702a0618e9e74fe350e6e0d
              - emergencyStop (destruction):  0xd3a570af795405e141988c48527a595434665089117473bc0389e83091391adb
              - Malicious redeploy tx:        0xa7d20ccdbc2365578a106093e82cc9f6ec5d03043bb6a00114c0ad5d03620122
              - Malicious execution tx:       0x3274b6090685b842aca80b304a4dcee0f61ef8b6afee10b7c7533c32fb75486d
              - TORN drain tx:                0x13e2b7359dd1c13411342fd173750a19252f5b0d92af41be30f9f62167fc5b94
              Attack block span 17,249,477 (malicious-proposal deploy) .. 17,304,426 (drain),
              per on-chain verification of the 6 cited txs. Reported loss $2.7M+.

Source code:  Self-contained fixture authored in this repo (MIT). No third-party source copied.
License:      MIT (this repo).

Minimization: TornadoGovernanceClone.sol models the shared mechanism, not the full DAO. A
              GovernanceClone approves a proposal address after a passing vote and grants the
              executing proposal a privileged `mintVotes`. MetamorphicProposal is a swappable-
              implementation holder standing in for the attacker's code at the fixed address:
              BenignProposalLogic (no-op emergencyStop) at vote time, MaliciousProposalLogic
              after. On execute() the mutated code mints the attacker the controlling vote
              balance. The ~100-minion fan-out is collapsed to one direct grant; the effect
              (attacker vote weight > honest majority) is identical.

Offline:      Fully offline; no live RPC, no fork. Deterministic Foundry test in Docker.

EIP-6780:     Post-Cancun (2024) the literal SELFDESTRUCT-then-redeploy-at-same-address trick is
              restricted, so - following the dev create2 fixture's convention - code mutation at a
              fixed address is modeled with a swappable implementation; the effective code
              identity is the implementation codehash, standing in for EXTCODEHASH(proposal).
              The attack as it happened (May 2023) predates EIP-6780. This fixture is distinct
              from the dev create2 b-incident (Scam Sniffer per-victim CREATE2 drainer / approval
              spend): that one abuses CREATE2 to spend a standing *token approval*; this one
              abuses metamorphic reuse to seize *governance vote weight*.

Harness:      MUST flag VULNERABLE (attacker ends with a controlling vote balance).
```
