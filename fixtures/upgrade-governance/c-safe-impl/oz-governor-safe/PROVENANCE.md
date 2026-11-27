# Fixture provenance

```
Fixture:      upgrade-governance/c-safe-impl/oz-governor-safe
Vector:       upgrade-governance
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin `governance/Governor.sol` + extensions (GovernorSettings,
              GovernorCountingSimple, GovernorVotes, GovernorVotesQuorumFraction,
              GovernorTimelockControl) + `TimelockController` + an `ERC20Votes` token - the
              canonical on-chain governance stack. The protected admin op is owned by the
              governance executor (the timelock), and a change requires a TOKEN-WEIGHTED VOTE to
              pass: propose -> vote -> queue -> execute through the timelock. The
              upgrade-governance vector (Audius-style instant single-key swap) is impossible: a
              lone key can neither call the protected op directly (only the timelock/governance
              executor may) nor pass a proposal without quorum + majority voting weight.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files governance/Governor.sol, governance/extensions/*.sol,
                    governance/TimelockController.sol, token/ERC20/extensions/ERC20Votes.sol
                    (+ ERC20, Votes, Checkpoints, EIP712 import closure) -> vendored
                    byte-identical under fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in
              fixtures/vendor/oz/LICENSE.
Source code:  ./OZGovernorGoverned.sol (thin concrete Governor wiring = the standard OZ override
              boilerplate with unmodified super calls; a minimal ERC20Votes token; and a
              governed vault whose `setImplementation` is `onlyGovernance`. Changes none of
              OpenZeppelin's governance logic.)
```

## Independent corroboration (the pattern, not an incident)
Safe-side PRECISION fixture - no incident to triangulate. The propose/vote/queue/execute
lifecycle and timelock-gated execution are the documented behaviour of OZ Governor:
- OZ Governor docs: https://docs.openzeppelin.com/contracts/5.x/governance
- OZ Governor API: https://docs.openzeppelin.com/contracts/5.x/api/governance#Governor

## Distinct from the other upgrade-governance safe fixtures
`oz-timelock-safe` / `solady-uups-timelock-safe` gate upgrades with a bare TIMELOCK;
`oz-accessmanager-safe` gates with ROLE + DELAY. This fixture requires a token-weighted VOTE to
pass (quorum + majority) before the timelock executes - a different governance mechanism.

## Why the harness must stay silent (BLOCKED)
The test wires a real Governor (token + timelock + quorum), has a lone attacker try to call the
vault's protected `setImplementation(hostile)` directly (reverts - only the timelock may), and
confirms the protected pointer is unchanged. A full legitimate proposal (delegate votes ->
propose -> vote -> queue -> execute after the timelock delay) then changes the pointer to the
benign target (non-vacuous: governance works). No instant single-key swap -> verdict BLOCKED.
