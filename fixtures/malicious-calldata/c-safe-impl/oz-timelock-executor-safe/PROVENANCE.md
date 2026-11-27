# Fixture provenance

```
Fixture:      malicious-calldata/c-safe-impl/oz-timelock-executor-safe
Vector:       malicious-calldata
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin `governance/TimelockController.sol` - a canonical, widely-deployed
              arbitrary-call executor. `execute(target, value, payload, predecessor, salt)`
              performs a low-level call to ANY target with ANY payload - exactly the
              arbitrary-external-call shape the malicious-calldata vector abuses (Socket 2024:
              caller supplies target + calldata and the contract runs it against a victim's
              standing approval). It is safe not because the sink is absent but because
              reaching it is gated: `schedule` requires PROPOSER_ROLE; `execute` requires
              EXECUTOR_ROLE AND the operation to have been scheduled with the min-delay
              elapsed. An attacker holding neither role cannot inject
              `transferFrom(victim, attacker, ...)`.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              file governance/TimelockController.sol (+ AccessControl import closure) ->
                   vendored byte-identical under fixtures/vendor/oz/ (see
                   fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in
              fixtures/vendor/oz/LICENSE.
Source code:  ./OZTimelockExecutor.sol authors NO logic - it only re-exports the unmodified OZ
              TimelockController so the fixture has a local subject symbol. The test drives the
              real contract directly.
```

## Independent corroboration (the pattern, not an incident)
Safe-side PRECISION fixture - no incident to triangulate. The role + schedule + min-delay
gating of the executor is the documented behaviour of OZ TimelockController:
- OZ TimelockController docs: https://docs.openzeppelin.com/contracts/5.x/api/governance#TimelockController
- OZ governance guide: https://docs.openzeppelin.com/contracts/5.x/governance

## Distinct from the upgrade-governance timelock fixture
`upgrade-governance/c-safe-impl/oz-timelock-safe` uses a TimelockController as the UPGRADE
authority of a UUPS wallet (vector: implementation swap). Here the TimelockController ITSELF
is the executor that holds a victim's standing approval, and the vector is arbitrary-external
-call injection against that approval. Different subject, different vector.

## Why the harness must stay silent (BLOCKED)
The test deploys a real `TimelockController` (proposer/executor roles, 2-day min-delay), has a
victim grant it a standing max approval, then has an unauthorized attacker try to drain via
`execute(token, 0, transferFrom(victim, attacker, ...))` (reverts - unscheduled / no
EXECUTOR_ROLE) and via `schedule(...)` (reverts - no PROPOSER_ROLE). A proposer/executor pair
legitimately schedules and, after the delay, executes a benign call (non-vacuous). The victim
is never drained -> verdict BLOCKED.

If a (future) static malicious-calldata detector flagged this as VULNERABLE, that would be a
genuine detector false positive on a gated arbitrary-call executor - to be recorded as a
finding, NOT masked by altering this fixture.
