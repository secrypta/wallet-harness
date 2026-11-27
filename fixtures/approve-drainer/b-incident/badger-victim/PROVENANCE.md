# Fixture provenance

```
Fixture:      approve-drainer/b-incident/badger-victim
Vector:       approve-drainer
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)

Origin:       BadgerDAO front-end compromise / approval-injection drain
Reference:    Attacker/spender: 0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107 (500+ approvers)
              Example victim:   0x53461e4fddcc1385f1256ae24ce3505be664f249
              Approval tx (increaseAllowance ~6h before drain):
                0x5e4c7966b0eaddaf63f1c89fc1c4c84812905ea79c6bee9d2ada2d2e5afe1f34
              Drain tx (transferFrom, ~900 byvWBTC ~= $50.8M - the largest single-victim tx):
                0x951babdddbfbbba81bbbb7991a959d9815e80cc5d9418d10e692f41541029869
              Date: 2021-12-02, drain from 00:00:23 UTC
              Source: rekt.news/badger-rekt + Etherscan (all public)
Source code:  ../BadgerSettClone.sol (authored minimized clone, this repo)
License:      MIT (this repo). No third-party code copied; the drained token's full vault
              logic is NOT reproduced - only the OZ-style allowance + transferFrom surface
              needed to replay the documented path.

Minimization: Modeled only `approve` / `increaseAllowance` / `transferFrom` with standard
              OpenZeppelin-style allowance accounting (8-decimal WBTC-based vault token).
              Vault share accounting, strategies and access control omitted - irrelevant to
              the approve-drain path. The example victim/attacker addresses above are used
              as-is for fidelity.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        VICTIM_BALANCE in the test (900e8) models the LARGEST single victim, who lost
              ~900 byvWBTC (~$50.8M) in the single drain tx above (per The Block / PeckShield).
              The full incident drained ~$120M total across 500+ approvers through the same
              front-end approval-injection path; this fixture replays that path, not the total.
              test/BadgerIncident.t.sol replays increaseAllowance -> transferFrom and the
              verdict is derived from the real outcome (balance emptied). Expected: VULNERABLE (TP).
```
