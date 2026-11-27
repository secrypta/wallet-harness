# Fixture provenance (required header for every (b)/(c) fixture)

Copy this into a `PROVENANCE.md` at the root of each real-case fixture directory and fill
every field. A fixture that cannot be sourced to a PUBLIC origin does not go in
(see the validation standard in corpus/real-cases.md).

```
Fixture:      <vector>/<tier>-<slug>/<target>
Vector:       <approve-drainer | permit-phishing | set-approval-for-all | fake-airdrop | ...>
Tier:         <b-incident | c-safe-impl>
Expected:     <vuln | safe>            # ground-truth label (must match the meta `label`)

Origin:       <public incident write-up / CVE / audit report / repository URL>
Reference:    <tx hash | block number | post-mortem link | advisory id>
Source code:  <repo URL + commit SHA>  # exact pinned commit the fixture was minimized from
License:      <license of the copied code, e.g. MIT / GPL-3.0>  # keep upstream attribution

Minimization: <what was stripped to reproduce the vector offline; keep it faithful>
Offline:      <pinned bytecode | minimized copy | forked block N, committed cache>  # NO live RPC
Notes:        <anything a reviewer needs to reproduce the verdict>
```

Rules (hard - the scope/leak boundary):
- PUBLIC incidents only. Never anything non-public or from private engagements (targets,
  scope, findings, addresses, leads). When in doubt, leave it out.
- No checks against LIVE contracts. Offline fixtures only; a fork must pin its block and run
  from committed/cached data, inside Docker.
- Tier (c) must be GENUINELY safe real code (e.g. OpenZeppelin), not a lightly-edited toy.
