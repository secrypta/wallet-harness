# fixtures/ - labeled benchmark corpus (ground truth)

Each vector is validated against an **independent labeled corpus**, not only its own toy
pair, and `harness/benchmark.sh` reports precision/recall against these labels. See the
validation standard in [../corpus/real-cases.md](../corpus/real-cases.md).

## Layout

```
fixtures/<vector>/<tier>-<slug>/<target>/
    meta            # key=value label manifest (see below) - REQUIRED
    PROVENANCE.md   # provenance header (REQUIRED for tier b/c; see PROVENANCE.template.md)
    ...             # vendored/minimized source for tier b/c (with license + attribution)
```

Tiers (see the validation standard):
- `a-toy/` - an MIT toy pair (one `vuln`, one `safe`). Fast mechanics smoke.
- `b-incident/` - >=1 minimized reproduction of a real public bug, label `vuln`.
- `c-safe-impl/` - >=1 genuinely safe real implementation (e.g. OpenZeppelin), label `safe`.

## The `meta` file (label manifest)

Flat `key=value`, one per line (`#` comments ignored):

```
vector=approve-drainer          # vector name; matches the "[vector]" in the verdict line
tier=a                          # a | b | c
target=vulnerable-wallet        # the target id; matches "target=" in the verdict line
label=vuln                      # ground truth: vuln | safe
test=test/ApproveDrainer.t.sol  # the Foundry test that exercises this target (informational)
provenance=...                  # one-line origin; full block goes in PROVENANCE.md for b/c
```

The benchmark key is the pair **(vector, target)** - target ids are reused across vectors
(e.g. `vulnerable-wallet` exists for both `approve-drainer` and `set-approval-for-all`), so
only the pair is unique.

## How the label is checked

`harness/benchmark.sh` runs the whole Foundry suite in Docker, collects every
`[<vector>] target=<target> verdict=<VULNERABLE|BLOCKED>` line, joins each to its `meta`
label by `(vector, target)`, and scores:

| label | verdict    | cell | meaning                 |
|-------|------------|------|-------------------------|
| vuln  | VULNERABLE | TP   | real bug flagged        |
| vuln  | BLOCKED    | FN   | real bug missed         |
| safe  | BLOCKED    | TN   | safe code stayed silent |
| safe  | VULNERABLE | FP   | false positive          |

Target: **recall = 1.0** on `vuln`, **precision = 1.0** on `safe` (0 false positives).

## Adding a fixture (tier b/c)

1. Create `fixtures/<vector>/<b-incident|c-safe-impl>/<target>/`.
2. Add a `meta` file (above) and a filled `PROVENANCE.md` (copy `PROVENANCE.template.md`).
3. Add a Foundry test under `test/` that drives the fixture and emits exactly one
   `[<vector>] target=<target> verdict=...` line (reuse the `_report` pattern).
4. Run `harness/benchmark.sh` - the new `(vector, target)` is picked up automatically; a
   labeled fixture with no matching verdict line fails the run (coverage gap).
