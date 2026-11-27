# EXAMPLE - a runnable results stub

This directory is a **complete, fictional example** of a third-party results submission.
It shows the exact layout and the full flow from a tool run to a scored result. The tool
`acme-approve-lint` is **not real** and these numbers are illustrative - copy the shape,
not the content. The authoritative rules are in [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md).

## Layout (what every `results/<tool>/` looks like)

```
EXAMPLE/
├-- README.md                     # this file (your real submission doesn't need one)
├-- META.md                       # required - version, exact command, mapping rule, env
├-- verdicts.txt                  # required - the schema lines, scored by score.sh
└-- raw/
    └-- acme-approve-lint.json    # required - unedited native tool output
```

## How this stub was "generated"

`acme-approve-lint` is a fictional static linter that only has rules for the
`approve-drainer` vector. The (pretend) command was:

```sh
acme-approve-lint --format json fixtures/ > raw/acme-approve-lint.json
```

`verdicts.txt` is then the raw JSON mapped through the rule documented in
[`META.md`](META.md): `severity high|critical -> VULNERABLE`, `info / no finding -> BLOCKED`.
The tool reports on only four `approve-drainer` targets; everything it says nothing about -
the other 12 vectors, plus the `approve-drainer` cases it has no rule for - is omitted and
scores as `MISS`.

## Feed it to the scorer

From the repo root:

```sh
bench/score.sh bench/results/EXAMPLE/verdicts.txt
```

Expected (illustrative) outcome:

- `approve-drainer`: 2 TP + 2 TN - the tool is correct on the four targets it reported.
- everything else: **66 MISS** - coverage gaps, because the tool reported nothing there
  (the other 12 vectors, plus the `approve-drainer` cases it has no rule for). The scorer
  prints these; in report-only mode (the default) it still exits 0.
- `precision=1.000 recall=1.000` **on the four targets it scored** - MISS is a coverage
  gap, not a false negative, so it does not drag recall down. The 66 MISS lines are the
  honest signal that this tool is narrow in scope.

Running with `--strict` would exit non-zero (because of the 66 MISS). That is expected for
a narrowly-scoped third-party tool - `--strict` is for wal's own CI, not for grading other
people's tools. See the scope caveats in [`../../README.md`](../../README.md).
