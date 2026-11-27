# Contributing to drain-bench

Two kinds of contribution are welcome, and they are handled very differently:

1. **Results** - you ran a detector over the fixtures and want to share its numbers.
2. **Fixtures** - you have a new drain case (ideally a real public incident, or a
   genuinely-safe real implementation) to add to the dataset.

> **Posture (read this first).** A result under `results/<tool>/` is **your own
> self-report**. We re-run and review it before merging, and we host it so the command
> and mapping are reproducible - but it is **not drain-bench's rating of your tool**, and
> we do **not** publish a leaderboard comparing third-party tools. A low score usually
> means the tool was never built to catch drain-UX (see the *Scope caveats* in
> [`README.md`](README.md)), not that the tool is bad. We describe; we do not rank.

---

## 1. Contributing results

### Step 1 - produce a verdict file

Run your detector over the fixtures (sources under [`../fixtures/`](../fixtures/)) and emit
one line per scored target, in the dataset's tool-agnostic schema:

```
[<vector>] target=<target> verdict=<VULNERABLE|BLOCKED>
```

- `<vector>` and `<target>` are the dataset keys - see
  [`dataset/manifest.tsv`](dataset/manifest.tsv) (columns `vector`, `target`). Both match
  `[a-z0-9-]+`.
- `VULNERABLE` = your tool flagged a drain / unsafe action on that target.
- `BLOCKED` = your tool judged it safe / stayed silent.
- Lines that don't match the schema are ignored by the scorer, so a header comment
  (prefixed `#`) is fine.

Mapping your tool's **native** output (a severity, a rule id, a pass/fail, a diff) onto
`VULNERABLE`/`BLOCKED` is a judgement call. **It is the single easiest place to
accidentally inflate or deflate a score**, so it must be written down in `META.md` (Step 4).

### Step 2 - validate the file

`score.sh` silently ignores any line it can't parse and de-duplicates the rest, so a typo'd
vector name, a conflicting duplicate, or a malformed line disappears without warning and
quietly skews the numbers. Lint the file first:

```
bench/validate-verdicts.sh <your-verdicts-file> [--manifest <path>] [--strict]
```

It reports `MALFORMED` (a line that looks like a verdict but doesn't match the schema),
`UNKNOWN` (a `(vector,target)` not in the manifest - usually a typo), `CONFLICT` (the same
target given two different verdicts), `DUP` (a harmless exact repeat), and `MISS` (a
coverage gap - informational, never a failure). Report-only by default; `--strict` exits
non-zero on any `MALFORMED`/`UNKNOWN`/`CONFLICT`. It does **not** score - it only checks the
file's shape against the dataset keys. Fix anything it flags before Step 3.

### Step 3 - score it locally

```
bench/score.sh <your-verdicts-file> [--split dev|holdout|all] [--strict]
```

Report-only by default (prints precision / recall / F1 + a per-vector breakdown and exits
0). `--strict` exits non-zero on any FP, FN, or MISS - that is what *our own* CI uses; you
do not need to pass `--strict` for a third-party tool, since FP/FN/MISS are expected.

A labeled fixture with **no matching verdict line** is a coverage gap (`MISS`), not a
wrong answer. Reporting only on the vectors your tool actually targets is fine and
honest - leave the rest as MISS rather than guessing.

### Step 4 - lay out `results/<tool>/`

Pick a short lowercase `<tool>` slug (`[a-z0-9-]+`). The directory must be
self-contained and reproducible:

```
bench/results/<tool>/
├-- verdicts.txt   # required - the schema lines from Step 1 (a '# ...' header is fine)
├-- META.md        # required - fill in every field of the template below
└-- raw/           # required - the tool's raw, unedited output (one or more files)
```

- **`verdicts.txt`** - exactly what you scored. Nothing hand-edited after the run.
- **`raw/`** - the detector's own output, captured verbatim (logs, JSON, SARIF, a report
  file - whatever it emits). This is what lets us reproduce your `verdicts.txt` from the
  tool, so keep it unedited.
- **`META.md`** - the provenance of the run. Copy
  [`results/EXAMPLE/META.md`](results/EXAMPLE/META.md) and fill in:
  - tool **name + exact version / commit**,
  - the **exact command(s)** you ran (so we can re-run them),
  - the **mapping rule** (native output -> `VULNERABLE`/`BLOCKED`), stated precisely,
  - the **environment** (OS, Docker image, chain/fork if any),
  - date, and a one-line statement that this is your self-report.

See [`results/EXAMPLE/`](results/EXAMPLE/) for a complete, runnable stub.

### Step 5 - open a PR

Add only your `results/<tool>/` directory. We will:

1. re-run your command from `META.md` against the current fixtures,
2. check that `verdicts.txt` follows from `raw/` via the stated mapping,
3. merge it as **your** self-report (we keep your `META.md` statement; we add no rating of
   our own).

We may ask for clarification on the mapping, or decline to host a result we cannot
reproduce. That is a reproducibility bar, not a judgement of the tool.

#### Checklist

- [ ] `bench/validate-verdicts.sh results/<tool>/verdicts.txt --strict` passes (no
      MALFORMED / UNKNOWN / CONFLICT; DUP / MISS are fine).
- [ ] every `<vector>`/`<target>` exists in `dataset/manifest.tsv`.
- [ ] `raw/` contains the unedited tool output that `verdicts.txt` was derived from.
- [ ] `META.md` states version, exact command, mapping rule, environment, date.
- [ ] `bench/score.sh results/<tool>/verdicts.txt` runs clean (any FP/FN/MISS are fine).
- [ ] you only added files under `results/<tool>/`.

### (optional) CI - validate on every push

If you track your results in your own repo, wire the validator into CI so a malformed or
drifted verdict file fails the build. A minimal GitHub Actions template (adjust paths to
where you vendor or submodule drain-bench):

```yaml
# .github/workflows/drain-bench-verdicts.yml
name: drain-bench verdicts
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate verdict schema + dataset keys
        run: |
          bench/validate-verdicts.sh results/<tool>/verdicts.txt \
            --manifest bench/dataset/manifest.tsv --strict
      # Optional: also score (report-only - FP/FN/MISS do not fail a 3rd-party tool).
      # Drop --strict here unless you intend to require full coverage + 0 FP/FN.
      - name: Score (report-only)
        run: bench/score.sh results/<tool>/verdicts.txt
```

`validate-verdicts.sh --strict` is safe to gate CI on: it fails only on broken input
(MALFORMED / UNKNOWN / CONFLICT), never on a legitimate coverage gap. Gating on
`score.sh --strict` instead means requiring full coverage and zero FP/FN - appropriate for
wal's own suite, usually too strict for a third-party tool.

---

## 2. Contributing fixtures

New fixtures are a bigger change and follow the corpus rules, **not** this file. In short:
each fixture is an executable case with a label (`vuln`/`safe`), a tier (a/b/c), and
provenance, and a real incident (`b`) must come from a **public** post-mortem / CVE /
tx-hash. The authoritative standard is [`../corpus/real-cases.md`](../corpus/real-cases.md);
the dataset layout is in [`README.md`](README.md). A genuinely independent `holdout` can
only be a **new** fixture authored without tuning wal to it (see the honesty section of
`README.md`). If in doubt, open an issue describing the case before writing code.

---

## License

By contributing you agree your contribution is licensed under the repo's MIT license
(see [`../LICENSE`](../LICENSE)). Any vendored third-party code you include must keep its
own attribution and license and be recorded in the fixture's `PROVENANCE.md`.
