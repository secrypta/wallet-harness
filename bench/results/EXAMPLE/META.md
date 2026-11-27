# acme-approve-lint - run metadata (EXAMPLE / fictional)

> **This is a template + a fictional example, not a real result.** Copy this file to
> `bench/results/<your-tool>/META.md` and replace every field. The tool
> `acme-approve-lint` does not exist; the numbers below are illustrative.

- **Tool:** acme-approve-lint
- **Version / commit:** v0.0-example (commit `0000000`)
- **Run by:** (self-report - the submitter; drain-bench does not rate this tool)
- **Date (UTC):** 2026-11-14

## Exact command(s)

```sh
# (fictional) run the linter over every fixture source and capture raw output
acme-approve-lint --format json fixtures/ > raw/acme-approve-lint.json
```

## Mapping rule (native output -> verdict)

State this precisely - it is the easiest place to inflate or deflate a score.

- acme-approve-lint emits one JSON finding per target with a `severity` field.
- `severity` of `high` or `critical`  -> `VULNERABLE`.
- no finding for a target, or `severity: info`  -> `BLOCKED`.
- The tool only has rules for the `approve-drainer` vector, so it emits **no** findings
  for the other 11 vectors. Those targets are left out of `verdicts.txt` entirely and
  score as `MISS` (coverage gap), **not** as `BLOCKED` - we do not guess a verdict the
  tool never produced.

## Environment

- OS: (e.g. Ubuntu 24.04)
- Runtime / image: (e.g. node 20, or a Docker image + tag)
- Chain / fork: n/a (static analysis; no on-chain run)

## Note

This is the submitter's own self-report. drain-bench re-runs the command above and checks
that `verdicts.txt` follows from `raw/` via the mapping rule, then hosts it as-is. A
non-perfect score here (this fictional tool MISSes 66 of 70 fixtures) reflects the tool's
narrow scope, not its quality - see the scope caveats in [`../../README.md`](../../README.md).
