# Interface contract (frozen at `v0.1`)

This file defines the **stable interface** that downstream consumers (e.g. an educational
sandbox that uses the corpus as levels and the harness as a grader) build on. Everything
below is frozen as of the `v0.1` tag: **after the tag it is not changed silently.** Additive
changes (new vectors, new fixtures) are fine; a breaking change to any format below gets a
new tag and a note in this file's changelog.

Consumers should parse the machine-readable fields (`meta`, the verdict line), **not**
infer meaning from directory names or prose.

## 1. Vector specs - `corpus/*.md`

- One Markdown file per vector, named `corpus/<vector>.md`, where `<vector>` matches
  `[a-z0-9-]+` and equals the `vector` field used in fixtures and verdict lines.
- Each spec is the human contract-of-record for its vector. Conventional sections:
  **Class / Chain / Severity** header line, *What it is*, *Attack mechanics*,
  *Defensive signal* (what a harness/wallet policy must catch), *Targets* (the fixture
  targets and their expected verdicts), *Source base*. `[[other-vector]]` denotes a cross link.
- `corpus/real-cases.md` is the **validation standard** plus per-vector incident (tier b)
  and safe-basis (tier c) references, with an honest proof-level per entry
  (strong / incident-level / class-level).
- Prose may change; the **set of vector names** and their meaning are the stable part.

## 2. Labeled corpus layout - `fixtures/`

```
fixtures/<vector>/<tier-dir>/<target>/meta           # required, machine-readable
fixtures/<vector>/<tier-dir>/<target>/PROVENANCE.md   # required for tiers b and c
fixtures/<vector>/<tier-dir>/*.sol                    # fixture sources (tier b/c)
fixtures/vendor/**                                    # vendored third-party code + LICENSE + PROVENANCE
```

- `<tier-dir>` is organizational: `a-toy`, `b-incident`, `c-safe-impl`. **Do not key off the
  directory name** - read the tier from `meta`.
- `meta` is `key=value` lines (`#` comments allowed). Required keys:
  - `vector` - the vector name (`[a-z0-9-]+`), matches `corpus/<vector>.md`.
  - `tier` - `a` | `b` | `c`. (a = toy pair, b = real incident repro, c = real safe code.)
  - `target` - unique within its vector (`[a-z0-9-]+`). The key is the pair `(vector, target)`.
  - `label` - **ground truth**: `vuln` | `safe`. A grader's expected outcome:
    `vuln` ⇒ `VULNERABLE`, `safe` ⇒ `BLOCKED`.
  - `test` - the test file that exercises this target.
  - `provenance` - one-line source summary (full detail in `PROVENANCE.md`).
- Every vector carries all three tiers (a + b + c). Tier (c) is either genuinely-safe
  vendored code (`fixtures/vendor/`) or an honestly-marked reference implementation.
- `fixtures/vendor/` holds third-party sources byte-for-byte with their own `LICENSE` and a
  `PROVENANCE.md` (source + commit + license + any deviation).

## 3. Harness verdict format - `harness/`

- Each Foundry test emits, for each target it exercises, **exactly one line**:
  ```
  [<vector>] target=<target> verdict=<VULNERABLE|BLOCKED>
  ```
  `<vector>` and `<target>` match `[a-z0-9-]+`; `verdict` is `VULNERABLE` or `BLOCKED`.
  `VULNERABLE` = the attack landed; `BLOCKED` = the protected path held. The line is built
  with no stray spaces so it is greppable.
- `harness/run.sh` - toy smoke. Runs the suite in Docker, prints `<vector>: VERDICT` per
  target, and enforces the bar by target name (`*vulnerable*` ⇒ must be `VULNERABLE`,
  `*safe*`/`*protected*` ⇒ must be `BLOCKED`). Exit non-zero on any mismatch.
  Naming rule this implies: a **vuln** target name never contains `safe`/`protected`;
  a **safe** target name contains `safe`.
- `harness/benchmark.sh` - the grader. Loads every `fixtures/**/meta`, runs the suite in
  Docker, joins each `(vector, target)` to its emitted verdict, scores against `label`
  (TP/FP/FN/TN), and prints a confusion matrix + precision/recall. **Exit non-zero** on any
  false positive, false negative, or labeled fixture with no verdict (coverage gap).
- Build: Docker + `ghcr.io/foundry-rs/foundry`; `foundry.toml` sets `auto_detect_solc` and
  `via_ir = true` (the vendored Permit2 needs both). `lib/forge-std` is fetched by the
  consumer (pinned clone per the README), not vendored.

## 4. For a grader/levels consumer

- Corpus of vectors = a set of levels; the three tiers per vector = difficulty/credibility
  rungs (toy -> real incident -> real safe code).
- A level's pass/fail is `meta.label` vs the harness verdict: a solution must produce
  `VULNERABLE` on `vuln` targets and `BLOCKED` on `safe` targets - identical to how
  `benchmark.sh` scores. Reuse `benchmark.sh`'s join, or read `meta` + the verdict lines
  directly.

## Changelog
- `v0.1` - initial frozen interface. 12 vectors, each at a/b/c depth; benchmark scores 48
  labeled fixtures at precision = recall = 1.0.
- `v0.2.0` - additive growth since `v0.1`; all `v0.1` formats (meta keys, verdict line, manifest
  schema) are unchanged, so existing consumers keep working. Changes:
  - **+1 vector** `upgrade-governance` at full a/b/c depth - **13 vectors** total.
  - Corpus grown to **153 labeled fixtures** (32 `a`-toy + 121 `b`/`c`), 68 `vuln` / 85 `safe`;
    strict p/r/F1 = 1.0 on the full corpus (`TP=68 TN=85`, 0 FP/FN).
  - **Independent holdout grown to 92 fixtures** (`split=holdout`, 39 `vuln` real incidents /
    53 `safe` real code) covering **all 13 vectors**, scored apart (`--split holdout`): p/r/F1 = 1.0
    (`TP=39 TN=53`). *Correction (2026-11-22):* each holdout fixture ships with its own test, written
    together with the case, so this 1.0 is a corpus self-consistency check, not blind detector accuracy. 12 of 13
    vectors carry an independent *vulnerable* holdout; `fake-airdrop` is precision-side (safe-only).
  - Every tier-b real incident carries web-verified provenance (on-chain tx and/or authoritative
    post-mortem / audit; incidents with no pinnable tx are modeled at mechanism level with an
    explicit disclaimer). Every tier-c safe fixture is unmodified permissive third-party code
    (OpenZeppelin, Solady, Uniswap Permit2, ERC721A) or an honestly-disclaimed minimized post-fix
    reproduction - never a lightly-edited toy.
  - **Baseline harness** (`bench/results/BASELINES.md`): wal's own result plus a reproducible,
    documented way to run general-purpose analyzers against the same corpus yourself. No published
    per-tool leaderboard - wal is a dynamic harness and the general tools are static, so a scored
    head-to-head would be apples-to-oranges; a like-for-like static comparison belongs with a static
    drain scanner, not here. `bench/score.sh --list` prints the targets to produce verdicts for, and a
    normal run now prints an actionable FP/FN/MISS summary ("what to look at"), not just aggregate numbers.
    `--template` emits a fillable verdict file; `--json` emits a machine-readable result (composes with `--strict`).
    A top-level `Makefile` wraps the common entry points (`make doctor`/`ctf`/`selftest`/`bench`/`forge-std`).
  - The benchmark is a growing corpus; `split` keeps the independent (holdout) slice separable
    from the development (dev) slice for honest reporting.
  - **New `ctf/` layer - additive, does not touch any `v0.1`/benchmark format.** "Patch the
    drain": one challenge per vector (13 mechanisms) **plus incident-anchored challenges built
    from real drains - 27 in all**, each a vulnerable wallet to fix behind a two-sided hidden
    gate (block the drain *and* keep the legitimate feature). Incident challenges carry verbatim
    provenance in `meta`. Its own runner (`ctf/ctf.sh`: `list`/`start`/`solve`/`hint`/`diff`/
    `reset`/`selftest`/`doctor`, local offline progress tracker, difficulty-ordered) and self-contained test doubles - it does **not** import the
    corpus, fixtures, vendor code, or the harness verdict format, so it shares only the vectors and
    the gate *principle*, never code. `ctf.sh selftest` enforces ground truth (seed->FAIL, solution->PASS).
- `unreleased` - additive growth since `v0.2.0` (version tag assigned at release). All `v0.1`/`v0.2.0`
  formats (meta keys, verdict line, manifest schema) are unchanged, so existing consumers keep working.
  Changes:
  - Corpus grown to **155 labeled fixtures** (70 `vuln` / 85 `safe`): **+2** real-incident
    `signature-phishing` cases for the ERC-1271 forged / permissive contract-signer surface
    (Lumi/Sodium 2026, Odos ERC-6492 2025), both `split=holdout`, each with explorer-verified provenance.
  - **Independent holdout grown to 94 fixtures** (41 `vuln` / 53 `safe`), still covering all 13 vectors;
    strict p/r/F1 = 1.0 on both splits (`all`: `TP=70 TN=85`; `holdout`: `TP=41 TN=53`, 0 FP/FN) -
    a corpus self-consistency check (every label confirmed by executing its own reproduction), not blind detector accuracy.
  - Both new incidents carry executable Foundry exploit tests, so the dynamic harness now runs **every**
    labeled fixture with **0 MISS** (`harness/benchmark.sh`: `TP=70 FP=0 FN=0 TN=85 missing=0`).
