# drain-bench - wal's result, and a reproducible baseline harness

This file reports **wal's own score on the drain corpus** and gives you everything to run
general-purpose Solidity analyzers against the same fixtures **yourself**: the dataset, the scorer,
the per-tool run harness, and the documented mapping rules.

It deliberately does **not** publish a head-to-head leaderboard of third-party tools. wal is a
*dynamic* harness - it executes the attack and reads balances - while the general-purpose tools are
*static* analyzers that read source. A single scored table across the two would compare apples to
oranges, and a perfect dynamic score set against static tools is close to tautological. The honest,
reproducible pieces are all here; you draw your own comparison by running them. A fair, like-for-like
comparison - a *static*, drain-specific scanner against general static analyzers on the same source
input - belongs with that scanner, not in this harness's results.

**Corpus accounting (read first).** The corpus is **155 labeled fixtures**. A static analyzer is
pointed at a `.sol` file, so a fixture is scored by such a tool only when it has a first-party
scanned contract to point at: **152** fixtures map to a subject contract in
`bench/tools/baseline-targets.tsv`, and those 152 targets resolve to **127 unique scanned `.sol`
files** (several permit/permit2 variants legitimately share one first-party wrapper - the variants
differ only in the off-chain flow, so a static analyzer sees the same file N times and returns one
verdict replicated across those rows; a *same-subject pair*). The remaining **3** fixtures have no
target-specific first-party contract at all (only shared mocks), so there is nothing to hand a
static analyzer and they are scored **MISS**, never a guessed verdict. wal's *dynamic* harness runs
the flow for **every** labeled fixture, so it covers all **155** - including the two R15
signature-phishing incident clones (`sodium-erc1271-victim`, `odos-erc6492-victim`), which have
executable Foundry exploit tests: a forged / permissive ERC-1271 signer coerced into a max ERC-20
approval, and an ERC-6492 counterfactual-deploy arbitrary call made from the router during signature
validation. R15 is **also** static-validated via drain-scan + its `all.sh` anchors; each clone has a
first-party contract the static baselines scan as well.

## wal's result

| split | fixtures | TP | FP | FN | TN | MISS | precision | recall | F1 |
|-------|----------|----|----|----|----|------|-----------|--------|-----|
| **all** (full labeled corpus) | 155 | 70 | 0 | 0 | 85 | 0 | **1.000** | **1.000** | **1.000** |
| **holdout** (independent, post-freeze) | 94 | 41 | 0 | 0 | 53 | 0 | **1.000** | **1.000** | **1.000** |

*precision = TP/(TP+FP), recall = TP/(TP+FN). wal's dynamic harness runs an exploit/control test for
every labeled fixture - the R15 ERC-1271 / ERC-6492 incident clones included - so it has no coverage
gap (MISS) on this corpus. (The static baselines below still MISS the 3 off-chain-only OMIT fixtures,
which have no first-party contract to point at.)*

**What this does and does not claim.** wal's detectors were authored against the dev-split
fixtures, so scoring 1.0 on `split=all` is expected **by construction** - it is *not* an independent
result on that split. The meaningful number is the **holdout**: 94 fixtures (41 `vuln` / 53 `safe`)
authored *after* the detectors froze, covering all 13 vectors, which wal was **not** tuned to - wal's
dynamic harness scores all 94 and holds 1.0 there too. That is the honest evidence the dev-split
result is not a tuning artifact. It
is a statement about *this corpus*, not a claim that wal is flawless on arbitrary code.

## Running a baseline yourself (methodology)

To see how off-the-shelf analyzers fare on the corpus, the harness runs each one in Docker,
**default config, no tuning**, over the same fixtures, maps its native output to drain-bench verdicts
by a documented rule, and scores it with `bench/score.sh`. The per-tool invocation and output-to-verdict
mapping are documented in `bench/tools/run-baseline.sh`; when you run a tool, its run metadata and raw
output are written under `bench/results/<tool>/` for you to inspect and publish or not - **your** result,
not ours. A few things to keep the exercise honest:

- **Score the general tools generously.** A fair mapping counts *any* serious finding on the subject
  contract as a catch (e.g. Slither High/Medium impact; Mythril any SWC issue; Semgrep any match) -
  even when the finding is a generic warning unrelated to the drain. This is the generous direction:
  it inflates a general tool's recall, and it is the honest reason precision comes out low (general
  tools flag safe OZ/Solady code for generic reasons - unused-return, external-call/reentrancy - and
  still miss drain vectors that have no low-level-call or classic-bug signature).
- **A low score is not a criticism of the tool.** Slither, Mythril, Wake, Semgrep and the rest are
  excellent general-purpose analyzers; they were simply never designed for the wallet-drain niche
  (approval scope, signing policy, address poisoning, delegation/upgrade authority). That niche is
  what drain-bench measures and what a drain-specific harness covers.
- **Static tools cannot see an off-chain-only difference.** Where a safe and a vuln target share one
  contract (the difference is in the off-chain signing or front-end flow), a static analyzer
  necessarily returns the same verdict for both - an honest coverage fact, and why 152 targets
  collapse to 127 scanned files. wal's dynamic harness does separate them (it runs the flow).
- **The 3 OMIT fixtures** - `permit-phishing/{safe-permit,vulnerable-permit}` and
  `set-approval-for-all/premint-operator-victim` - have no target-specific first-party contract (only
  shared mocks); the safe/vuln difference is purely off-chain, so there is no code artifact to hand a
  static analyzer, and they are scored MISS.
- **Symbolic/formal engines MISS what they cannot finish in time.** If you run Mythril or SMTChecker,
  give them a per-file timeout; a file whose analysis does not complete produces no output and is a
  coverage gap (MISS), not a wrong answer.
- **Tool availability on `^0.8.24` (reproduction note).** Some standalone analyzers no longer install
  cleanly or lag the pragma, so a reproduction attempt isn't surprised: **Aderyn** (Cyfrin) is retired
  upstream (installer withdrawn); **4naly3er** pins `solc-js 0.8.23` and fails to compile `^0.8.24`
  as-shipped; **Pyrometer** is a beta manual-verification aid that outputs bound analysis, not a
  per-contract pass/fail; **Halmos** verifies symbolic `check_*` test functions, not point-at-a-`.sol`
  findings. These are observations, recorded rather than dropped silently.
- **Licensing.** If you run the copyleft tools - Slither and Falcon (**AGPL-3.0**), SMTChecker/solc
  (**GPL-3.0**) - run them **as external processes only**; none is imported or linked into wal's MIT
  code. Solhint (MIT) and Wake (ISC) are permissive but are likewise external.

## Reproduce

All tools run in Docker (container cap 3). Mythril and SMTChecker need the host's pinned solc staged
in; others fetch or bundle their own. Tools with no suitable prebuilt image (Solhint, Wake, Falcon)
are installed at a pinned version/commit in a base image at run time (see each META). The Permit2
fixtures pin solc 0.8.17 (Permit2's own pragma).

```sh
bench/tools/run-baseline.sh slither    && bench/score.sh bench/results/slither/verdicts.txt
bench/tools/run-baseline.sh mythril    && bench/score.sh bench/results/mythril/verdicts.txt
bench/tools/run-baseline.sh semgrep    && bench/score.sh bench/results/semgrep/verdicts.txt
bench/tools/run-baseline.sh solhint    && bench/score.sh bench/results/solhint/verdicts.txt
bench/tools/run-baseline.sh wake       && bench/score.sh bench/results/wake/verdicts.txt
bench/tools/run-baseline.sh falcon     && bench/score.sh bench/results/falcon/verdicts.txt
bench/tools/run-baseline.sh smtchecker && bench/score.sh bench/results/smtchecker/verdicts.txt
bench/tools/run-baseline.sh solc       && bench/score.sh bench/results/solc/verdicts.txt
bench/tools/run-baseline.sh remix      && bench/score.sh bench/results/remix/verdicts.txt
bench/tools/run-wal.sh                 && bench/score.sh bench/results/wal/verdicts.txt
```

Each run also supports `--split holdout` for the independent slice.

When the corpus grows, a baseline can be replayed cheaply on just the new fixtures instead of
re-running the whole tool over every source: pass the new `.sol` paths after the tool name, e.g.
`bench/tools/run-baseline.sh slither fixtures/<vector>/<new>.sol ...`. In this delta mode `raw/` is
kept and only the named subjects are re-analyzed; `verdicts.txt` is then regenerated from the full
`raw/` + `baseline-targets.tsv`, so the result is identical to a full re-run. Whole-project tools
(Wake) always re-scan the whole tree regardless.
