# wallet-harness

[![ci](https://github.com/secrypta/wallet-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/secrypta/wallet-harness/actions/workflows/ci.yml)

A reproducible corpus of **wallet-drain attack vectors** as executable test cases, plus a
harness that runs a target wallet or dApp flow against them and reports **what it withstood**.

Every vector is proven by its test body, never by prose: the harness must fire on code that
is actually drainable and stay **silent** on code that is actually safe. The bar is
**0 false positives and 0 false negatives**, measured as precision/recall against a labeled
corpus with ground truth.

This is a builder's tool (the kind of developer infrastructure an EF ESP grant funds), not an
end-user product: a shared, executable yardstick for the wallet-drain threat class.

## Quickstart

Everything runs offline in Docker; Foundry runs inside the container, so you only need **Docker + git**.

```sh
# 1. get the repo + its one build dependency (forge-std, pinned; lib/ is git-ignored)
git clone <this-repo> wallet-harness && cd wallet-harness
git clone --depth 1 --branch v1.9.4 https://github.com/foundry-rs/forge-std lib/forge-std

# 2. check prerequisites - tells you exactly what's missing and how to fix it
./ctf/ctf.sh doctor

# 3a. solve your first CTF challenge (fix a deliberately vulnerable wallet)
./ctf/ctf.sh list                    # browse challenges ( - unsolved / ✓ solved )
./ctf/ctf.sh start approve-drainer   # seeds ctf/work/approve-drainer/src/Challenge.sol + prints the brief
#    ...edit that file to patch the drain...
./ctf/ctf.sh solve approve-drainer   # runs the hidden two-sided gate in Docker -> security / functionality

# 3b. or score your own detector against the benchmark
bench/score.sh --list                # the (vector, target) pairs to produce verdicts for
bench/score.sh my-verdicts.txt       # confusion matrix + precision/recall/F1 + exactly what you missed
```

## Why this exists

Wallet-drain losses are dominated by a small set of well-understood **authorization**
patterns - standing unlimited approvals, off-chain signature phishing, poisoned address
history, account delegation. Individually these are known; what is missing is a common,
*executable* way to ask a concrete wallet or dApp flow: *which of these do you actually
resist?*

`wallet-harness` answers that. Each vector is a minimized, offline, reproducible scenario
whose verdict comes from the real on-chain outcome (did the funds move?), so "resists vector
X" is a test result, not a claim.

## Vectors

13 vectors, each built to the same three-tier depth (see
[Validation](#validation-three-independent-tiers)): an `a-toy` pair, a `b-incident` minimized
from a real public case, and a `c-safe-impl` genuinely-safe implementation.

| Vector | Attack class | Spec | Tiers |
|---|---|---|---|
| `approve-drainer` | unlimited ERC-20 approval abuse | [spec](corpus/approve-drainer.md) | a - b - c ✅ |
| `permit-phishing` | EIP-2612 off-chain permit signature | [spec](corpus/permit-phishing.md) | a - b - c ✅ |
| `set-approval-for-all` | ERC-721/1155 blanket operator approval | [spec](corpus/set-approval-for-all.md) | a - b - c ✅ |
| `signature-phishing` | EIP-712 typed order signature (Seaport/Wyvern) | [spec](corpus/signature-phishing.md) | a - b - c ✅ |
| `fake-airdrop` | scam-token bait inducing approval on a real asset | [spec](corpus/fake-airdrop.md) | a - b - c ✅ |
| `address-poisoning` | look-alike recipient from poisoned tx history | [spec](corpus/address-poisoning.md) | a - b - c ✅ |
| `malicious-calldata` | mislabeled / multicall-hidden approval in calldata | [spec](corpus/malicious-calldata.md) | a - b - c ✅ |
| `eip7702-delegation` | EIP-7702 account-delegation abuse (post-Pectra) | [spec](corpus/eip7702-delegation.md) | a - b - c ✅ |
| `permit2-phishing` | Uniswap Permit2 signature phishing | [spec](corpus/permit2-phishing.md) | a - b - c ✅ |
| `create2-metamorphic` | metamorphic code swap at an approved CREATE2 address | [spec](corpus/create2-metamorphic.md) | a - b - c ✅ |
| `delegatecall-hijack` | `delegatecall` operation / implementation swap | [spec](corpus/delegatecall-hijack.md) | a - b - c ✅ |
| `blind-eth-sign` | blind raw-hash (`eth_sign`) signing | [spec](corpus/blind-eth-sign.md) | a - b - c ✅ |
| `upgrade-governance` | single-key proxy upgrade without timelock/guardian | [spec](corpus/upgrade-governance.md) | a - b - c ✅ |

Each `corpus/<vector>.md` is the **contract-of-record** for its vector: the attack mechanics,
the defensive signal a wallet policy should catch, and the exact benchmark targets.

## Validation: three independent tiers

A toy pair on its own is weak evidence - *"you wrote both the vulnerable and the safe
contract, of course your checker catches your own."* To answer that, every vector is scored
against an **independent, labeled corpus** with ground truth, across three tiers:

- **(a) `a-toy`** - a minimal vulnerable/safe pair authored here. Fast smoke test of the
  vector's mechanics.
- **(b) `b-incident`** - a **minimized, offline reproduction of a real, public incident**
  (post-mortem / CVE / documented drainer pattern). The harness **must** flag it
  `VULNERABLE`.
- **(c) `c-safe-impl`** - **genuinely safe real code** (a vendored OpenZeppelin/Permit2
  implementation, or a faithful reference implementation of the canonical defense - never a
  lightly-edited toy). The harness **must** stay silent (`BLOCKED`). This tier is what makes
  a false-positive rate meaningful.

Every `b`/`c` fixture carries a `PROVENANCE.md` header linking it to a public origin
(incident write-up, tx hash, advisory, or upstream repo + commit + license), and the proof
level is stated honestly: some real incidents are reproduced at **mechanism / class level**
(the documented pattern, not a byte-for-byte tx replay) where full traces are not public.

Each fixture declares its expected label in a `meta` file; the benchmark joins every fixture
to the verdict its Foundry test emits and scores it:

```
label vuln + VULNERABLE = TP      label vuln + BLOCKED    = FN
label safe + BLOCKED    = TN      label safe + VULNERABLE = FP
```

## Provenance of the real tiers

All sources are **public**. Toy targets and reference implementations are authored in this
repository (MIT).

| Vector | (b) real public incident | (c) safe implementation |
|---|---|---|
| `approve-drainer` | BadgerDAO front-end approval-injection drain, 2021-12-02, ~$120M total (largest single-victim tx ~$50M) | OpenZeppelin ERC-20 (MIT, vendored) |
| `permit-phishing` | USDC ERC-2612 permit drain, 2026-03-16, ~$1.77M, tx `0xfd7417...f5a642` (darknavy.org + Etherscan) | OpenZeppelin ERC20Permit (MIT, vendored) |
| `set-approval-for-all` | Monkey Drainer NFT phishing-as-a-service, 2022-2023, SlowMist *estimated* ~$12.97M across 1,708 addresses (SlowMist; zerotracelabs; arXiv 2409.02386) | OpenZeppelin ERC-721 operator model (MIT, vendored) |
| `signature-phishing` | Seaport/Wyvern order-signature phishing - OpenSea migration (Feb 2022) + Kevin Rose / Moonbirds (Jan 2023) | OpenZeppelin EIP-712 + scoped-order verification (MIT, vendored) |
| `fake-airdrop` | LFG fake-airdrop "claim" guide, 2023, ~$125K stETH (The Block; Scam Sniffer) - *proof: medium* | OpenZeppelin ERC-20 as the real asset (MIT, vendored) |
| `address-poisoning` | December 2024 ~$50M USDT look-alike withdrawal (Spark; Elliptic; Etherscan) | full-address verification - reference-impl of the canonical defense (authored here) |
| `malicious-calldata` | multicall-hidden / mislabeled approval in drainer kits (arXiv 2409.02386) - *proof: class-level, incident-anchored (Inferno Drainer "Reloaded", Check Point 2025)* | net-effect simulation guard - reference-impl |
| `eip7702-delegation` | "CrimeEnjoyor" reusable EIP-7702 sweeper, live since Pectra 2025 (Wintermute; Scam Sniffer) - *proof: incident/class-level* | allow-listed-delegate policy - reference-impl |
| `permit2-phishing` | PEPE holder Permit2 signature phishing, 2024-10-13, ~$1.39M (Scam Sniffer; Decrypt) | vendored Uniswap Permit2 (MIT, verbatim @cc56ad0) under a scoped-signature policy |
| `create2-metamorphic` | CREATE2 drainer / metamorphic address reuse, 2023-2024, ~$60M across ~99K victims (Scam Sniffer; BleepingComputer; MixBytes) - *proof: incident-level for the fresh-address variant (concrete ~$927K Arbitrum drain tx in the Scam Sniffer report); metamorphic-reuse variant class-level, EIP-6780/Cancun caveat* | codehash-pinning vault - reference-impl |
| `delegatecall-hijack` | Bybit Safe multisig `delegatecall` swap, 2025-02-21, ~$1.46B (CertiK; SlowMist; NCC Group) - *proof: mechanism-level* | guarded executor (call-only / implementation-pinned) - reference-impl |
| `blind-eth-sign` | legacy `eth_sign` blind raw-hash signing (MetaMask MIP-3 removal 2024; Safe removal after Bybit) - *proof: class-level* | clear-signing (EIP-712 typed-only) - reference-impl |
| `upgrade-governance` | PAID Network single-key proxy upgrade, 2021-03-05, ~59.47M PAID minted (CertiK; Halborn; SlowMist) - *proof: incident-level* | OpenZeppelin UUPS + TimelockController v5.1.0 (MIT, vendored byte-for-byte) |

Where a vector has no single canonical third-party library (e.g. address-poisoning,
eip7702-delegation, create2-metamorphic, delegatecall-hijack, blind-eth-sign), tier (c) is a
faithful **reference implementation** of the accepted defense, marked as such in its
`PROVENANCE.md` - not vendored code, and not a lightly-edited toy.

## Benchmark (precision / recall)

The corpus is **155 labeled fixtures** across the 13 vectors (70 `vuln` + 85 `safe`): every
vector carries at least the `a`/`b`/`c` tiers, and most add extra independent-holdout cases.
The benchmark runs every fixture inside Docker, joins each to its expected label, and prints a
confusion matrix:

```sh
./harness/benchmark.sh
```

```
== confusion matrix ==
  TP=70  FP=0  FN=0  TN=85  (missing=0)
  precision=1.000  recall=1.000
== BENCHMARK: OK - precision=1.000, recall=1.000, 0 false positives, 0 false negatives ==
```

**What this number is.** Every fixture is driven by its own Foundry test, written together with
the fixture, that replays the attack and asserts the outcome. `benchmark.sh` is therefore a
**corpus self-consistency check**: it proves that each `vuln` case really drains, each `safe` case
really blocks the same attack, and no labeled fixture is left without an executed verdict. It is
not the accuracy of a detector that was blind to the cases.

**94 of the 155 fixtures are the `holdout` split** - new, independently web-verified public
incidents (41 `vuln`) and unmodified real safe code (53 `safe`), covering **all 13 vectors**,
added after the `v0.1` interface freeze, each with its own new test. The 32 toy fixtures are all
`dev`-split and never enter it. The holdout is independent ground truth for scoring **other**
tools (`bench/score.sh --split holdout`); wal's own `TP=41 FP=0 FN=0 TN=53` on it is the same
self-consistency check, not a generalization result. One vector
(`fake-airdrop`) is **precision-side, safe-only** in holdout: no clean, independent *vulnerable*
public incident exists for it at our provenance bar, so its independent case is real safe code
the detector must stay silent on (0 FP) - an honest precision check, not a recall claim. The
benchmark is a **growing**, hand-built corpus (currently 155) - a reproducible methodology
artifact, **not** a statistical claim of generalization
to wallets in the wild. Scope is **on-chain policy** (what the contract code permits), not
off-chain / UX attack surface. The corpus targets **modern smart-wallet code (Solidity 0.8+)**
- smart wallets, ERC-4337 accounts, EIP-7702 delegates and Permit2 are all 0.8-era, so older
compilers (0.4-0.7) are out of scope by design, not an omission. See
[`bench/README.md`](bench/README.md) for the full per-vector honesty split and how to score
your own tool.

Target bar: **recall 1.0** on `vuln` fixtures (every real bug caught) and **precision 1.0**
on `safe` fixtures (no safe code flagged). The run exits non-zero on any false positive, any
false negative, or any labeled fixture with no emitted verdict (a coverage gap).

A lighter smoke runner, `./harness/run.sh`, executes the toy tier and prints one
`VULNERABLE`/`BLOCKED` line per target, enforcing the same 0-FP / 0-FN bar.

## Requirements

- **Docker** - all contracts are built and run only inside a container (untrusted code is
  never built on the host).
- the `ghcr.io/foundry-rs/foundry` image.
- `forge-std` in `lib/` (not vendored; fetch the pinned version yourself - see below).

## Run

```sh
# one-time: fetch the pinned forge-std into lib/ (lib/ is git-ignored)
git clone --depth 1 --branch v1.9.4 https://github.com/foundry-rs/forge-std lib/forge-std

# toy smoke (one verdict line per target)
./harness/run.sh

# full labeled benchmark (confusion matrix + precision/recall)
./harness/benchmark.sh
```

## CTF - patch the drain

A hands-on layer on top of the same vectors: each challenge hands you a deliberately
vulnerable wallet contract and asks you to **fix it**. A hidden exploit test grades the fix
on two sides at once - the drain must be blocked **and** the legitimate feature must still
work - so you can't pass by deleting the feature. Same bar as the benchmark, as a puzzle.

**One challenge per vector (13 mechanisms)** plus **incident-anchored challenges built from
real drains** (Badger, Parity, Nomad, Socket, Visor, Gondi, QNT/7702, Lixir, Anyswap, LINK,
Magic Eden, NFTTrader, ...) - **27 in all** (`intro` / `core` / `advanced`). Each is checked by a
ground-truth `selftest`: the hidden gate must **fail on the vulnerable seed** and **pass on the
reference solution**, so every puzzle is provably both broken and solvable. The incident ones
carry verbatim provenance (on-chain tx / date / loss) in their `meta`.

```sh
./ctf/ctf.sh doctor                  # check prerequisites (Docker, forge-std)
./ctf/ctf.sh list                    # list challenges ( - unsolved / ✓ solved, with a solved N/27 count )
./ctf/ctf.sh start approve-drainer   # seed an editable copy + print the brief
./ctf/ctf.sh solve approve-drainer   # run the hidden gate (Docker); prints security / functionality
./ctf/ctf.sh selftest                # ground-truth check: seed->FAIL, solution->PASS on all
```

See [ctf/README.md](ctf/README.md) for details.

## Layout

```
corpus/    vector specs (contract-of-record per vector) + real-cases.md (public provenance)
src/       toy targets: minimal ERC-20/721, malicious spenders, vulnerable/safe wallets
test/      the vector proofs (Foundry tests); each emits [<vector>] target=... verdict=...
fixtures/  the labeled benchmark corpus:
             <vector>/{a-toy,b-incident,c-safe-impl}/<target>/meta   (+ PROVENANCE.md for b/c)
             vendor/   vendored third-party safe code (OpenZeppelin / Permit2, pinned, MIT)
harness/   run.sh (toy smoke) and benchmark.sh (precision/recall over fixtures/)
ctf/       "patch the drain" challenges (ctf.sh) built from the same vectors
```

## Safety / scope

Only **public** incidents are reproduced, and only **offline**: pinned bytecode or a
minimized committed clone, never a check against a live contract, always inside Docker. The
toy contracts are deliberately vulnerable test fixtures - never deploy them to a real
network.

## License

MIT. See [LICENSE](LICENSE).
