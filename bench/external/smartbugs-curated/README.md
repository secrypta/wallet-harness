# External cross-validation - SmartBugs-Curated (`access_control`)

**This directory is NOT part of the drain-bench real-incident corpus** (`split=external`). It is a
separate cross-validation set: an *independent* labelled corpus
([SmartBugs-Curated](https://github.com/smartbugs/smartbugs-curated), `access_control` category,
with line-level ground-truth annotations) run through the **drain-scan** scanner to check whether
our rules agree with an outside ground truth - and to show honestly where our scope ends.

Like `../swc-xval`, it is kept out of `bench/dataset/manifest.tsv`, the `fixtures/**` corpus and
the Foundry harness: these are scored by the **static scanner** (drain-scan rules R*), carry no
`meta`/verdict, and change no benchmark number.

- Upstream: `smartbugs/smartbugs-curated` @ `230e649123477eff332742a59a1c7cc6dc286cab`
  (retrieved 2026-11-14). Repo code Apache-2.0; **each contract keeps its original upstream
  license** - see `NOTICE`, `ground-truth.tsv`, and the per-file headers. A per-file license
  review was done before copying any `.sol`; GPL-3.0 (`parity_wallet_bug_1`) is **referenced only,
  not vendored**.
- Imported examples are **ported `^0.4.x` -> `^0.8.17`** to compile under our pinned solc, so they
  are no longer byte-identical to upstream. Value = **taxonomy-agreement**, not real-incident
  reproduction. Each port diff is in the file header. Two upstream files
  (`arbitrary_location_write_simple`, `mapping_write`) rely on writable array `.length` (removed
  in ≥0.5) and **cannot be ported without destroying the bug** - referenced, not run.

## Honest framing: a narrow tool on a general corpus

drain-scan is a **narrow wallet-drain linter** (approval / signature / delegatecall / upgrade /
init-hijack drains, rules R1-R12). SmartBugs `access_control` is a **general** category. We are
**not a leader** on it and do not claim to be: several entries (`tx.origin` auth, unprotected
`selfdestruct`, refund/comparison logic bugs) are deliberately **out of scope** and the scanner
stays silent on them - a precision / scope property, not a false negative. The value is
cross-validation on the *overlapping* sub-families and an honest coverage statement.

## Scope mapping (18 `access_control` entries -> drain-scan)

| bucket | upstream entries | our rule | scanner |
|--------|------------------|----------|---------|
| **delegatecall** | `FibonacciBalance`, `proxy` | R7 / R8 | **flags** - agrees with GT |
| **init-hijack / unguarded authority-setter** | `incorrect_constructor_name{1,2,3}`, `multiowned_vulnerable`, `unprotected0`, `rubixi`, `wallet_03_wrong_constructor`, (`parity_wallet_bug_2`†) | **R12** | **flags** - agrees with GT |
| **out of scope (silent by design)** | `phishable`, `mycontract` (tx.origin); `simple_suicide` (selfdestruct); `wallet_02_refund_nosub`, `wallet_04_confused_sign` (logic) | none | silent - scope boundary |
| **not portable to 0.8** | `arbitrary_location_write_simple`, `mapping_write` (array `.length` write) | - | referenced, not run |

† `parity_wallet_bug_2` is the R12 class (WalletLibrary unguarded `initWallet`) but is referenced,
not ported (~200 LOC of 0.4.9). See `NOTICE`.

## Cross-validation result (files actually run)

Command (per file): `drain-scan/scan <file> --format json` - solc **0.8.17**, drain-scan core
engine (no Slither). Scanner version: **scan-d `d54e0bb`** (includes R12 init-hijack). Run
read-only 2026-11-14.

### In-scope - agreement with upstream GT

| file | GT lines (0.4 src) | our rule | fired? | agreement |
|------|--------------------|----------|--------|-----------|
| `FibonacciBalance_0.8.sol` | 31,38 | R7/R8 | R7+R8 @ both delegatecall sites | ✅ match (line-level) |
| `../swc-xval/SWC-112-proxy-vulnerable.sol` | 19 | R7/R8 | R7+R8 | ✅ match (see `../swc-xval`) |
| `incorrect_constructor_name1_0.8.sol` | 20 | R12 | R12 @ `IamMissing` | ✅ match |
| `incorrect_constructor_name2_0.8.sol` | 18 | R12 | R12 @ `missing` | ✅ match |
| `incorrect_constructor_name3_0.8.sol` | 17 | R12 | R12 @ `Constructor` | ✅ match |
| `multiowned_vulnerable_0.8.sol` | 38 | R12 | R12 @ `newOwner` | ✅ match |
| `unprotected0_0.8.sol` | 25 | R12 | R12 @ `changeOwner` | ✅ match |
| `rubixi_0.8.sol` | 23,24 | R12 | R12 @ `DynamicPyramid` | ✅ match |
| `wallet_03_wrong_constructor_0.8.sol` | 19,20 | R12 | R12 @ `initWallet` | ✅ match |

**In-scope agreement: 9 / 9 match** (2 delegatecall + 7 init-hijack), each landing on the
upstream-annotated function (line numbers shift by the provenance header; function-level exact).

### Out-of-scope - silence by design (precision)

| file | GT (upstream vuln) | fired? | note |
|------|--------------------|--------|------|
| `phishable_0.8.sol` | tx.origin auth | **no** | tx.origin is not a drain-scan vector |
| `simple_suicide_0.8.sol` | unprotected selfdestruct | **no** | R12 models authority-role install, not bare selfdestruct |
| `wallet_02_refund_nosub_0.8.sol` | refund not zeroed | **no** | state-update logic bug, not our family |
| `wallet_04_confused_sign_0.8.sol` | wrong comparison | **no** | comparison logic bug, not our family |

**0 false positives** on the four out-of-scope examples run.

### Honest coverage statement

- In-scope (delegatecall + init-hijack): **9 / 9 flagged, 0 false negatives.**
- Out-of-scope: **4 / 4 correctly silent, 0 false positives.**
- Referenced, not run: 5 (`parity_wallet_bug_1` GPL; `parity_wallet_bug_2` impractical port;
  `mycontract` license/scope; `arbitrary_location_write_simple`, `mapping_write` 0.4-only).
- **Not claimed:** `simple_suicide` / `wallet_02` are drains by *other* mechanisms (bare
  selfdestruct, un-zeroed refund) that our rule set does **not** model today; we report them as
  out-of-scope rather than silently omitting them, so the reader can judge coverage fairly. These
  are candidate future rules, not current matches.

## Full-taxonomy scope audit (why only `access_control`)

To check generalization honestly we surveyed **all 10** SmartBugs-Curated categories at commit
`230e649` (2026-11-14), not just the one we import from. Finding:

- **Only `access_control`** contains cases inside drain-scan's R1-R12 remit (delegatecall ->
  R7/R8; unguarded-authority / init-hijack -> R12). Those are the files imported above.
- The other **9 categories are out of scope and intentionally NOT imported**: `arithmetic`
  (overflow, SWC-101), `reentrancy`, `bad_randomness`, `denial_of_service`, `front_running`
  (approve-race / TOD, SWC-114), `time_manipulation`, `short_addresses`,
  `unchecked_low_level_calls`, `other`. A grep across the whole dataset confirms **no
  `delegatecall`, unprotected `initialize`, `upgradeTo`, or `setApprovalForAll` pattern exists
  outside `access_control`**. The few files elsewhere that mention `approve()` / `transferFrom`
  carry a non-drain ground-truth label and are correctly out of scope - e.g.
  `front_running/ERC20.sol` is labelled `FRONT_RUNNING` (the ERC-20 allowance race), and
  `arithmetic/BECToken.sol` is labelled `ARITHMETIC` (the `batchTransfer` overflow). Importing
  them to pad the external set would be dishonest; drain-scan is silent on them by design.
- **SWC Registry** (see `../swc-xval`): SWC-112 -> R7 is cross-validated; the signature IDs our
  R5/R6 map to (SWC-121 / SWC-122) ship **no sample contract**; no other SWC sample maps to
  R1-R12.

**Conclusion:** beyond `access_control` + SWC-112, there is **no clean, independent, in-scope
case available** in these public corpora. We do not fabricate or stretch scope to inflate the
external set; the honest external coverage is what is listed above.

These are scanner (drain-scan) results - they do **not** affect the wal benchmark numbers. D runs
the authoritative scanner-side pass over the full set from the drain-scan repo.
