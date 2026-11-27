# External cross-validation - SWC Registry examples

**This directory is NOT part of the drain-bench real-incident corpus.** It is a separate,
external cross-validation set: canonical example contracts taken from an *independent* taxonomy
(the [SWC Registry](https://github.com/SmartContractSecurity/SWC-registry), MIT) and run through
the **drain-scan** scanner to check whether our rules agree with an outside ground truth.

It is kept out of `bench/dataset/manifest.tsv`, the `fixtures/**` corpus and the Foundry harness
on purpose:

- the SWC samples are **synthetic** examples (not real incidents), so mixing them into the
  real-incident corpus would dilute it;
- they are **ported from `^0.4.24` to `^0.8.x`** to compile under our pinned solc, so they are no
  longer byte-identical to upstream;
- they are scored by the **static scanner** (drain-scan rules R*), not by the wal Foundry harness,
  so they carry no `meta`/verdict and do not change any benchmark number.

Provenance of every file is in its own header (source repo + SWC-ID + commit + MIT + the exact
0.8.x port diff). Upstream commit: `1b6227074ecd180b374e4844153afdda0332f979` (retrieved 2026-11-14).
Note: the SWC Registry is **no longer actively maintained since 2020** (stated at the top of each
entry) - fine for a fixed cross-validation reference, not as a live source of truth.

## Scope of what could actually be imported (honest)

Only **SWC-112** carries example contracts in the registry (`entries/docs/SWC-112.md`, `## Samples`).
**SWC-121 and SWC-122 contain no sample contracts** - only a description and a CWE link. The whole
registry ships **zero `.sol` files**; code lives only inline in the few entries that have a
`## Samples` section. So:

| SWC | our rule | sample in registry? | cross-validation |
|-----|----------|---------------------|------------------|
| SWC-112 Delegatecall to Untrusted Callee | R7 (delegatecall-hijack) | **yes** (proxy.sol + 2 variants) | done - below |
| SWC-121 Missing Protection against Signature Replay | R5 (signature-phishing) | **no** | not possible without fabricating a contract (would violate provenance) |
| SWC-122 Lack of Proper Signature Verification | R6 (blind-eth-sign) | **no** | not possible without fabricating a contract |

R5/R6 cross-validation against the SWC Registry is therefore **not available** - the registry
simply has no example code for those two IDs. (The *conceptual* mapping R5->SWC-121, R6->SWC-122 is
verified against the registry's own CWE relationships and lives in drain-scan `RULES.md`.)

**Re-verified 2026-11-14** (task to add SWC-121->R5 and SWC-122->R6): `entries/docs/SWC-121.md` and
`entries/docs/SWC-122.md` were re-fetched from the current registry and still contain **no
`## Samples` section and no Solidity** - only Title / Relationships / Description / Remediation /
References. There is no example contract to cross-validate against, so none is added here.
Fabricating a "representative" contract would defeat the purpose of an *independent* ground truth,
so we do not. For an external signature-replay / signature-verification corpus we would need a
different labelled source (none with a drop-in MIT example was found).

One adjacent signature ID, **SWC-117 (Signature Malleability)**, *does* ship sample contracts
(`transaction_malleablity.sol` + a fixed variant). It is deliberately **not** used here: signature
malleability (a second valid `s`-value surviving `ecrecover`) is a different defect from the
phishing / replay (R5) and blind-`eth_sign` (R6) vectors drain-scan models - drain-scan has no
malleability rule - so it is out of R5/R6 scope. We note it explicitly rather than silently skip a
signature ID that happens to carry samples.

## SWC-112 -> R7 cross-validation result

Command (per file): `drain-scan/scan <file> --format json` (solc 0.8.24, our core engine).
Scanner version: drain-scan `main` `bc0abf5` - includes the R7/R8 revert-guard narrowing (the R7
owner's response to this cross-validation; re-run on `main` confirms the table below).

| file (registry label) | expected (registry) | R7 fired? | agreement |
|-----------------------|---------------------|-----------|-----------|
| `SWC-112-proxy-vulnerable.sol` (vulnerable) | vuln | **yes** (R7 + R8) | ✅ **match** - we flag the delegatecall-to-caller-supplied-target positive |
| `SWC-112-proxy-false-positive.sol` (known FP) | safe | **no** | ✅ **match** - R7/R8 narrowed to model the mandatory-revert guard (in `main` `bc0abf5`) |
| `SWC-112-proxy-fixed.sol` (fixed/safe) | safe | **yes** (R7 + R8) | ⚠️ **mismatch - documented (intentional)** |

(R7 and R8 share one static primitive - a delegatecall to an attacker-settable target - so both
fire together on the positive; see `RULES.md`. The agreement we care about for SWC-112 is R7.)

Net: **2 of 3 match** the registry's labelling; the one mismatch is an intentional, documented
threshold divergence (below), not a defect.

### Findings from this cross-validation (routed to the R7 owner - not suppressed)

1. **`proxy_fixed`** -> **mismatch, kept by design (R7 owner's call).** The registry calls this
   "fixed" because the delegatecall target (`callee`) is settable **only by the owner**
   (`onlyOwner setCallee`). drain-scan R7 still flags it: R7 suppresses a mutable delegatecall
   target only when it is guarded by an **allow-list / net-effect simulation / governed proxy
   (timelock+guardian)** - a bare single-key owner-settable pointer is, by R7's design, still a
   drain surface (a compromised or malicious single key can point it at a drainer; this overlaps
   R10's single-key-swap concern). This is a **threshold difference**, not a bug: SWC-112 (2020)
   treats owner-control as sufficient; drain-scan's bar is stricter (allow-list / governance, not
   single-key). The R7 owner confirmed this is **intentional** and R7 is not changed; R7 stays
   silent on real governed proxies (OZ UUPS, verified 0-FP on the real-safe corpus).
2. **`proxy_false_positive`** -> **resolved.** The registry's explicitly-labelled "a naive
   delegatecall detector would wrongly report this" pattern - the delegatecall is **required to
   revert** (`require(!_to.delegatecall(_data))`), so it cannot mutate storage. The first run of
   this cross-validation flagged it; the R7 owner then **narrowed R7/R8 to model the
   mandatory-revert guard** (scan-d `a08a669`), after which R7/R8 stay silent here - now agreeing
   with the registry - with the rule's dev/holdout anchors and the full 0-FP probe still green (no
   false negative introduced). This is exactly the value of external cross-validation: it surfaced
   a real precision edge that was then fixed.

**Bottom line:** R7 **agrees with SWC-112 on the vulnerable positive** (the cross-validation's main
claim: our rule matches an independent taxonomy's labelling of the drain-positive), and after the
revert-guard narrowing it also agrees on the registry's known-FP sample. The single remaining
mismatch (`proxy_fixed`) is an intentional, documented threshold divergence. These are scanner
(drain-scan) results - they do **not** affect the wal benchmark numbers.
