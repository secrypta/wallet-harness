# Vector: delegatecall-hijack (implementation / storage takeover)

**Class:** account-logic takeover - **Chain:** EVM - **Severity:** critical (whole-account loss)
**Prior art:** NDSS'25 partial II-B (proxy upgrade); SWC-112 (Delegatecall to Untrusted Callee); DASP-10 nearest: Access Control.

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** the `operation=delegatecall` payload is often an instance of [[malicious-calldata]]; the resulting implementation/storage takeover is the same end as [[upgrade-governance]] reached without governance.

## What it is
A smart-contract wallet (e.g. a Safe/Gnosis-style multisig or a proxy account) executes
owner-approved transactions. If such a transaction is a **`delegatecall`** to an
attacker-controlled contract, that contract runs **in the wallet's own storage context** -
it can overwrite the implementation/`masterCopy` pointer or any storage slot and seize the
account. The victim signs what looks like a routine transfer; the `operation` flag (0 =
`call`, 1 = `delegatecall`) is the hidden teeth.

This differs from [[malicious-calldata]] (a hidden *approve* behind a benign label): here the
effect is **taking over the account's logic/storage**, after which the attacker controls all
future execution, not just one allowance.

## Attack mechanics
1. Victim/signers are shown a benign action (a transfer) in the wallet UI.
2. The actual payload sets `operation = 1` (delegatecall) targeting an attacker contract.
3. On execution the attacker contract, running as the wallet, rewrites the implementation
   slot (or approves itself / moves assets). The account is now attacker-controlled.

## Defensive signal (what a harness / wallet policy should catch)
- **Delegatecall-to-untrusted flag:** any `operation = delegatecall` to a target that is not
  an allow-listed, audited library.
- **Implementation-slot invariant:** the proxy/implementation pointer (and other critical
  slots) must be unchanged after a normal user transaction; a post-exec check reverts if it
  moved.
- A protected target: a transaction guard rejects delegatecall to non-allow-listed targets,
  so the hijack path is unreachable.

## Targets (for the benchmark)
- `a-toy`: `vulnerable-exec` (wallet executes a delegatecall that swaps its implementation ->
  attacker takeover) vs `safe-exec` (guard blocks delegatecall to unknown target).
- `b-incident`: `bybit-exec-victim` - Feb 21 2025, ~$1.46B. A Safe `execTransaction` with
  `operation` flipped to `delegatecall` ran attacker code that replaced the wallet logic;
  largest crypto theft on record. See [[real-cases]] §(b) delegatecall-hijack. Honest proof
  level: mechanism-level repro (full calldata/traces were not all public; reproduce the
  documented delegatecall-swap, not a byte-replay).
- `c-safe-impl`: `guarded-exec-safe` - reference-impl of a Safe-style transaction guard /
  implementation-slot invariant that blocks delegatecall to non-allow-listed targets.

> **Independent holdouts (`split=holdout`):**
> - `parity-wallet-library-victim` - the Parity multisig delegatecall-hijack via an unguarded
>   shared-library `initWallet` (2017-07-19).
> - `furucombo-proxy-victim` - the Furucombo "evil contract" drain (2021-02-27, ~$15M): the
>   proxy delegatecalled a whitelisted handler (the Aave V2 proxy) whose uninitialized
>   implementation the attacker repointed, so attacker code ran in the proxy's context and
>   spent users' standing approvals ("cascading trust").
>
> Independent real-incident `b` cases scored on the holdout split. See [[real-cases]] and
> `bench/README.md`.

> **Real-safe holdout (`split=holdout`, tier c):** `solady-erc7821-safe` - a wallet over the
> unmodified Solady `ERC7821` canonical batch executor, which runs each operation with a plain
> `call` (no `operation=delegatecall` flag), so the hijack surface is structurally absent. The
> harness must stay silent (BLOCKED). Real MIT code (Solady v0.1.22); see its `PROVENANCE.md`.

> **Real-safe holdout (`split=holdout`, tier c, round 4):** `oz-erc1967-proxy-safe` - a UUPS
> wallet behind the unmodified OpenZeppelin `ERC1967Proxy`. A proxy legitimately USES
> `delegatecall`, but only to its MANAGED implementation slot: an attacker can neither redirect
> that sink (upgrade is owner-gated) nor request a delegatecall operation (owner ops run via a
> plain `call`). A precision check that a canonical proxy's delegatecall-to-implementation is
> not flagged. The harness must stay silent (BLOCKED). Real MIT code (OZ v5.1.0); see its
> `PROVENANCE.md`.

> **Real-safe holdouts (`split=holdout`, tier c, round 5):** `solady-uups-proxy-safe` and
> `oz-transparent-proxy-safe` - two more canonical proxy mechanisms, each delegatecalling only
> its managed implementation slot. The first is Solady's INDEPENDENT (non-OZ) UUPS mixin behind
> an ERC-1967 proxy; the second is OpenZeppelin's TRANSPARENT-proxy admin pattern (external
> `ProxyAdmin`, admin/user call-routing). Neither exposes a caller-chosen delegatecall target;
> the sink is redirectable only by the proper upgrade authority. Precision checks across
> distinct proxy codebases/patterns. The harness must stay silent (BLOCKED). Real MIT code
> (Solady v0.1.22 / OZ v5.1.0); see their `PROVENANCE.md`.

## Source base
Toy targets + guard reference-impl authored in this repo (MIT). Tier (c) is a reference-impl
of the canonical post-Bybit mitigation pattern (transaction guard / slot invariant), not a
vendored library - marked honestly in PROVENANCE. Related: [[malicious-calldata]],
[[eip7702-delegation]].
