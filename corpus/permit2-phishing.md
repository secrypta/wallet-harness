# Vector: permit2-phishing (Uniswap Permit2 signature)

**Class:** off-chain allowance-signature abuse - **Chain:** EVM - **Severity:** critical (full balance loss)
**Prior art:** NDSS'25 cat I-B (ice phishing: Permit - Permit2 variant); DASP-10 nearest: Access Control.

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** the shared-Permit2 variant of [[permit-phishing]] (same off-chain-allowance class, distinct typed struct + contract). Shares the signature surface with [[signature-phishing]].

## What it is
Uniswap's **Permit2** (`0x000000000022D473030F116dDEE9F6B43aC78BA3`) is a single canonical
contract that holds token allowances on behalf of many dApps. A user first makes a one-time
ERC-20 `approve(Permit2, max)`, after which **off-chain signatures** (not on-chain txs) grant
per-dApp spending rights via `AllowanceTransfer` (`PermitSingle`/`PermitBatch`) or
`SignatureTransfer` (`PermitTransferFrom`). A victim who signs a malicious Permit2 payload
hands an attacker a signed authorization to pull tokens - no gas, no second prompt.

This is **distinct from EIP-2612 `permit`** ([[permit-phishing]]): the signature targets the
shared Permit2 contract (one approve covers all tokens routed through it), the typed struct
is Permit2's own (`spender`, `amount`, `expiration`, `nonce`, `sigDeadline`), and the drain
runs through `Permit2.permit()/transferFrom()` rather than the token's own `permit`.

## Attack mechanics
1. Victim has (or is induced to make) the standard `approve(Permit2, max)` on a token.
2. A phishing page asks the victim to **sign** a `PermitSingle`/`PermitTransferFrom` with
   `spender = attacker`, `amount = max` (or the full balance), far-future `expiration`.
3. Attacker submits the signature: `Permit2.permit(victim, permitSingle, sig)` then
   `Permit2.transferFrom(victim, attacker, amount, token)` - full balance leaves in one tx.

## Defensive signal (what a harness / wallet policy should catch)
- **Unbounded Permit2 signature flag:** a Permit2 `amount` of `max` (or ≫ action need) or an
  implausibly long `expiration`/`sigDeadline` to a non-allow-listed `spender`.
- **Scoped signature:** sign only the exact amount the action needs with a short expiration;
  residual Permit2 allowance after the action ≈ 0.
- A protected target: the signed Permit2 authority is bounded so a full-balance
  `transferFrom` reverts.

## Targets (for the benchmark)
- `a-toy`: `vulnerable-permit2` (victim signs max PermitSingle -> drain) vs `safe-permit2`
  (scoped amount+expiration -> full drain reverts).
- `b-incident`: `pepe-permit2-victim` - Oct 13 2024, a PEPE holder lost ~$1.39M (PEPE/MSTR/APU)
  to a single Permit2 phishing signature. See [[real-cases]] §(b) permit2-phishing.
- `c-safe-impl`: `scoped-permit2-safe` - the **real Uniswap Permit2** contract (vendored,
  MIT, pinned commit) under a scoped-signature policy; genuinely-safe real code the harness
  must stay silent on. Additional real-Permit2 safe holdouts exercise its revocation surface:
  `permit2-lockdown-safe` (owner `lockdown` zeroes an already-granted unbounded allowance),
  `permit2-invalidate-nonce-safe` (owner `invalidateNonces` pre-empts a phished signature) and
  `permit2-expiration-safe` (a bounded, short-expiry allowance auto-revokes once the
  `expiration` passes, so a later `transferFrom` reverts `AllowanceExpired`),
  `permit2-sigdeadline-safe` (a phished permit submitted past its `sigDeadline` is rejected
  `SignatureExpired` before any allowance is set) and `permit2-batch-scoped-safe` (a `PermitBatch`
  granting bounded per-token amounts over two tokens cannot be over-drawn).

> **Independent *vulnerable* holdout (`split=holdout`):** `link-permit2-victim` - a LINK
> Permit2 phishing drain (verified on-chain drain tx `0xa25807c8...339b04d0`, 12,041.30 LINK
> swept from the victim via a standing `approve(Permit2, max)` and one phishing `PermitSingle`
> signature). An independent real-incident `b` case scored on the holdout split. The
> precision-side independent case is real safe code the detector must stay silent on:
> `permit2-sigtransfer-safe` (vendored Uniswap Permit2 `permitTransferFrom`, 0 FP). See
> [[real-cases]] and `bench/README.md`.

## Source base
Toy targets authored in this repo (MIT). Tier (c) vendors the real Uniswap `permit2`
(Uniswap Labs, MIT) byte-for-byte with provenance. Related: [[permit-phishing]],
[[approve-drainer]], [[signature-phishing]].
