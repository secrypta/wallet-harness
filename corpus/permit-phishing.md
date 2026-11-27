# Vector: permit-phishing (EIP-2612 / off-chain approval signature)

**Class:** token-allowance abuse via signature - **Chain:** EVM - **Severity:** critical
**Prior art:** NDSS'25 cat I-B (ice phishing: Permit); DASP-10 nearest: Access Control.

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** same `transferFrom` sink as [[approve-drainer]], reached by signature instead of tx; the Permit2 variant is [[permit2-phishing]]; often delivered via [[fake-airdrop]].

## What it is
EIP-2612 `permit` lets a token owner grant an allowance with an **off-chain signature**
instead of an on-chain `approve` transaction. The owner signs an EIP-712 typed message
`(owner, spender, value, nonce, deadline)`; anyone holding that signature can submit it to
`token.permit(...)`, which sets `allowance[owner][spender] = value`.

This is more dangerous than [[approve-drainer]] for the victim: there is **no transaction
in the wallet to inspect**, no gas spent by the victim, and phishing UIs present it as a
harmless "sign to continue / connect". The signature is the authorization.

## Attack mechanics
1. Victim is lured into signing a permit typed-message, typically with
   `value = type(uint256).max` and `spender =` attacker-controlled contract.
2. Attacker submits `token.permit(owner, spender, max, deadline, v, r, s)` - allowance is
   now live without the victim ever sending a transaction.
3. Attacker drains via `transferFrom` exactly as in [[approve-drainer]].

Same loss bound as approve-drainer: loss ≤ signed `value`. An unlimited-value permit =
everything; a bounded-value permit caps the loss.

## Defensive signal (what a harness / wallet policy should catch)
- **Decode-and-flag:** the signed payload MUST be decoded and shown as what it is - an
  allowance grant to `spender` of `value`. A blind `eth_signTypedData` of a permit to an
  unknown spender, or with `value == type(uint256).max`, is the flag.
- **Bounded value:** only sign permits whose `value` equals the action's need; residual
  signed allowance should be ~0.
- A protected target signs/accepts only a **bounded-value** permit (or refuses the
  unlimited one), so a later full-balance drain reverts.

## Repro (toy targets - proven by test body)
Reuse `MockERC20` extended with EIP-2612 `permit` (domain separator, nonce, `ecrecover`
with `recovered != 0 && == owner`, deadline check), plus `MaliciousSpender`.
- **Vulnerable target:** owner signs an **unlimited** permit to the spender -> attacker
  `permit()` + `drain()` takes 100% -> `permit-phishing: VULNERABLE`.
- **Protected target:** owner signs a permit for exactly the action amount -> attacker's
  full-balance `drain()` reverts, balance intact -> `permit-phishing: BLOCKED`, 0 false
  positives.

Also assert the signature guards hold (expired deadline reverts; wrong signer / zeroed
signature -> `ecrecover` mismatch reverts) so the vector isn't "blocked" for the wrong
reason. Validation bar: fires on vulnerable, silent on protected.

> **Independent holdouts (`split=holdout`):** `anyswap-permit-bypass-victim`
> (Anyswap/Multichain AnyswapV4Router permit-bypass, 2022-01) and `lixir-permit-victim`
> (Lixir vault-token broken-permit drain - a dummy signature is accepted) and
> `spark-weth-permit-victim` (Spark WETH / spWETH ~$32M drain, 2024-09-28: one phishing
> EIP-2612 permit -> unbounded allowance -> the drainer sweeps the whole balance with two
> `transferFrom` calls splitting the proceeds; verified on-chain as an EIP-2612 token permit,
> not Uniswap Permit2) and `fwdeth-permit-victim` (fwDETH ~$35M drain on **Blast**, 2024-10-11:
> one offline EIP-2612 permit -> the Angel-Drainer attacker sweeps 15,079 fwDETH in two stages;
> **mechanism-level** - no public drain-tx hash and the official Blast explorer is deprecated, so
> modeled like the beanstalk/furucombo/li-fi/socket tier-b cases) - independent real-incident `b`
> cases scored on the holdout split. See [[real-cases]] and `bench/README.md`.

> **Real-safe targets (precision side):** beyond `oz-permit-safe` (bounded-allowance) and the
> `solady-permit-safe` holdout (forged-signature rejected), three more genuinely-safe real-code
> cases cover distinct defensive properties of real EIP-2612 permit: `oz-permit-deadline-safe`
> (OZ rejects an expired-deadline phishing permit, `ERC2612ExpiredSignature`),
> `oz-permit-nonce-replay-safe` (OZ consumes the nonce, so a captured permit cannot be
> replayed to re-grant allowance) and `solady-permit-deadline-safe` (`split=holdout`: the same
> expired-deadline defense proven on the independent Solady codebase, `PermitExpired`). All are
> unmodified upstream code (OZ v5.1.0 / Solady v0.1.22, MIT). Two further independent Solady
> holdouts complete the property matrix on that codebase: `solady-permit-nonce-replay-safe` (a
> captured permit cannot be replayed - nonce consumed -> `InvalidPermit`) and
> `solady-permit-bounded-safe` (a bounded-value Solady permit cannot over-draw).

## Source base
Toy targets authored in this repository (MIT): a minimal EIP-2612 `permit` token
(`DOMAIN_SEPARATOR` + `PERMIT_TYPEHASH`, strict deadline/signer/nonce checks) and the
vulnerable/safe permit flows. Related: [[approve-drainer]], [[fake-airdrop]].
