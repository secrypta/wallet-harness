# Vector: blind-eth-sign (raw-hash signing)

**Class:** blind off-chain signature - **Chain:** EVM - **Severity:** critical (full balance loss)
**Prior art:** not cleanly in NDSS'25 taxonomy (blind `eth_sign` over an opaque payload; ice-phishing adjacent); DASP-10: Unknown Unknowns.

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** same off-chain-signature class as [[signature-phishing]]; blind-eth-sign is the raw/opaque-hash sub-case, [[signature-phishing]] the typed-data/order sub-case. Not independent classes.

## What it is
`eth_sign` asks the wallet to sign an **opaque 32-byte hash** with no `"\x19Ethereum Signed
Message"` prefix and no structure the user can read. That hash can stand for **anything** -
a transaction, a Permit, an exchange order. A victim tricked into signing a bare hash produces
a signature an attacker can replay wherever that hash is valid, draining the account without
any on-chain approval.

This differs from [[signature-phishing]] (which here anchors on **EIP-712 typed** order
signatures, e.g. Seaport): the distinguishing defect of this vector is signing an
**unstructured, undisplayable** hash. The defense is categorical (never blind-sign raw
hashes; require structured/clear signing), not per-field scoping.

## Attack mechanics
1. Phishing page triggers `eth_sign(victim, h)` where `h` is a bare 32-byte hash.
2. `h` is actually `keccak256`/EIP-712 digest of a payload the attacker controls (a transfer
   authorization, a Permit, an order).
3. Attacker submits `h` + the victim's signature to the contract that accepts it ->
   authorization executes, assets leave. Signing cost the victim no gas and showed no detail.

## Defensive signal (what a harness / wallet policy should catch)
- **Raw-hash signing flag:** any request to sign an opaque 32-byte digest via the legacy
  `eth_sign` path (as opposed to `personal_sign` with the prefix, or EIP-712 typed data with
  a decodable domain+struct).
- **Clear-signing requirement:** only sign payloads the wallet can decode and display
  (EIP-712 / ERC-7730 clear signing); the blind-hash entrypoint is disabled.
- A protected target: there is no path to produce a valid authorization from a blind raw-hash
  signature; only structured, scoped signatures are accepted.

## Targets (for the benchmark)
- `a-toy`: `vulnerable-ethsign` (contract accepts a bare-hash signature -> drain) vs
  `safe-ethsign` (requires EIP-712 typed, decodable order; blind-hash path unreachable).
- `b-incident`: `ethsign-blind-victim` - the deprecated-but-still-abused `eth_sign` phishing
  class. MetaMask MIP-3 accepted 2024-05-15 and removed `eth_sign` (Aug 2024) **because** of
  real blind-signing drains; Safe removed `eth_sign` days after the Bybit hack. See
  [[real-cases]] §(b) blind-eth-sign. Honest proof level: class-level (reproduce the
  documented mechanism; cite the deprecation + drainer analyses).
- `b-incident`: `bybit-blind-sign-victim` - the Bybit / Safe multisig theft (2025-02-21,
  ~$1.5B), an **incident-level** anchor. Owners blind-signed an opaque Safe `execTransaction`
  digest their hardware wallets could not decode; the authorization drained the cold wallet.
  On-chain-confirmed: tx `0x46deef...7882` to the Safe `0x1db9...dfcf4` (selector `0x6a761202`),
  malicious impl `0xbDd077...9516`. Models the blind-signed-authorization->drain essence (not the
  delegatecall/upgrade mechanics, which other rules cover). Sources: SlowMist + CertiK +
  BlockSec + on-chain. See its `PROVENANCE.md`.
- `c-safe-impl`: `typed-only-safe` - reference-impl that accepts only decodable EIP-712 typed
  signatures and rejects raw-hash signing (clear-signing direction).

> **No independent *vulnerable* holdout** for this vector - precision-side only. The
> independent (`split=holdout`) case is real safe code the detector must stay silent on:
> `permit2-sigverify-safe` (vendored Uniswap Permit2 `SignatureVerification`, 0 FP) and
> `oz-clearsign-safe` (real OpenZeppelin v5.1.0 `EIP712`+`ECDSA` clear-signing wallet with no
> raw-hash entrypoint - a signature obtained by blind-signing an opaque hash authorizes nothing,
> 0 FP). A third safe holdout, `solady-typed-sig-safe` (real Solady `EIP712` +
> `SignatureCheckerLib`, typed-only gate with no raw-hash/eth_sign entrypoint), carries the same
> clear-signing defense on the independent Solady codebase: a blind eth_sign signature recovers to
> a different signer and is rejected, 0 FP. A fourth, `oz-votes-delegatebysig-safe`, covers the
> governance delegation-by-signature surface (real OZ `ERC20Votes`/`Votes.delegateBySig`): a blind
> eth_sign cannot redirect the victim's voting power because it does not cover the typed Delegation
> digest, 0 FP. See `bench/README.md`.

## Source base
Toy targets + reference-impl authored in this repo (MIT). Related: [[signature-phishing]],
[[permit-phishing]], [[permit2-phishing]].
