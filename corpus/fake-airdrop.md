# Vector: fake-airdrop (scam-token bait -> approval on the real asset)

**Class:** social-engineering + allowance abuse - **Chain:** EVM - **Severity:** critical
**Prior art:** NDSS'25 cat IV-A (payable: airdrop/claim function); DASP-10: Unknown Unknowns.

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** a *delivery* vector, not a distinct code sink - its end state is an [[approve-drainer]] allowance or a [[permit-phishing]] signature on the real asset. Those rules flag the drain; this spec documents the bait/mismatch.

## What it is
An unsolicited "gift" token appears in the victim's wallet (a constructor mint, a mass
airdrop). The token's name/UX lures the victim to a site to "claim" / "unlock" / "enable"
the reward. The claim action is not about the gift at all - it makes the victim grant an
allowance (or sign a permit) on their **real, valuable** asset to an attacker spender,
which is then drained via [[approve-drainer]] / [[permit-phishing]].

The bait token is worthless and untouched; the loss is the victim's genuine holdings. The
distinct signal of this vector is the **mismatch**: the thing that lured you (gift token)
is not the thing the approval targets (your real asset).

## Attack mechanics
1. Victim receives an unsolicited `GiftToken` balance (no action by them).
2. "Claim reward" flow induces `realToken.approve(spender, type(uint256).max)` (or a
   permit) - on the real asset, not the gift.
3. Attacker drains the real asset. Gift balance stays, maintaining the illusion.

## Defensive signal (what a harness / wallet policy should catch)
- **Unsolicited-token flag:** a token balance that arrived without the owner initiating it
  is untrusted; interacting with it is the entry point of the scam.
- **Approval-target mismatch:** surface which token and spender the "claim" actually
  approves. An approval on a *different, valuable* asset while the user thinks they act on
  the gift is the flag.
- **Bounded/zero approval:** the real asset should receive only the approval the genuine
  action needs (here: none) - a protected flow leaves the real asset's allowance at ~0.

A protected target performs the claim without granting a drainable allowance on the real
asset (bounded/zero), so the attacker's full-balance drain of the real asset reverts.

## Repro (toy targets - proven by test body)
Add a toy `GiftToken` (constructor mints the bait to the holder, mirroring the unsolicited
airdrop) + reuse `MockERC20` (real asset) and `MaliciousSpender`.
- **Vulnerable target:** claim flow does `realToken.approve(spender, max)` -> attacker
  drains 100% of the **real** asset; gift untouched -> `fake-airdrop: VULNERABLE`.
  Assert the drained token is the real asset and the gift balance is unchanged.
- **Protected target:** claim flow grants no drainable allowance on the real asset (0 or
  exactly the action need) -> attacker's full-balance drain reverts, real asset intact ->
  `fake-airdrop: BLOCKED`, 0 false positives.

Verdict line: `[fake-airdrop] target=<name> verdict=VULNERABLE|BLOCKED`. Target names must
match the harness gate (`*vulnerable*` / `*safe*|*protected*`). Validation bar: fires on
vulnerable, silent on protected.

> **No independent *vulnerable* holdout** for this vector - precision-side only. The
> independent (`split=holdout`) case is real safe code the detector must stay silent on:
> `solady-merkle-airdrop-safe` (Solady `MerkleProofLib` under a canonical Merkle airdrop, 0 FP)
> and `oz-merkleproof-safe` (real OpenZeppelin v5.1.0 `MerkleProof` under the same canonical
> distributor pattern - a different canonical verifier, double-hash leaf; an absent account /
> wrong amount / forged proof cannot claim, 0 FP) and `signature-voucher-safe` (real OZ
> `EIP712`+`ECDSA` authority-signed voucher - a different inclusion mechanism than a Merkle proof;
> a forged voucher recovers to a non-authority signer and is rejected, 0 FP).
> See `bench/README.md`.

## Source base
Toy targets authored in this repository (MIT): a bait/scam token and a claim flow that
induces an approval on the victim's real asset, plus the safe claim control. Related:
[[approve-drainer]], [[permit-phishing]].
