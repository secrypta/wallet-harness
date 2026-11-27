# Vector: approve-drainer (unlimited ERC-20 approve)

**Class:** token-allowance abuse - **Chain:** EVM - **Severity:** critical (full balance loss)
**Prior art:** NDSS'25 cat I-A (ice phishing: Approve); DASP-10 nearest: Access Control.

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** the sink many other vectors funnel into - [[fake-airdrop]] (bait), [[permit-phishing]]/[[permit2-phishing]] (same `transferFrom` sink via signature), [[malicious-calldata]] (hidden `approve`). Those specs describe the *delivery*; this one the standing allowance.

## What it is
An ERC-20 `approve(spender, amount)` grants `spender` the right to move up to `amount`
of the owner's tokens via `transferFrom`. Wallets and dApps routinely request
`amount = type(uint256).max` ("unlimited approve") for convenience. A malicious or
compromised `spender` can then drain the owner's **entire** balance at any later time -
the approval is standing, off-screen, and survives until explicitly revoked.

The danger is not the `approve` transaction itself but the **persistent, unbounded,
third-party authority** it leaves behind.

## Attack mechanics
1. Victim is induced to call `TOKEN.approve(spender, type(uint256).max)` (a fake "claim",
   "enable trading", "connect", or an airdrop lure - see [[fake-airdrop]]).
2. The classic ERC-20 `transferFrom` does **not** decrement an allowance equal to
   `type(uint256).max`. So one unlimited approve = perpetual access, no re-prompt.
3. Any time afterwards, the attacker (not the victim's wallet) calls a drainer:
   `balance = TOKEN.balanceOf(victim); TOKEN.transferFrom(victim, attacker, balance)`.
   The full current balance leaves the victim in a single transaction.

Key property for detection: the loss is bounded by the **granted allowance**, not by
anything the victim does at drain time. A limited approve caps the loss to that limit;
`type(uint256).max` caps it at "everything, forever".

## Defensive signal (what a harness / wallet policy should catch)
A protected flow MUST surface at least one of:
- **Unlimited-approve flag:** an `approve`/`increaseAllowance` whose value is
  `type(uint256).max` (or implausibly large relative to need) to a spender that is not a
  known-trusted contract.
- **Bounded allowance:** approve only the amount the current action needs; residual
  allowance after the action should be ~0.
- **Standing-allowance audit:** existing non-zero allowances to arbitrary spenders are
  discoverable and revocable (allowance = 0).

A protected target is one where the drain path is **not reachable** for the victim's real
assets - either the allowance was bounded (drain reverts on the excess) or the spender is
constrained so `transferFrom` of the full balance cannot succeed.

## Repro (toy targets - proven by test body, not prose)
- **Vulnerable target:** a plain ERC-20 + a `Drainer` spender. Victim does unlimited
  approve -> attacker's `drain()` moves 100% of victim balance. Harness MUST report
  `approve-drainer: VULNERABLE`.
- **Protected target:** same flow but allowance is bounded to the action amount (or
  spender is allow-listed/constrained). Attacker's `drain()` of the full balance reverts;
  victim keeps all but the bounded amount. Harness MUST report `approve-drainer: BLOCKED`
  with **zero false positives** (it must not flag the bounded/limited case as a drain).

Validation bar (same as the project invariant): the harness fires on the vulnerable
target and stays silent on the protected one. The vector is proven by a failing/ passing
test body, never by this description.

> **Independent holdouts (`split=holdout`):** `pennysia-victim` (Pennysia Settlement
> stale-approval drain) and `steth-whale-victim` (the 2023-09-06 whale approval-phishing
> drain - ~$24.24M in stETH + rETH; the victim was phished into `increaseAllowance` to the
> attacker, who then `transferFrom`'d the balance out; verified on-chain drain tx
> `0xcbe7b32e...2f77913`, 9,579.21 stETH) - independent real-incident `b` cases scored on the
> holdout split. See [[real-cases]] and `bench/README.md`.
>
> **Stale-approval holdout (`split=holdout`):** `hedgey-victim` - the Hedgey Finance drain
> (2024-04-19, ~$44.7M). `ClaimCampaigns.createLockedCampaign` approved an **unvalidated**,
> campaign-supplied "locker" address, and the approval was **not revoked on cancel**; the
> residual standing allowance let the attacker `transferFrom` the contract's pooled balance.
> On-chain-verified ETH attack tx `0x2606d459...1595739` (block 19687890, 2024-04-19 07:06:47
> UTC) moved 1,303,910.12 USDC from ClaimCampaigns `0xbc452fdc...` to the attacker. A distinct
> enabling bug (unvalidated-spender + no-revoke stale approval) from the other holdouts.
> Sources: Halborn + CertiK + TechFlow + ImmuneBytes + Rekt.

> **Real-safe holdouts (`split=holdout`, precision side):** beyond `oz-safe-wallet` and
> `solady-erc20-safe`, two more genuinely-safe real-code cases the harness must stay silent
> on: `oz-safeerc20-safe` (OpenZeppelin **SafeERC20** `forceApprove`/revoke bounded-approve
> helper) and `oz-erc4626-safe` (a real OZ **ERC4626** vault whose share token caps a bounded
> approve). Both are unmodified OZ v5.1.0 (MIT), vendored under `fixtures/vendor/oz/`.
> A further independent holdout, `solady-safetransferlib-safe`, routes a scoped
> approve-and-revoke through the real **Solady `SafeTransferLib`** (the approval wrapper
> integrators actually call) over a Solady ERC-20 (Vectorized/solady v0.1.22, MIT): bounded
> allowance, no lingering surface, over-draw reverts. Two more independent Solady holdouts cover
> other token standards: `solady-erc4626-safe` (bounded approve on real Solady **ERC-4626** vault
> shares) and `solady-erc6909-safe` (bounded per-token-id allowance on real Solady **ERC-6909**
> multi-token; over-draw reverts `InsufficientPermission`).

## Source base
Toy targets and the protected-control target authored in this repository (MIT). The
vulnerable/safe pair is minimal by design: an unlimited approve that a single `transferFrom`
drains, versus a bounded approve that reverts the full-balance drain. Related vectors:
[[permit-phishing]], [[fake-airdrop]].
