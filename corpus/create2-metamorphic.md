# Vector: create2-metamorphic (approved-address code swap)

**Class:** deterministic-address code mutation - **Chain:** EVM - **Severity:** high->critical
**Prior art:** not covered by NDSS'25 phishing or DASP-10/SWC (metamorphic-contract class: CREATE2 + SELFDESTRUCT).

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** the standing trust it abuses is an [[approve-drainer]]/[[set-approval-for-all]] approval to the metamorphic address; code-mutation sibling of [[upgrade-governance]].

## What it is
`CREATE2` deploys a contract to an address derived from `(deployer, salt, initcode)` - a
**deterministic, pre-computable** address independent of nonce. Combined with `SELFDESTRUCT`
(pre-Cancun semantics), the same address can be **redeployed with different code**
("metamorphic"). The drain: a victim grants an approval (or trusts) a contract that holds
**benign** code at a known CREATE2 address; the attacker then destroys and redeploys
**malicious** code at that *same, already-approved* address and drains.

A related, simpler variant drainers use in the wild: pre-compute a fresh CREATE2 address per
victim so each malicious signature points at an address with **no reporting history**, to
slip past wallet blocklists.

## Attack mechanics
1. Attacker deploys benign-looking code at a CREATE2 address `A`; victim approves / trusts `A`.
2. Attacker `SELFDESTRUCT`s `A`, then redeploys attacker code at the same `A` (same salt,
   new initcode) - the standing approval now points at hostile logic.
3. The redeployed `A` calls `transferFrom`/`drain` on the victim's still-valid approval.

> **Honesty note (Cancun):** EIP-6780 (Cancun, 2024) restricted `SELFDESTRUCT` so the classic
> redeploy-at-same-address trick no longer works except within the same tx as creation. The
> fixture reproduces the *mechanism* and marks this caveat in PROVENANCE; the fresh-address
> blocklist-evasion variant is unaffected and independently documented.

## Defensive signal (what a harness / wallet policy should catch)
- **Codehash pinning:** record `EXTCODEHASH` of an approved/trusted contract at approve time;
  flag/refuse if the code at that address later differs (metamorphic swap) or is empty.
- **No-history-address flag:** approving a brand-new contract with no history for a
  full-balance authority.
- A protected target: the wallet re-checks the approved address's codehash before letting the
  drain path execute, so the swapped code is rejected.

## Targets (for the benchmark)
- `a-toy`: `vulnerable-create2` (approve address `A`; `A`'s code swaps to a drainer -> drain)
  vs `safe-create2` (codehash pinned -> swapped code rejected, drain reverts).
- `b-incident`: `metamorphic-approve-victim` - the CREATE2 drainer/address-reuse pattern
  documented by Scam Sniffer (CREATE2 blocklist-evasion, ~$60M/99k victims over 6 months,
  2023-2024) and MixBytes (metamorphic address reuse). See [[real-cases]] §(b)
  create2-metamorphic. Honest proof level: class-level (reproduce the documented pattern).
- `c-safe-impl`: `codehash-pinned-safe` - reference-impl of codehash-pinning at approve time.

> **Independent holdout (`split=holdout`):** `tornado-governance-victim` - Tornado Cash
> governance takeover via a metamorphic (CREATE2 + SELFDESTRUCT + redeploy) proposal
> (2023-05-21), an independent real-incident `b` case scored on the holdout split. See
> [[real-cases]] and `bench/README.md`.

> **No additional real-incident fixture (honest survey, 2026-11-17).** A search for a
> *new* real metamorphic/CREATE2 incident beyond the two already modeled (the `b-incident`
> `metamorphic-approve-victim` CREATE2 blocklist-evasion pattern and the `tornado-governance-victim`
> holdout) found no clean candidate that clears our bar: a public post-mortem with an on-chain
> artifact **and** an offline-reproducible minimization. The classic selfdestruct->redeploy code
> swap is no longer offline-reproducible on Cancun (EIP-6780 restricts `SELFDESTRUCT` to the
> creating transaction), and the in-the-wild CREATE2 drainer activity is the fresh-address
> blocklist-evasion variant already captured by `metamorphic-approve-victim`. Rather than
> stretch a weak case, this vector keeps its two existing real-incident fixtures. (Per task
> note: create2 is the hard one; a forced fixture would be dishonest.)

> **Real-safe holdout (`split=holdout`, tier c):** `solady-libclone-safe` - a factory over the
> unmodified Solady `LibClone.cloneDeterministic` (canonical CREATE2 minimal-proxy deployer).
> The clone has no `selfdestruct`, and a different implementation derives a different address,
> so the deterministic address can never hold different code - the metamorphic swap is
> impossible. A precision check: legitimate, ubiquitous CREATE2 usage must NOT be flagged. The
> harness must stay silent (BLOCKED). Real MIT code (Solady v0.1.22); see its `PROVENANCE.md`.

> **Real-safe holdout (`split=holdout`, tier c, round 4):** `oz-clones-safe` - the same
> immutable-clone guarantee on a different canonical library: the unmodified OpenZeppelin
> `Clones.cloneDeterministic` (EIP-1167 minimal proxy). No `selfdestruct`, and OZ bakes the
> implementation into the clone init code, so a different impl derives a different address - the
> deterministic address can never hold different code. The harness must stay silent (BLOCKED).
> Real MIT code (OZ v5.1.0); see its `PROVENANCE.md`.

> **Real-safe holdout (`split=holdout`, tier c, round 5):** `solady-create3-safe` - Solady
> `CREATE3`, a different deterministic-deploy mechanism. The address depends only on
> (salt, deployer), INDEPENDENT of init code, and nothing self-destructs; so a redeploy at the
> same salt - even with different code - targets the SAME address and fails. Unlike the EIP-1167
> clones (address derived from code), CREATE3 fixes the address up front, and it still cannot be
> replaced. The harness must stay silent (BLOCKED). Real MIT code (Solady v0.1.22); see its
> `PROVENANCE.md`.

## Source base
Toy targets + reference-impl authored in this repo (MIT). Tier (c) is a reference-impl of the
canonical codehash-pinning defense, marked honestly in PROVENANCE. Related:
[[approve-drainer]], [[address-poisoning]].
