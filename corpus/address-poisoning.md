# Vector: address-poisoning (look-alike address in history)

**Class:** transaction-history spoofing - **Chain:** EVM - **Severity:** high
**Prior art:** NDSS'25 cat III (zero-value / fake-token / dust); dedicated studies USENIX'25 (arXiv 2501.16681), CCS'24 Poison-Hunter; DASP-10: Unknown Unknowns.

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** the most self-contained vector - a transaction-history/UX spoof with the thinnest on-chain code surface. Independent of the allowance/signature family above.

## What it is
Wallets display addresses truncated (`0x1234...cdef`) and users often copy a destination from
their **transaction history** rather than a verified source. An attacker generates a
vanity address that matches the leading/trailing hex of a real counterparty the victim
transacts with, then plants it in the victim's history - typically a **zero-value or dust
transfer** from (or to) that look-alike address. Later the victim copies the poisoned
address from history and sends real funds to the attacker.

No contract is exploited; the "bug" is the human/UI trusting a truncated match from
unverified history.

## Attack mechanics
1. Attacker mints a vanity address `0x1234...cdef` matching the victim's real counterparty
   `0x1234...cdef` in the displayed (truncated) form but different in the middle.
2. Attacker plants it in the victim's history: a 0-value transfer, a dust send, or a fake
   token transfer event that shows up next to the real counterparty.
3. Victim later copies the address from history (it "looks right") and sends funds -
   straight to the attacker.

## Defensive signal (what a harness / wallet policy should catch)
- **Full-address verification:** compare the full destination, never the truncated form;
  a destination that matches a known counterparty only on prefix/suffix but differs in the
  middle is the flag.
- **Verified address book:** sending to an address that appeared only via an unsolicited
  zero-value/dust transfer (not a verified, user-saved counterparty) is flagged.
- **Protected target:** a send policy that resolves the destination against verified
  counterparties (full address) and rejects an unverified look-alike pulled from history.

## Repro (toy targets - proven by test body)
Model a wallet `send(to, amount)` plus a verified address book and a poisoned look-alike
entry (same displayed prefix/suffix, different full address). Probe: does the victim's
transfer reach the attacker or the real counterparty?
- **Vulnerable target:** wallet sends to the address copied from poisoned history -> funds
  reach the attacker -> `address-poisoning: VULNERABLE`.
- **Protected target:** wallet verifies the full address against the address book and
  rejects the look-alike -> funds do not reach the attacker (send reverts or routes to the
  verified counterparty) -> `address-poisoning: BLOCKED`, 0 false positives (a genuine send
  to a verified counterparty still succeeds - guard).

Verdict line: `[address-poisoning] target=<name> verdict=VULNERABLE|BLOCKED`.

## Real-case validation (required beyond toy - see [[real-cases]])
(b) A public address-poisoning incident (several large ones are documented with the
poisoning tx and the victim's mistaken send - pick one with provenance). (c) A wallet send
flow with full-address verification (harness stays silent). Offline fixtures with provenance.

> **Independent holdout (`split=holdout`):** `wbtc-poison-victim` - the ~1,155 WBTC
> address-poisoning drain (2024-05-03) where the victim copied a look-alike recipient from
> poisoned history, an independent real-incident `b` case scored on the holdout split. See
> [[real-cases]] and `bench/README.md`.
>
> **Real-safe precision control (`c`):** `oz-erc20-benign-nearcollision-safe` - the honest
> 0-false-positive complement. The transfer is the **unmodified OpenZeppelin v5.1.0
> `ERC20.transfer`** (real MIT code, commit `69c8def5`, via `OZERC20Fixture`); the scenario is
> an **authored** benign near-collision: a decoy in history shares the displayed prefix+suffix
> with the verified counterparty, yet the user pays the correct FULL address. The detector must
> stay silent - flagging a legitimate send over a coincidental truncated-display overlap would
> be a false positive. Funds reach the intended recipient, the decoy gets nothing -> BLOCKED.
> Honest scope: real OZ code + authored scenario, **not** an independent real-world holdout and
> not a real incident (there is no third-party on-chain anti-poisoning library - see below and
> [[real-cases]]). Distinct from `verified-send-safe` (a *policy* rejecting a poisoned target):
> this pins the other side - a plain real transfer to the *right* target must not be flagged.

## Source base
New toy wallet + address book (English). This is a UX/history attack, not a contract bug -
the "target" is the send policy. Related: [[fake-airdrop]], [[malicious-calldata]].
