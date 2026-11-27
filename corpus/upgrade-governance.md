# Vector: upgrade-governance (upgradeable wallet without timelock/guardian)

**Class:** account/code-trust governance - **Chain:** EVM - **Severity:** high
**Prior art:** OWASP Smart Contract Top-10 (2026) lists "Proxy & Upgradeability" as a category; canonical proxy-governance guidance (OpenZeppelin TimelockController / UUPS upgrade authorization; Safe guardian/module patterns). Real incidents: PAID Network (2021), UPCX, proxy-admin key compromises. Post-Cancun note: this replaces a `selfdestruct`-based code-mutation vector, obsolete under EIP-6780.

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** the code-trust sibling of [[delegatecall-hijack]] (implementation takeover) and [[create2-metamorphic]] (code mutation at a trusted address). Distinct in *who* swaps the code and how it is governed.

## What it is
A smart-contract wallet (or account / module host) that delegates its asset-moving logic to
a **swappable implementation** - a proxy implementation, an installed module, or a delegate.
The drain surface is not the delegation itself but its **governance**: if a single key
(owner/admin) can replace that implementation **instantly**, with no timelock, delay, or
guardian, then whoever holds that one key can swap in a hostile implementation and empty the
wallet in the same transaction. One compromised key == instant malicious upgrade == full
drain.

This is a wallet-code defect, not a UX attack: the hostile upgrade is a legitimate call made
by a legitimately-authorized (but compromised) key. The defense is structural - put a
delay/guardian between "I hold the key" and "the code changed".

## Attack mechanics
1. The wallet holds the victim's assets and routes operations through `implementation`
   (delegatecall / module call), which therefore has full authority over those assets.
2. The owner key is compromised (phished seed, leaked hot key, a malicious or coerced
   signer).
3. The attacker, acting as owner, calls `upgradeTo(hostileImpl)` - which takes effect
   immediately - then triggers one `execute`. The hostile implementation ignores the
   requested operation and sweeps the full balance to the attacker.

## Defensive signal (what a harness / wallet policy should catch)
- **Timelock on upgrades:** an implementation/module swap cannot take effect in the same
  call it is requested; it is a two-step propose -> (delay) -> apply, so an instant swap is
  impossible.
- **Guardian / second factor:** a separate key can cancel a pending upgrade during the delay
  window (or a 2-of-N threshold is required to apply it), so a single compromised key is not
  sufficient.
- **Protected target:** a wallet whose upgrade path is delay-gated and guardian-cancellable;
  a compromised owner alone cannot swap in a hostile implementation and drain.
- **Static-detector form:** fire only when a single-key call mutates the
  implementation/module/delegate slot with no delay/guardian/threshold between request and
  effect; stay silent when the swap is routed through a timelock/guardian.

## Repro (toy targets - proven by test body)
Model an upgradeable wallet that delegatecalls a swappable implementation, a benign
implementation (pays the requested amount), and a malicious implementation (sweeps the full
balance to the attacker). Simulate a compromised owner key and probe whether the attacker can
swap + drain.
- **Vulnerable target:** owner swaps the implementation instantly (`upgradeTo`) and the next
  `execute` sweeps the wallet -> `upgrade-governance: VULNERABLE`.
- **Protected target:** the same compromised owner can only *propose* the hostile
  implementation; applying it immediately reverts on the timelock (and a guardian can cancel
  it), so the benign implementation stays active and no drain occurs ->
  `upgrade-governance: BLOCKED`, 0 false positives. Guard: a legitimate upgrade still applies
  after the delay and normal `execute` still works, so BLOCKED is not vacuous.

Verdict line: `[upgrade-governance] target=<name> verdict=VULNERABLE|BLOCKED`.

## Real-case validation (required beyond toy - see [[real-cases]])
(b) A public incident where an unguarded single-key implementation/admin swap (or equivalent
instant upgrade) enabled asset loss, minimized offline with provenance. (c) A canonical
delay/guardian-gated upgrade path (OpenZeppelin TimelockController-style or a Safe guardian
module) that the harness stays silent on. Offline fixtures with provenance.

> **Independent holdouts (`split=holdout`):**
> - `audius-governance-victim` - the Audius governance takeover via a callable proxy
>   `initialize` (2022-07-23).
> - `beanstalk-governance-victim` - the Beanstalk flash-loan governance takeover (2022-04-17,
>   ~$182M): governance with no timelock and no flash-loan-resistant snapshot let an
>   instantaneously-acquired supermajority `emergencyCommit` a proposal that was delegatecalled
>   in the protocol's context and swept its assets.
> - `nomad-reinit-root-victim` - the Nomad Bridge exploit (2022-08-01, Ethereum, ~$190M): a
>   routine implementation UPGRADE re-ran the Replica initializer, which marked the ZERO root
>   acceptable; every forged (un-proven) message then resolved to the zero root and passed
>   `process()`, draining custodied funds. An upgrade-introduced authorization bypass (distinct
>   from flash-governance and proxy-reinit-storage-collision). Process-out tx `0xa5fe9d04...`.
> - `poly-keeper-takeover-victim` - the Poly Network exploit (2021-08-10, Ethereum, ~$611M): the
>   cross-chain manager executed inbound messages with its own authority and did not stop a
>   message from targeting its OWN privileged keeper-management function, so a crafted message
>   reassigned the keeper role to the attacker, who then authorized withdrawals and drained the
>   vaults. A privileged-ROLE takeover (the drain follows from seizing the role, not from
>   pulling approvals). Keeper-takeover tx `0xb1f70464...`, drain tx `0xad7a2c70...`.
>
> Independent real-incident `b` cases scored on the holdout split. See [[real-cases]] and
> `bench/README.md`.

> **Real-safe holdout (`split=holdout`, tier c):** `solady-uups-timelock-safe` - the
> independent-codebase sibling of `oz-timelock-safe`: unmodified Solady `UUPSUpgradeable`
> behind an OpenZeppelin `TimelockController` authority, so an instant single-key upgrade
> reverts while a timelock-scheduled upgrade still applies after the delay. The harness must
> stay silent (BLOCKED). Real MIT code (Solady v0.1.22 + OZ v5.1.0); see its `PROVENANCE.md`.

> **Real-safe holdout (`split=holdout`, tier c, round 4):** `oz-accessmanager-safe` - a managed
> vault whose sensitive admin op defers to the unmodified OpenZeppelin `AccessManager`
> (`canCall`). A different canonical governance primitive from the two timelock fixtures: a key
> with no role is rejected, and a key whose role carries an execution delay is also rejected for
> a direct call (it must schedule), so there is no instant single-key swap. The harness must
> stay silent (BLOCKED). Real MIT code (OZ v5.1.0); see its `PROVENANCE.md`.

> **Real-safe holdout (`split=holdout`, tier c, round 5):** `oz-governor-safe` - a full
> OpenZeppelin Governor stack (GovernorVotes + quorum + GovernorTimelockControl) owns the
> protected op. A distinct governance MECHANISM from the timelock- and AccessManager-gated
> fixtures: a change requires a token-weighted vote to pass (propose -> vote -> queue -> execute
> through the timelock), so a lone key can neither call the protected op directly nor pass a
> proposal without quorum + majority weight. A legitimate vote does apply the change
> (non-vacuous). The harness must stay silent (BLOCKED). Real MIT code (OZ v5.1.0); see its
> `PROVENANCE.md`.

> **No additional real-incident fixture from UPCX (honest survey, 2026-11-17).** UPCX (2025-04,
> ~$70M) is a genuine single-key proxy-admin upgrade takeover and a good vector fit, but public
> write-ups (Halborn + mainstream coverage) do not pin a verifiable on-chain artifact to our
> strengthened bar: the chain is reported ambiguously, and no full attacker address or attack
> transaction hash appears consistently across independent sources. Rather than guess, no UPCX
> fixture is added; `beanstalk-governance-victim` and `audius-governance-victim` remain the
> real-incident holdouts, with `oz-timelock-safe` / `solady-uups-timelock-safe` as real-safe.

> **Real-incident holdout (`split=holdout`, round 5):** `wormhole-uninit-impl-victim` - Wormhole
> uninitialized-implementation bug (disclosed 2022-02-24 by whitehat satya0x; $10M Immunefi
> bounty). A UUPS IMPLEMENTATION contract was left uninitialized, so anyone could call
> `initialize()` on it directly, seize guardian control, and invoke the guardian-only upgrade
> path (which delegatecalled a selfdestruct that would brick the proxy). A distinct takeover
> mechanism from a proxy reinit (`nomad`), a compromised key (`paid-upgrade`), a keeper takeover
> (`poly-keeper`), or a governance vote (`beanstalk`). MECHANISM-LEVEL: no attack tx exists (a
> whitehat disclosure, never exploited); the selfdestruct consequence is abstracted to its
> takeover precondition. Documented by Immunefi + Coinspect + r.security. Harness VULNERABLE.
> See its `PROVENANCE.md`.

## Source base
New toy wallet pair authored in this repo (English, MIT): `src/VulnerableUpgradeWallet.sol`,
`src/SafeUpgradeWallet.sol`, logic modules `src/UpgradeModules.sol`, test
`test/UpgradeGovernance.t.sol`. The "target" is the upgrade policy, not the delegatecall.
Related: [[delegatecall-hijack]] (controlled-delegatecall target), [[create2-metamorphic]]
(trust in mutable code).
