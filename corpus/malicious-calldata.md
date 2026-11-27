# Vector: malicious-calldata (hidden effect behind a benign-looking action)

**Class:** transaction-intent obfuscation - **Chain:** EVM - **Severity:** high-critical
**Prior art:** NDSS'25 partial II-B (proxy upgrade) / payload obfuscation; DASP-10 nearest: Access Control.

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** the *obfuscation*, not a new sink - the hidden effect is usually an [[approve-drainer]]/[[set-approval-for-all]]/[[permit-phishing]] grant or a [[delegatecall-hijack]] step.

## What it is
Users approve a transaction by its *presented* intent ("Connect", "Claim", "Enable",
"Mint") but what they actually sign is **calldata** whose real effect is something else:
an `approve` / `setApprovalForAll` / `transfer` to the attacker, or a `multicall` /
`delegatecall` bundling a drain step. The label is cosmetic; the calldata is the truth.

Common shapes: a contract whose innocuously named function performs a hidden state change;
a `multicall([...])` where one inner call is the drain; calldata presented as a method the
UI mislabels. The victim's wallet shows a friendly name and an amount of 0 ETH, so nothing
looks wrong.

## Attack mechanics
1. Phishing dApp requests a transaction (or `eth_sendTransaction`) to an attacker contract,
   presented as a harmless action.
2. The calldata actually invokes (directly or via `multicall`/`delegatecall`) an approval
   or transfer that hands the attacker control of the victim's assets.
3. Drain proceeds from the granted approval / direct transfer.

## Defensive signal (what a harness / wallet policy should catch)
- **Decode the real effect:** surface the actual state-changing calls regardless of the
  function's display name - any `approve`/`setApprovalForAll`/`transfer`/`delegatecall`
  reaching the user's assets is the flag, even under a "connect"/"claim" label.
- **Simulate:** a pre-execution simulation showing net asset/allowance changes catches the
  mismatch between presented intent and real effect.
- **Protected target:** a wallet/policy that simulates and surfaces effects refuses (or
  hard-warns) when the decoded calldata grants/transfers assets inconsistent with the
  stated action.

## Repro (toy targets - proven by test body)
Model an attacker contract with a benign-named entrypoint (e.g. `connect()` / `claim()`)
whose body performs a hidden `approve`/`transfer` of the caller's assets, plus a probe that
inspects the resulting allowance/balance delta.
- **Vulnerable target:** wallet executes the calldata by its label -> hidden effect grants
  the drain -> `malicious-calldata: VULNERABLE`.
- **Protected target:** wallet simulates/decodes and only executes calls whose real effect
  matches the intended, scoped action -> the hidden-effect calldata is rejected, assets
  intact -> `malicious-calldata: BLOCKED`, 0 false positives (a genuinely matching benign
  call still succeeds - guard).

Verdict line: `[malicious-calldata] target=<name> verdict=VULNERABLE|BLOCKED`.

## Real-case validation (required beyond toy - see [[real-cases]])
(b) A public incident where a mislabeled/`multicall` calldata hid an approval/transfer
(many drainer kits do this; pick a documented one with provenance). (c) A canonical
contract whose decoded calldata matches its stated effect (harness stays silent). Offline
fixtures with provenance only.

> **Independent holdouts (`split=holdout`):** `squid-multicall-victim`,
> `bebop-jam-settlement-victim`, `socket-gateway-victim`, and `lifi-gaszip-victim` - independent
> real-incident `b` cases scored on the holdout split (Bebop is an arbitrary-caller-calldata
> drain relabelled here from signature-phishing; see its `PROVENANCE.md`).
> `socket-gateway-victim` is the Socket Gateway arbitrary-external-call injection (2024-01-16,
> ~$3.3M): a route ran caller-supplied target+calldata unvalidated, so an injected
> `transferFrom` spent users' standing approvals (a zero-value post-call check was bypassed).
> `lifi-gaszip-victim` is the LI.FI / Jumper exploit (2024-07-16, ~$9.73M): a swap facet ran a
> caller-supplied call target+calldata unvalidated, draining users' infinite approvals to the
> diamond. See `bench/README.md`.

> **More independent holdouts (`split=holdout`, round 3) - distinct arbitrary-call variants:**
> - `transit-claimtokens-victim` - Transit Swap (2022-10-01, BNB Chain, >$21M): a transfer
>   helper ran `transferFrom` with a caller-supplied, UNVALIDATED owner (`from`), so anyone
>   could name a victim who had approved the router and drain them. Attack tx `0x181a7882...`.
> - `rubic-router-whitelist-victim` - Rubic Exchange (2022-12-25, Ethereum, ~$1.4M): a proxy
>   forwarded caller-supplied calldata to any WHITELISTED router, and a TOKEN (USDC) was
>   mistakenly whitelisted, so a `transferFrom` ran as the proxy and drained approvals.
>   Attack tx `0x9a97d856...`.
> - `dexible-selfswap-victim` - Dexible (2023-02-17, Ethereum, ~$2M): the `selfSwap` path ran a
>   caller-supplied router+calldata with NO router validation (plainest form), draining
>   approvals. Attack tx `0x138daa4c...`.
> - `seneca-performoperations-victim` - Seneca Protocol (2024-02-28, Ethereum, ~$6.4M): the
>   `performOperations` batch entrypoint reached an internal `_call` that executed an arbitrary
>   callee+calldata unvalidated; the Chamber held approvals, so a `transferFrom` drained users.
>   Attack tx `0x23fcf9d4...`.
> - `unizen-aggregator-victim` - Unizen (2024-03-08, Ethereum, ~$2.1M): a post-upgrade swap flow
>   ran an arbitrary external call with no source-binding to `msg.sender` and no trusted-router
>   allowlist (confused deputy), draining approvals. Attack tx `0x923d1d63...`.
> - `rabby-swaprouter-victim` - Rabby Wallet Swap router (2022-10-11, Ethereum+BNB, ~$200K): the
>   in-wallet swap router executed a caller-supplied target+calldata via OZ `functionCallWithValue`
>   with no validation, draining users' approvals (a consumer-wallet swap router - on-theme).
>   Attack tx `0x914c1ae4...`.
> Each is the arbitrary-external-call / unvalidated-parameter class, scored as distinct real
> incidents (different protocols/txs) with a distinct failure point (unvalidated owner vs.
> insufficient allowlist vs. no validation vs. batch-dispatch reach vs. missing source-binding).
> See their `PROVENANCE.md` and `bench/README.md`.

> **More independent holdouts (`split=holdout`, round 5) - distinct drain mechanisms:**
> - `hashflow-deprecated-router-victim` - Hashflow (2023-06-14, Ethereum +4 chains, ~$600K): a
>   DEPRECATED contract kept a publicly callable function that still ran `transferFrom` against
>   standing approvals with inadequate access control, so any caller could drain approvers.
>   Attack tx `0xdedda493...` (verified on-chain).
> - `visor-delegated-transfer-victim` - Visor Finance (2021-12-21, Ethereum, ~$8.2M): the vVISR
>   rewards hypervisor's `deposit` trusted a CALLER-SUPPLIED contract for the token pull
>   (`delegatedTransferERC20`) and the share recipient (`owner()`), minting shares with no real
>   transfer; the attacker then withdrew the pool. Attack tx `0x69272d8c...` (verified on-chain).
> Two distinct mechanisms (deprecated unauthorized `transferFrom` vs. trusted caller-supplied
> callback + fake credit), distinct from the arbitrary-call-router family above. See their
> `PROVENANCE.md`. (The Multichain/AnySwap `anySwapOutUnderlyingWithPermit` permit-bypass is
> already covered as `permit-phishing/b-incident/anyswap-permit-bypass-victim` - same incident,
> not re-counted here.)

> **Real-safe holdouts (`split=holdout`, tier c):** `oz-multicall-safe` and
> `solady-multicallable-safe` - routers over the unmodified OpenZeppelin `Multicall` and Solady
> `Multicallable`, which batch calls by delegatecall to `address(this)` ONLY. There is no
> caller-chosen external-call sink, so the Socket-style arbitrary-call injection cannot drain a
> standing approval. The harness must stay silent (BLOCKED) on this canonical self-only
> multicall. Real MIT code (OZ v5.1.0 / Solady v0.1.22); see their `PROVENANCE.md`.

> **Real-safe holdout (`split=holdout`, tier c, round 4):** `oz-timelock-executor-safe` - the
> unmodified OpenZeppelin `TimelockController` used as a gated arbitrary-call executor. Unlike
> the self-only multicalls above, its `execute(target, data, ...)` IS a genuine
> arbitrary-external-call sink - but reaching it needs `EXECUTOR_ROLE` + a prior `schedule`
> (`PROPOSER_ROLE`) + an elapsed min-delay, so an unprivileged attacker cannot inject a
> `transferFrom` against a standing approval. A precision check that a role+delay-gated executor
> is not read as an injection sink. The harness must stay silent (BLOCKED). Real MIT code (OZ
> v5.1.0); see its `PROVENANCE.md`.

> **Real-safe holdout (`split=holdout`, tier c, round 5):** `solady-ownableroles-executor-safe`
> - an arbitrary-call executor gated by Solady `OwnableRoles` (`onlyOwnerOrRoles`). Like the
> timelock executor its `execute(target, data)` is a genuine external-call sink, but the gate is
> owner/role authorization (no delay, no self-only restriction) - an unauthorized caller cannot
> inject a `transferFrom` against a standing approval. A different real gating primitive than
> the self-only multicalls and the role+delay timelock. The harness must stay silent (BLOCKED).
> Real MIT code (Solady v0.1.22); see its `PROVENANCE.md`.

## Source base
New toy attacker contract + probe (English). Related: [[approve-drainer]],
[[signature-phishing]], [[set-approval-for-all]].
