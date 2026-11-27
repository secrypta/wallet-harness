# Validation standard - labeled benchmark with ground truth

A toy pair alone is **not sufficient** evidence. If the same author writes both the
vulnerable and the protected toy, a reviewer rightly says "of course it catches its own."
Every vector is therefore validated against an **independent labeled corpus with ground
truth**, run as a **benchmark** that reports precision/recall. That benchmark - not prose -
is the evidence that the harness works.

## The three tiers per vector (ground-truth labeled)
- **(a) toy pair** - an MIT toy vulnerable + protected target (`test/*.t.sol`). A fast smoke
  that proves the vector mechanics. Labels: one `vuln`, one `safe`.
- **(b) ≥1 real known bug** - a *minimized reproduction* of a real, publicly documented
  incident for this vector (post-mortem / CVE / incident write-up). The harness MUST flag it
  (`VULNERABLE`). Label: `vuln`.
- **(c) ≥1 real safe implementation** - *genuinely* safe real code (OpenZeppelin, Uniswap
  Permit2, or a reference implementation of the canonical defense), NOT a lightly-edited toy.
  The harness MUST stay silent (`BLOCKED`). Label: `safe`. This is the real 0-false-positive
  test.

## Provenance (required in every fixture)
Each fixture carries a provenance block: the incident link / tx hash / audit reference /
source `repo + commit + license`. A fixture that cannot be sourced to a public origin does
not go in. When third-party code is copied into a fixture, its attribution and license are
kept. Where an exact on-chain transaction is not public, the fixture reproduces the
documented *mechanism* and the provenance says so plainly (incident-level / class-level).

## Benchmark run (precision/recall)
The benchmark runs every fixture, each carrying its **expected label** (vuln/safe), compares
the harness verdict (VULNERABLE/BLOCKED) to the label, and prints the confusion matrix plus
**precision / recall** (TP = real bug flagged, FP = safe code flagged, FN = real bug missed,
TN = safe code silent). Target bar: recall 1.0 on known bugs, precision 1.0 on safe code
(0 false positives).

## Boundary - offline, public, no live contracts (hard rule)
- **No checks against live contracts.** Only local, offline fixtures: a minimized copy
  committed to the repo (or pinned bytecode / a pinned-block fork run offline), inside Docker.
  No live RPC calls to live addresses.
- **Public incidents only.** Public token/drainer addresses, public tx hashes, public
  post-mortems - cited. Nothing from private sources.
- **Determinism.** The toy tier stays offline and always-green; the real tier is deterministic
  via committed fixtures (no network dependency in CI).

## Incident references (tier b) and safe basis (tier c), per vector

Honest proof-level is noted per entry: *strong* (named victim/amount/date, tx pinnable),
*incident-level* (named incident, exact per-victim tx not fully public), or *class-level*
(documented pattern/dataset rather than a single tx). For a wallet-phishing class, a faithful
minimized repro of the documented mechanism is the fixture; exact addresses/tx are cited where
public.

### 1. approve-drainer
- **(b) BadgerDAO front-end approval-injection drain**, 2021-12-02, ~$116-120M. An injected UI
  prompted `approve`/`increaseAllowance` to the attacker, then `transferFrom` swept the balance.
  Public addresses/tx: attacker spender `0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107`; example
  victim `0x53461e4fddcc1385f1256ae24ce3505be664f249`; approval tx
  `0x5e4c7966b0eaddaf63f1c89fc1c4c84812905ea79c6bee9d2ada2d2e5afe1f34`; drain tx
  `0x951babdddbfbbba81bbbb7991a959d9815e80cc5d9418d10e692f41541029869`. Sources: Halborn;
  rekt.news/badger-rekt; Microsoft "ice phishing". Proof: strong.
- **(c)** OpenZeppelin `ERC20` v5.1.0 (MIT) under a bounded-approve flow - a full-balance
  `transferFrom` reverts on the unmodified allowance check.
- **(b) Hedgey Finance ClaimCampaigns drain** (contract-level, drain-scan R13), 2024-04-19,
  ~$44.7M. `createLockedCampaign` approved an unvalidated caller-supplied `locker` over pooled
  custody and did not revoke on cancel; the residual allowance let the attacker `transferFrom`
  the pool. Grant/custody use the SafeERC20 / TransferHelper **library** forms
  (`SafeERC20.safeIncreaseAllowance(token, locker, amount)`, spender = 2nd arg), the exact shape
  a member-only scan was blind to. Exploited `0xbc452fdc...3d511`; attack tx `0x2606d459...5739`.
  Committed as a faithful minimized MIT clone (`approve-drainer/b-incident`); the genuine verified
  flattened source was also scanned (Docker, solc 0.8.19) -> R13 TP. Sources: Halborn, CertiK,
  TechFlow, Rekt. Proof: strong.
- **(c) Hedgey ClaimCampaigns, current hardened version** (drain-scan R13 precision control).
  Deployed + Etherscan-verified `0x8A2725a6f04816A5274dDD9FEaDd3bd0C253C1A6` (mainnet), solc
  0.8.28, repo `hedgey-finance/ClaimCampaigns`. It is genuinely safe (locker is a
  constructor-curated allow-list entry **and** every claim path asserts
  `require(allowance(address(this), locker) == 0)` after the pull - no residual allowance). R13
  stays silent (0-FP) after the zero-residual suppressor. **License BUSL-1.1 -> NOT vendored**:
  validated in Docker only, no fixture committed. *Caveat:* this is the current official hardened
  source; the repo's git history starts Oct 2024, so it is not confirmed to be the exact
  Apr-2024 post-exploit fix commit.

### 2. permit-phishing
- **(b) USDC ERC-2612 permit drain**, 2026-03-16, ~$1.77M USDC in one tx. A genuine `permit`
  (selector `0xd505accf`, value = MAX_UINT256, deadline = never) consumed off-chain, then
  `transferFrom` in the same tx. Drain tx
  `0xfd7417af8433e3d9bcbed3f965307c800a24eb4e98f42cebfab6ca6064f5a642` (block 24671606); victim
  `0x051bb76ff78366de530e293fdb1158c2079ab664`; spender/drainer
  `0x0927ba1f2a31875b0dd7b28eec3a3e74b4620653`; USDC
  `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`. Sources: darknavy.org write-up; Etherscan.
  Proof: strong.
- **(c)** OpenZeppelin `ERC20Permit`/`EIP712`/`ECDSA` v5.1.0 (MIT) under a bounded-permit flow.

### 3. set-approval-for-all
- **(b) Monkey Drainer** NFT phishing-as-a-service, 2022-2023. Victims `setApprovalForAll`
  (selector `0xa22cb465`) to a malicious operator; whole collections swept. SlowMist *estimated*
  the group's total at ~$12.972M across 1,708 addresses (on-chain analysis, 2023-02); the
  widely-cited $16M/$24M figures are unverified press / self-report. Sources: SlowMist "Analysis of
  Monkey Drainer NFT Phishing Group"
  (https://slowmist.medium.com/slowmist-analysis-of-monkey-drainer-nft-phishing-group-e4e269634854);
  ZeroTrace Labs Monkey Drainer write-up; arXiv 2409.02386 payload-phishing dataset. Proof:
  incident-level (named operation; per-victim tx not fully public at blog level).
- **(c)** OpenZeppelin `ERC721` v5.1.0 (MIT) under a scoped-approve flow.

### 4. fake-airdrop
- **(b) LFG fake-airdrop guide**, 2023, ~$125K stETH. A fake airdrop "claim" induced an
  approval/permit on the victim's real asset. Sources: The Block (2024-01-03 Scam Sniffer
  report); Scam Sniffer. Proof: incident-level (named victim/amount).
- **(c)** OpenZeppelin `ERC20` v5.1.0 (MIT) as the real asset; the safe claim grants no standing
  allowance, so a full drain reverts.

### 5. signature-phishing
- **(b) Seaport/Wyvern order-signature phishing** - OpenSea migration phishing (Feb 2022) and
  Kevin Rose / Moonbirds (Jan 2023). Victims blind-signed off-chain EIP-712 orders that
  transferred NFTs on fulfilment. Sources: public post-mortems of both campaigns. Proof:
  incident-level (pattern documented; standardized tx not public per victim).
- **(c)** A scoped settlement policy on real OpenZeppelin `EIP712`+`ECDSA` (MIT): only a
  decodable typed order to an allow-listed counterparty within a cap is accepted.

### 6. address-poisoning
- **(b)** Dec 2024 ~$50M USDT case (victim paid a poisoned look-alike address); a May 2024
  ~$68M campaign; zero-value / dust poisoning. Sources: Spark research; Elliptic; Etherscan.
  Proof: incident-level (documented campaigns; victim tx pinnable from Etherscan).
- **(c)** Two safe fixtures. (i) `verified-send-safe` - reference implementation of canonical
  full-address verification (send only to an address verified by its *full* value, not a
  truncated display). (ii) `oz-erc20-benign-nearcollision-safe` - a 0-FP precision control whose
  **transfer is real unmodified OpenZeppelin v5.1.0 `ERC20.transfer`** (MIT, commit `69c8def5`),
  wrapped in an **authored** benign near-collision scenario (a legit send to the verified full
  address while a displayed-prefix/suffix decoy exists in history; the detector must stay silent).
  **Vector boundary (conscious, not a corpus gap):** address poisoning is a UX / transaction-
  history attack, so there is **no canonical third-party on-chain anti-poisoning library** to
  vendor as an independent `split=holdout` safe implementation - the defence lives in the wallet
  / UX (verify the full address). The real OZ code above is genuine; the near-collision *scenario*
  around it is authored and labelled as such (not passed off as an independent real-world safe
  impl).

### 7. malicious-calldata
- **(b)** Mislabeled / `multicall`-hidden approval in drainer kits - a benign-looking action
  (e.g. `Verify()`/`Connect()`) that hides an `approve(attacker, 2^256-1)` (selector
  `0x095ea7b3`). Documented as a class (arXiv 2409.02386), and **incident-anchored** to the
  Inferno Drainer "Reloaded" campaign (Check Point Research 2025, ~$9M / 30K+ wallets,
  2024-09...2025-03). Representative public transactions cited in the Check Point report:
  operator `0x0000db5c8B030ae20308ac975898E09741e70000`, multicall helper
  `0x0B7A19c3d261dcEeb6ed3b2023B07b6cc4E60543`; ERC-20 theft trace
  `0x2e122bed57044a997bd710b25bb58310a124bd10941e881a88393d62e7e1540d`; a USDC drain
  `0x48814377bfc3e5f76283b3cd3b166442328972a8f6f9074b8d6b9693ce25c40a` (2024-10-09).
  Proof: **class-level, incident-anchored**. Honesty caveat: in the documented Inferno flow
  the `approve` and the drain are *separate* transactions (closer to [[approve-drainer]]);
  our fixture models the single-transaction hidden-`approve` variant of the same class, so the
  cited tx anchor the campaign, not a byte-replay of one tx.
- **(c)** Reference implementation of net-effect transaction simulation (dry-run, inspect the
  net asset/allowance delta, revert on a hidden grant) - the Fire / Blockaid / Pocket Universe
  class of defense.

### 8. eip7702-delegation
- **(b)** The reusable 7702 sweeper pattern ("CrimeEnjoyor", documented by Wintermute), live
  since the 2025 Pectra upgrade: a victim's EOA is delegated (via a signed SET_CODE
  authorization) to a sweeper contract that drains everything in one tx. Sources: Wintermute
  analysis; Scam Sniffer. Proof: incident/class-level (reported dollar figures vary across
  secondary write-ups; the fixture reproduces the mechanism).
- **(c)** Reference implementation that honors a 7702 delegation only to an allow-listed,
  audited delegate and refuses unknown ones.

### 9. permit2-phishing
- **(b)** 2024-10-13, a PEPE holder lost ~$1.39M (PEPE + MSTR + APU) after signing a single
  Uniswap **Permit2** phishing signature granting unrestricted pull rights. Permit2 contract
  `0x000000000022D473030F116dDEE9F6B43aC78BA3`. Sources: Scam Sniffer; Decrypt
  (decrypt.co/286076); Crypto Times. Proof: strong.
- **(c)** The **real Uniswap Permit2** (MIT) vendored byte-for-byte under a scoped-signature
  policy; a full-balance `transferFrom` reverts on the real allowance check. (The two upstream
  solmate imports, which carry a different license, are replaced with an MIT-equivalent token
  shim; Permit2's signature/allowance logic is unmodified - see `fixtures/vendor/permit2/`.)

### 10. create2-metamorphic
- **(b)** CREATE2 drainers: pre-computing a fresh address per malicious signature so wallets
  have no history to flag - Scam Sniffer (2023-11-12), ~$60M from ~99K victims over six months;
  and metamorphic address reuse (deploy benign code -> get approved -> `SELFDESTRUCT` -> redeploy
  malicious at the same address). Sources: Scam Sniffer; CoinDesk (2023-11-13); BleepingComputer;
  MixBytes.
  Concrete transaction (cited in the Scam Sniffer report, on Arbitrum): drain tx
  `0x0b8d095c9ee0f27362240ed3f315afa12d6f88a6a0c15b99231bc14d4dd1fb96` - victim lost ~$927K
  (GMX, via a `signalTransfer` in the GMX Reward Router) to a pre-computed CREATE2 receiver.
  Drainer CREATE2 receivers `0xbD2BF58Be46619B7A22cE9457e1D51A10B82EB91` and
  `0x4d9f7773deb9cc44b34066f5e36a5ec98ac92d40`; drainer CREATE2 factory
  `0x00004d035111f89dc358edc8d316fd2ad3f80000` (`calculateAddress`/`createAndCall`).
  Proof: **incident-level** for the fresh-address variant (concrete tx + addresses from the
  Scam Sniffer report). The metamorphic address-reuse variant stays **class-level** - EIP-6780
  (Cancun, 2024) restricts the `SELFDESTRUCT`-redeploy trick; the fixture reproduces the mechanism.
- **(c)** Reference implementation of codehash pinning: record `EXTCODEHASH` of an approved
  address and re-check it before the drain path, rejecting a swapped/empty contract.

### 11. delegatecall-hijack
- **(b) Bybit**, 2025-02-21, ~$1.46B (largest crypto theft on record). A Safe multisig
  transaction whose `operation` flag was flipped from `call` to `delegatecall` ran
  attacker-deployed code in the wallet's storage context and swapped the implementation -
  full account takeover. Root cause was a Safe{Wallet} front-end supply-chain compromise, not a
  contract bug. Sources: CertiK; SlowMist; NCC Group; BleepingComputer. Proof: mechanism-level
  (full calldata/traces not all public; the fixture reproduces the delegatecall swap).
- **(c)** Reference implementation of a Safe-style transaction guard plus an implementation-slot
  invariant that blocks delegatecall to non-allow-listed targets.

### 12. blind-eth-sign
- **(b)** The legacy `eth_sign` path signs an opaque 32-byte hash with no displayable structure;
  drainers used it to obtain blind authorizations. MetaMask MIP-3 (accepted 2024-05-15) removed
  `eth_sign` citing blind-signing phishing risk; Safe removed it after the Bybit hack; the
  Ethereum Foundation launched Clear Signing (ERC-7730) in response. Sources: MetaMask MIP-3;
  "ETH sign Phishing Explained" (Onchain Diary); Scam Sniffer. Proof: class-level.
- **(c)** Reference implementation that accepts only decodable EIP-712 typed signatures and
  rejects raw-hash signing (the clear-signing direction).

### 13. upgrade-governance
- **(b) PAID Network**, 2021-03-05, ~$3M (attacker-minted/dumped). An unguarded single-key proxy
  upgrade swapped in a malicious implementation that minted tokens. **Audius**, 2022-07-23,
  ~$1.1M (~705 ETH + 18.5M AUDIO) - a publicly callable proxy `initialize` let an attacker install
  themselves as the governance `controller` and push a malicious proposal. Sources: Audius
  post-mortem; rekt.news; SlowMist. Proof: mechanism-level (fixtures reproduce the unguarded
  upgrade / initialize-takeover surface).
- **(c)** OpenZeppelin `UUPSUpgradeable` + `TimelockController` v5.1.0 (MIT) - a timelock-gated
  upgrade with a guardian, on which the detector stays silent.

## Status
The validation standard described here is fully realized: all 13 vectors are built to a/b/c
depth and the benchmark scores 155 labeled fixtures (61 dev + 94 post-freeze holdout) at
precision = recall = 1.0 on the dev and holdout splits (a self-consistency run: each fixture has its
own exploit/control test); an additional **external** cross-validation
split (SmartBugs-Curated / SWC) checks the companion scanner against ground truth we did not
author. Related:
[[approve-drainer]], [[permit-phishing]], [[set-approval-for-all]], [[fake-airdrop]],
[[signature-phishing]], [[address-poisoning]], [[malicious-calldata]], [[eip7702-delegation]],
[[permit2-phishing]], [[create2-metamorphic]], [[delegatecall-hijack]], [[blind-eth-sign]],
[[upgrade-governance]].
