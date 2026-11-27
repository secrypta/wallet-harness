# Vector: eip7702-delegation (account-delegation abuse)

**Class:** account-delegation abuse - **Chain:** EVM (post-Pectra) - **Severity:** critical
**Prior art:** not in NDSS'25/DASP-10; dedicated study: EIP-7702 phishing (arXiv 2512.12174).

> **STATUS:** all three tiers are shipped - `a-toy` + `b-incident` + `c-safe-impl` - and scored by the benchmark (precision/recall = 1.0). (Was stale in an earlier draft; reconciled to `fixtures/` 2026-11-14.)
>
> **SCOPE:** the detector reasons about the **on-chain policy surface of the wallet's *code*** - what standing authority the code can grant, keep, or fail to guard. The **off-chain UX step** (the phishing site, the wallet's signing prompt, what the user "saw") is **out of scope**; it enters the model only as the calldata/signature the code ultimately acts on.
>
> **Overlap:** the malicious authorization is a [[signature-phishing]] signature; the delegate takeover is the EOA-level analogue of [[delegatecall-hijack]]. A single signature reaches the whole-account drain of both.

## What it is
EIP-7702 (live on Ethereum mainnet from the 2025 Pectra upgrade) lets an EOA set its
account code to **delegate** to a contract via a signed authorization. A victim tricked
into signing a malicious 7702 authorization gives an attacker contract the ability to act
*as the account* - a single signature can drain everything, no per-token approval needed.
It is the newest, highest-leverage wallet-drain primitive and a strong "we track the
current threat landscape" signal for a grant/portfolio reviewer.

## Design (shipped)
- **Attack:** victim signs a 7702 `SET_CODE` authorization pointing their EOA at an
  attacker-controlled delegate; the delegate sweeps all assets in one transaction.
- **Defensive signal:** a wallet must decode a 7702 authorization and flag delegation to an
  untrusted/unknown delegate; safe flows delegate only to known, audited delegates (or
  refuse). Protected target = delegation scoped/allow-listed, drain path unreachable.
- **Validation (same standard, [[real-cases]]):** (a) toy delegate drain vs safe delegate;
  (b) the CrimeEnjoyor sweeper pattern (Wintermute, live since Pectra 2025); (c) a
  canonical/safe delegate implementation (allow-listed/audited delegate only). Offline
  fixtures with provenance.

## Targets (for the benchmark)
- `a-toy`: `vulnerable-deleg` (EOA delegates to attacker sweeper -> one tx drains all) vs
  `safe-deleg` (delegation scoped/allow-listed, drain path unreachable).
- `b-incident`: `crimeenjoyor-victim` - minimized offline repro of the reusable 7702
  sweeper (victim signs a SET_CODE authorization to a sweeper delegate -> sweep). See
  [[real-cases]] §(b) eip7702-delegation. Honest proof level: class/incident-level (figures
  vary across public write-ups; reproduce the mechanism, not a byte-replay).
- `b-incident` (`split=holdout`): `sven-eth-victim` - the sven.eth 7702 drain (2026-10-14, ~9.12
  ETH / ~$22.7K): the victim EOA signed a SET_CODE authorization to an attacker delegate and an
  attacker-sponsor submitted the sponsored type-4 tx, which ran the delegate as the account and swept
  its ETH. Pinned on-chain (verified `type=0x4`, `authorizationList` -> delegate
  `0x0366b55f..60d1`, block 26,186,935, 2026-10-14 12:35:35 UTC; attacker-sponsor
  `0x9208097c..20bc`, victim `0xd8ba9e..4a28`, tx `0x36e0d149..820ee`), cross-checked against
  crypto.news / Cryptotimes / ExVul. Distinct from CrimeEnjoyor/Inferno (its own delegate + single
  victim). See its `PROVENANCE.md`.
- `b-incident` (`split=holdout`): `binance14-victim` - the Binance 14 hot-wallet drain (2026-10-29,
  the largest crypto theft on record; ~$2.5B first drain, multi-billion across chains): a compromised
  MPC signing service signed a type-4 SET_CODE authorization delegating Binance 14 to an
  attacker-deployed sweeper (hardcoded attacker caller), which the attacker then ran as the account
  to sweep its ETH + tokens. Pinned on-chain (verified type-4 tx `0xad99264d..051298b` with 50
  authorizations, nonces 18,914,775..18,914,824, delegate = sweeper `0x63e842B0..c6fAe`, block
  26,300,753, 2026-10-29 20:20:59 UTC; first drain `0x53bd38..e2f3` operator `0x7C8601d4..5CA0` ->
  Binance 14 `0x28C6..1d60` at 20:24:23 UTC), cross-checked against Binance / Blockaid / Wikipedia /
  Gizmodo / ChainCatcher. Distinct from CrimeEnjoyor/Inferno/sven (exchange hot wallet, 50-auth tx,
  compromised MPC signer). See its `PROVENANCE.md`.
- `b-incident` (`split=holdout`): `qnt-pool-7702-victim` - the QNT reserve-pool drain via a
  7702-delegated ADMIN EOA (2026-04-28, 1,974.546...548 QNT moved pool->attacker in the pinned tx,
  ~$124.9K; SlowMist reported ~1,988.5 QNT total). NOT an account sweeper: the pool's admin was an
  EOA that 7702-delegated its code to a BatchExecutor whose `batch(address[],bytes[])` (selector
  `0xf38f59d7`) is PUBLIC with no access control; any attacker drove the admin's delegated code to
  call the pool's `forwardTransaction`, and the pool's address-based admin trust (`msg.sender ==
  admin`) passed, draining a THIRD contract. Pinned on-chain (exploit tx `0xef9994ac..684f`, block
  24,978,818, 2026-04-28 13:19:59 UTC; QNT `Transfer` pool `0xdd4f556e..e16a` -> attacker
  `0xf5604f65..fa01` = 1,974.546...548 QNT verified in the receipt; BatchExecutor `0x044dc3e3..057c`
  `batch` selector `0xf38f59d7` confirmed via `eth_getCode`; admin EOA `0xc6ddf907..13f4` carries the
  `0xef0100` 7702 delegation indicator), cross-checked against SlowMist / DarkNavy / CryptoTimes /
  Coinfomania. Distinct code-level surface (missing access control + address-based trust), not a
  sweeper. See its `PROVENANCE.md`.
- `c-safe-impl`: `allowlisted-deleg-safe` - reference-impl of a wallet policy that honors a
  7702 delegation **only** to an allow-listed, audited delegate and refuses unknown ones.
- `c-safe-impl` (`split=holdout`): `solady-erc7821-safe` - the real Solady `ERC7821` batch
  executor (the EIP-7702 batch-execution interface) gated by real Solady `Ownable`; a non-owner
  batch reverts `Unauthorized()`. `oz-accesscontrol-exec-safe` - a real OZ `AccessControl`-gated
  arbitrary-call executor (a second, role-based real auth pattern); a non-role caller reverts.
  Both are real published code wal was never tuned against (precision holdouts, BLOCKED).
- `c-safe-impl` (`split=holdout`): `solady-initguard-safe` - a 7702-delegate account over real
  Solady `Ownable` that opts into its initialization-hijack guard (`_guardInitializeOwner`). Unlike
  the two above (which test **call-time** auth), this tests **init-time** auth: an attacker's
  re-`initialize` reverts `AlreadyInitialized` and a non-owner `execute` reverts `Unauthorized`, so
  the reinit-hijack cannot seize the delegate (BLOCKED) - a genuinely distinct sub-mechanism.
- `c-safe-impl` (`split=holdout`): `solady-ownableroles-exec-safe` - a 7702-delegate whose `execute`
  is gated by real Solady `OwnableRoles` (bitmask roles); a caller without owner/`EXECUTOR_ROLE`
  reverts `Unauthorized` (BLOCKED) - distinct role mechanism vs OZ `AccessControl`.
- `c-safe-impl` (`split=holdout`): `solady-handover-safe` - a 7702-delegate over real Solady
  `Ownable` two-step ownership handover; an attacker cannot unilaterally become owner
  (`completeOwnershipHandover`/`transferOwnership` are `onlyOwner`), so no one-step takeover (BLOCKED)
  - a distinct takeover-defense property.

> **Independent holdout (`split=holdout`):** `inferno-batch7702-victim` - an Inferno Drainer
> batched EIP-7702 sweep (Scam Sniffer, 2025-05), a multi-asset atomic drain distinct from
> CrimeEnjoyor, scored on the holdout split. See [[real-cases]] and `bench/README.md`.

## Dependencies
Needs a Foundry toolchain supporting EIP-7702 cheatcodes (`vm.signDelegation` /
`vm.attachDelegation`). forge-std v1.9.4 (our pinned version) ships them; if a fixture
cannot use them, fall back to modeling the delegate-call indirection explicitly and note it
in PROVENANCE. Related: [[signature-phishing]], [[approve-drainer]], [[delegatecall-hijack]].
