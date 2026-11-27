# Fixture provenance

```
Fixture:      eip7702-delegation/b-incident/qnt-pool-7702-victim
Vector:       eip7702-delegation
Tier:         b-incident
Split:        holdout
Expected:     vuln
Proof level:  INCIDENT-LEVEL (confirmed public exploit tx + addresses, on-chain verified incl.
              QNT Transfer amount and BatchExecutor selector; minimized mechanism reproduction)

Origin:       QNT reserve-pool drain via an EIP-7702-delegated ADMIN EOA, 2026-04-28, Ethereum
              mainnet. The pool's registered admin was an externally owned account (EOA). That EOA
              signed an EIP-7702 SET_CODE authorization delegating its code to a "BatchExecutor"
              contract whose batch(address[],bytes[]) entrypoint (selector 0xf38f59d7) is PUBLIC with
              NO access control and loops arbitrary low-level calls. Because EIP-7702 makes the admin
              EOA callable by anyone, an attacker called batch() on the admin EOA and drove it to call
              the reserve pool's privileged forwardTransaction(); the pool trusts its admin BY ADDRESS
              (msg.sender == admin), so the check passed and the reserves were forwarded out. The
              drained asset is the POOL's reserves (not the EOA's own balance) - a code-level
              access-control bug on the delegated executor, distinct from a plain account sweeper.
```

## Confirmed on-chain identifiers (public, Ethereum mainnet)

- Admin EOA (7702-delegated):   `0xc6ddf90790b433743bd050c1d1d45f673a3413f4`
- Unpermissioned BatchExecutor: `0x044dc3e39c566a95011e272ec800dbd2cc9c057c` (batch selector `0xf38f59d7`)
- QNT reserve pool (drained):   `0xdd4f556e1b42d9b29294a7eeb6d6a5059bbbe16a`
- QNT token:                    `0x4a220e6096b25eadb88358cb44068a3248254675`
- Attacker EOA:                 `0xf5604f6545d5827a01801ffa5c48f5c61258fa01`
- Attacker contract (created):  `0xee039cb73872827a5118cdd67e0b24e45651e49f`
- Pinned exploit tx:            `0xef9994ac862318ccf3ebdb66c181bb159651373b945aea59a966608d7b98684f`
- Block:                        24,978,818
- Timestamp:                    2026-04-28 13:19:59 UTC

## On-chain verification (read-only JSON-RPC, publicnode; offline fixture - no live-contract calls)

Done by this session against `https://ethereum-rpc.publicnode.com` (single requests):

- `eth_getTransactionByHash(0xef9994ac..684f)` -> `status`-bearing tx mined in block `0x17d2582`
  (24,978,818), `from` = attacker `0xf5604f65..fa01`, `to` = `null` (a contract-creation tx: the
  attacker deployed its attack contract and executed the drain inside the creation, which is why the
  write-up's "exploit tx" is a contract-creation). `type` = `0x2` - the type-4 SET_CODE authorization
  that delegated the admin EOA's code was a SEPARATE, earlier tx; this pinned tx is the DRAIN.
- `eth_getTransactionReceipt(0xef9994ac..684f)` -> `status` = `0x1` (success); `contractAddress` =
  `0xee039cb7..e49f` (the attack contract, matching the write-up). Logs contain a QNT ERC-20
  `Transfer` (token `0x4a220e60..4675`) **from pool `0xdd4f556e..e16a` to attacker `0xf5604f65..fa01`
  of 1,974.546547972979064297 QNT** - this exact amount is reproduced as the fixture's reserves.
- `eth_getBlockByNumber(0x17d2582)` -> `timestamp` = **2026-04-28 13:19:59 UTC** (ground-truth date;
  one aggregator republish is dated 27 Jul 2026 - that is the republish/aggregation date, not the
  on-chain incident date).
- `eth_getCode(0x044dc3e3..057c)` (BatchExecutor) -> deployed bytecode whose function dispatcher's
  first selector is `0xf38f59d7` = `batch(address[],bytes[])` - confirms the unpermissioned batch
  entrypoint on-chain independently of any decompilation.
- `eth_getCode(0xc6ddf907..13f4)` (admin EOA) -> begins with the EIP-7702 delegation indicator
  `0xef0100...` - confirms the account is a live 7702-delegated EOA. (Current delegate differs from
  the incident-time delegate implementation reported in the post-mortem, consistent with a later
  re-delegation; historical `eth_getCode` at the incident block is not available on this non-archive
  endpoint, so the delegate-at-incident address is taken from the post-mortem and not independently
  re-derived here.)

## Sources (independent, cross-checked; facts converge and match on-chain)

- SlowMist (security auditor), alert via @SlowMist_Team: EIP-7702 account vulnerability exploited,
  ~1,988.5 QNT (~54.93 ETH) stolen; admin-identity EOA + unpermissioned batch contract draining the
  QNT reserve pool. (Primary originating alert; reprinted widely, e.g. Bitget/ChainCatcher, WEEX.)
- DarkNavy - "QNT Pool Drain via EIP-7702 Admin EOA Delegation" (post-mortem): full root-cause with
  addresses, pinned exploit tx, and the `batch()`-public / `_isAdmin(msg.sender)` interaction.
  https://www.darknavy.org/web3/exploits/qnt-pool-drain-via-eip-7702-admin-eoa-delegation/
- CryptoTimes - "EIP-7702 Flaw Drains 1,988 QNT From Ethereum Pool" (2026-04-29):
  https://www.cryptotimes.io/2026/04/29/eip-7702-flaw-drains-1988-qnt-from-ethereum-pool/
- Coinfomania / CryptoNews (media, SlowMist-sourced): 1,988.5 QNT ≈ 54.93 ETH; admin-identity EOA +
  permissionless BatchCall/BatchExecutor; QNT reserve pool drained.
  https://cryptonews.net/news/security/33206817/
- Also covered by Phemex news. (Multiple independent outlets, not a single site/channel.)

### Honest discrepancies (noted, not papered over)
- Amount: SlowMist/media report ~1,988.5 QNT total; the single pinned drain tx moves 1,974.546...548 QNT
  on-chain (the ~14 QNT difference is likely a separate smaller movement or a rounded headline total).
  The fixture uses the on-chain-verified pinned-tx amount.
- Date: on-chain block timestamp (2026-04-28) is authoritative; one aggregator shows 27 Jul 2026
  (republish date).

## Why this is a legitimate addition (not a duplicate)

Distinct from every other `eip7702-delegation` b-incident in this corpus - `crimeenjoyor-victim`,
`inferno-batch7702-victim`, `sven-eth-victim`, `binance14-victim` - all of which are account SWEEPERS
(a malicious delegate moves the delegating account's OWN ETH/tokens out). Here the 7702-delegated
account is a PRIVILEGED ADMIN EOA, the delegate's code-level bug is a PUBLIC `batch()` with no access
control, and the drained target is a THIRD contract (the reserve pool) that trusts the admin by
address. Same vector root condition (malicious/abused 7702 delegation runs as the account) exercised
through a genuinely different code-level surface (missing access control + address-based trust).

## Fixture code

`../QntPool7702Clone.sol` + `test/QntPool7702Incident.t.sol` are original MIT code authored in this
repo. They reproduce the documented mechanism only (the "code runs as the account" 7702 semantics
modeled via delegatecall; an unpermissioned batch executor driving a privileged pool that trusts its
admin by address); no on-chain bytecode, decompilation, or third-party PoC code is copied. The test
derives the verdict from the real outcome (the pool's reserves end up at the attacker).
