# Fixture provenance

```
Fixture:      eip7702-delegation/b-incident/sven-eth-victim
Vector:       eip7702-delegation
Tier:         b-incident
Split:        holdout
Expected:     vuln
Proof level:  INCIDENT-LEVEL (confirmed public type-4 tx + addresses, on-chain verified; minimized mechanism reproduction)

Origin:       sven.eth EIP-7702 delegation drain, 2026-10-14 (~9.1231 ETH + 1.69271471 TAPEETH,
              ~$22.7K, Ethereum mainnet). The victim's EOA signed an EIP-7702 SET_CODE (type-4)
              authorization delegating the account's code to an attacker-controlled delegate contract.
              An attacker-controlled sponsor submitted the sponsored type-4 transaction carrying that
              authorization, so the delegate's logic ran IN THE ACCOUNT'S OWN CONTEXT and swept the
              account's ETH (and tokens) to the attacker in one shot - a single delegation handed over
              the whole account, with no per-asset approval. (EIP-7702 is live on mainnet since the
              2025 Pectra upgrade.)
```

## Confirmed on-chain identifiers (public, Ethereum mainnet)

- Victim EOA:            `0xd8ba9e5886b7000bace2c9dbdd0be98ac77d4a28` (sven.eth)
- Malicious delegate:    `0x0366b55f948a688888ca6e029ad0831f6ec260d1`
- Attacker sponsor:      `0x9208097c007be15e28b20e94e66870a3f9f820bc` (type-4 tx `from`)
- Type-4 (SET_CODE) tx:  `0x36e0d1491c14e3d8e50bc70d73675b89d2d4712814d16f808f957c84fde820ee`
- Block:                 26,186,935
- Timestamp:             2026-10-13 23:43:59 UTC  (block 0x18f94b7; write-ups report "Oct 14, 2026")

## On-chain verification (read-only JSON-RPC, publicnode; offline fixture - no live-contract calls)

- `eth_getTransactionByHash(0x36e0d149..820ee)` -> `type` = **`0x4`** (EIP-7702 SetCode tx), `from` =
  attacker sponsor `0x9208097c..20bc`, `to` = delegate `0x0366b55f..60d1`, `blockNumber` = `0x18f94b7`
  (26,186,935). Its `authorizationList` has 1 entry: `address` = the delegate `0x0366b55f..60d1`,
  `chainId` = `0x1`, `nonce` = `0x1d12` - i.e. an EOA's code was authorized to point at the malicious
  delegate.
- `eth_getBlockByNumber(0x18f94b7)` -> `timestamp` = **2026-10-13T23:43:59Z** (16 min before 00:00 UTC
  Oct 14; the write-ups report the incident as "Oct 14, 2026" - timezone/rounding).
- `eth_getTransactionReceipt` -> `status` = `0x1` (success).
- `eth_getCode(0x0366b55f..60d1)` -> 17,254 hex chars of deployed bytecode (a real contract, the
  malicious delegate). `eth_getCode` of the victim EOA now returns `0x` (the delegation was cleared
  after the drain, as is typical); the type-4 tx above is the pinned on-chain artifact of the
  malicious delegation.

## Sources (independent, cross-checked; facts converge and match on-chain)

- crypto.news - "Ethereum user loses $22K in EIP-7702 wallet attack":
  https://crypto.news/ethereum-user-loses-22k-in-eip-7702-wallet-attack/
  (victim `0xd8ba9e..4a28`, delegate `0x0366b55f..60d1`, attacker-controlled `0x9208097c..20bc`;
  ExVul identified the sponsored type-4 tx above)
- Cryptotimes - "Ethereum Wallet Loses $22.7K in EIP-7702 Delegation Attack" (2026-10-14):
  https://www.cryptotimes.io/2026/10/14/ethereum-wallet-loses-22-7k-in-eip-7702-delegation-attack/
- ExVul (security research) - identified and attributed the type-4 transaction hash (cited by the
  above outlets).

## Why this is a legitimate addition (not a duplicate)

Distinct from the other `eip7702-delegation` b-incidents: `crimeenjoyor-victim` (the reusable public
"CrimeEnjoyor" sweeper serving many victims, Wintermute, 2025) and `inferno-batch7702-victim` (an
Inferno Drainer batch-7702 module). sven.eth is a specific single-victim drain with its own
attacker-deployed delegate `0x0366b55f..60d1` and a pinned type-4 transaction. All share the vector's
root condition - a malicious EIP-7702 delegation runs as the account and sweeps it - through
distinct delegates/campaigns.

## Fixture code

`../SvenDelegateClone.sol` + `test/SvenDelegationIncident.t.sol` are original MIT code authored in
this repo. They reproduce the documented mechanism only (the "code runs as the account" 7702
semantics modeled via delegatecall, sweeping the account's ETH); no on-chain delegate bytecode and no
third-party PoC code are copied. The test derives the verdict from the real outcome (the account's
ETH ends up at the attacker).
