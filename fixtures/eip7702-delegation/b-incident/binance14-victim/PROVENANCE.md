# Fixture provenance

```
Fixture:      eip7702-delegation/b-incident/binance14-victim
Vector:       eip7702-delegation
Tier:         b-incident
Split:        holdout
Expected:     vuln
Proof level:  INCIDENT-LEVEL (confirmed public type-4 + drain tx + addresses, on-chain verified; minimized mechanism reproduction)

Origin:       Binance 14 EIP-7702 hot-wallet drain, 2026-10-29 - the largest crypto theft on record.
              The attacker gained control of Binance's MPC signing service and had it sign EIP-7702
              SET_CODE (type-4) authorizations for the Binance 14 hot wallet. One authorization
              delegated the EOA's code to an attacker-deployed sweeper contract (deployed hours
              earlier) that HARDCODED the attacker as the only allowed caller. The attacker then
              invoked the now-delegated account, and the sweeper ran in the account's context and
              moved its ETH and tokens to the attacker's aggregation address. Because the delegation
              lives on Ethereum (not in Binance's app layer), Binance's withdrawal suspension did not
              stop it; Binance cleared the delegation at 00:10 UTC on 2026-10-30 by authorizing the
              zero address. Loss figures vary across reports (Binance froze ~$2.85B; the first
              Binance 14 drain was ~$2.5B incl. 167,464 ETH + ~1.615B USDT; multi-billion total,
              ~$6.3B headline across ten chains).
```

## Confirmed on-chain identifiers (public, Ethereum mainnet)

- Victim EOA (Binance 14):  `0x28C6c06298d514Db089934071355E5743bf21d60`
- Sweeper / delegate:       `0x63e842B054Bd624a465454D533C33F573e9c6fAe` (hardcoded attacker caller)
- Hacker operator:          `0x7C8601d4645b93cea45F71e118A729332e6B5CA0`
- Aggregation address:      `0x5227f603C1eE34CE3C06eFe6477003BDfCCB2f8c`
- Type-4 (SET_CODE) tx:     `0xad99264d5532ae0dd04b2004eebda05f25657e70dacb764f7ac8d4ccd051298b`
                            (block 26,300,753, 2026-10-29 20:20:59 UTC)
- First Binance 14 drain:   `0x53bd38b816c23e74134786c29a8c18d792777998a3b9326047b583100e88e2f3`
                            (block 26,300,770, 2026-10-29 20:24:23 UTC)

## On-chain verification (read-only JSON-RPC, publicnode; offline fixture - no live-contract calls)

- `eth_getTransactionByHash(0xad99264d..051298b)` -> `type` = **`0x4`** (EIP-7702 SetCode tx), `from` =
  hacker operator `0x7C8601d4..5CA0`, **`authorizationList` has 50 entries**, and at least one entry's
  `address` = the sweeper `0x63e842B0..c6fAe`; the authorization `nonce` values run **18,914,775 ..
  18,914,824** (consecutive, as reported) - i.e. Binance 14's code was authorized to point at the
  attacker sweeper. Found in block 26,300,753, whose `timestamp` = **2026-10-29T20:20:59Z** (the
  reported authorization-submission time).
- `eth_getTransactionByHash(0x53bd38..e2f3)` -> `from` = operator `0x7C8601d4..5CA0`, `to` = Binance 14
  `0x28C6..1d60`, in block 26,300,770 whose `timestamp` = **2026-10-29T20:24:23Z** (the reported first
  drain time): the attacker invoking the now-delegated hot wallet.
- `eth_getCode(0x63e842B0..c6fAe)` -> 3,350 hex chars of deployed bytecode (the real sweeper contract).
  `eth_getCode` of Binance 14 now returns `0x` (the delegation was revoked to the zero address at
  00:10 UTC 2026-10-30, per Binance); the type-4 tx above is the pinned on-chain artifact of the
  malicious delegation.

## Sources (independent, cross-checked; facts converge and match on-chain)

- Binance - official incident report / X update ("29 October Binance Security Incident: Initial
  Findings and Response Update"): https://x.com/binance/status/2117626126214504729
- Blockaid - "$6.3B Binance Hack ... Detects the Biggest Theft in Crypto History":
  https://blockaid.io/blog/binance-55b-hack-using-advanced-ai-models-blockaid-detects-the-biggest-theft-in-crypto-history
- Wikipedia - "2026 Binance hack": https://en.wikipedia.org/wiki/2026_Binance_hack
- Gizmodo - "How Hackers Stole $6.3 Billion From Binance in Minutes" (consecutive nonces
  18,914,775-18,914,824): https://gizmodo.com/how-hackers-stole-6-3-billion-from-binance-in-minutes-2000833158
- ChainCatcher - EIP-7702 attack breakdown (full addresses: Binance 14 `0x28C6..1d60`, sweeper
  `0x63e842B0..c6fAe`, operator `0x7C8601d4..5CA0`, aggregation `0x5227f60..2f8c`; timeline):
  https://www.chaincatcher.com/en/article/2302691
- crypto.news - "Binance hack: how one wallet trick led to a $6.3 billion breach":
  https://crypto.news/binance-hack-eip-7702-wallet-attack/

Figures for the total loss vary across sources ($2.85B frozen / ~$6.3B headline across chains); the
MECHANISM (EIP-7702 type-4 delegation of Binance 14 to the attacker sweeper, then sweep) is
consistent across all of them and is confirmed on-chain above. The fixture reproduces the mechanism
and uses the first-drain figures (167,464 ETH + ~1.615B USDT); the proof level is incident-level.

## Why this is a legitimate addition (not a duplicate)

Distinct from the other `eip7702-delegation` b-incidents: `crimeenjoyor-victim` (reusable public
sweeper, 2025), `inferno-batch7702-victim` (Inferno batch-7702 module), and `sven-eth-victim` (a
single retail victim, Oct 14 2026). Binance 14 is a 2026-10-29 incident with its own
attacker-deployed, attacker-gated sweeper and a 50-authorization type-4 tx against an exchange hot
wallet via a compromised MPC signer - the largest instance of the vector.

## Fixture code

`../BinanceSweeperClone.sol` + `test/Binance14DelegationIncident.t.sol` are original MIT code authored
in this repo. They reproduce the documented mechanism only (a hardcoded-attacker-gated sweeper run as
the account via the 7702 "code runs as the account" semantics, modeled with delegatecall); no on-chain
sweeper bytecode and no third-party PoC code are copied. The test derives the verdict from the real
outcome (the account's ETH + tokens end up at the attacker).
