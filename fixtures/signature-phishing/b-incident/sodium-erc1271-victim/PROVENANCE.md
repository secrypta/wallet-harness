# Provenance - Lumi Finance / Sodium smart-account ERC-1271 bypass

**Fixture:** `../SodiumAccountClone.sol` (contract `SodiumAccountClone`)
**Vector:** signature-phishing - ERC-1271 forged / permissive signer (drain-scan rule **R15**, axis i)
**Verdict:** VULNERABLE (harness MUST flag)

## Incident facts

| Field | Value |
|---|---|
| Protocol | Lumi Finance - Sodium smart accounts (ERC-4337) |
| Date | 2026-07-13 |
| Chain | Arbitrum One |
| Reported loss | ~$270,000 USDT0 (Verichains); ~$264,000 per SlowMist / Olympix |
| Attacker EOA | `0xCe1a3BB0b98D0D90C7Dd0620Ab86C9A771888d88` |
| Malicious contract (ERC-1271 signer + session key + paymaster + spender + sweeper) | `0x56362412AE17cac443AAFBAb4289946Ad958E8a1` |
| Sodium implementation | `0xb5BC46dF04dEe31D219E7664122e29EEd9506b8b` |
| EntryPoint (v0.6) | `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` |
| **Pinned attacker drain tx** | `0x1cdba4c3f9c925e6d03ce8d07965a7521ee4e7258f6c5eeae8a7998886c2b9f0` - block **483390113** (`0x1ccff2a1`), 2026-07-13 15:29:12 UTC, status Success |
| Preceding approval tx | `0x630654fb1c8914405cf81bb02f091b049f19403a152f624f7b8a00c7724c6604` - block **483389834** (`0x1ccff18a`), 2026-07-13 15:28:02 UTC, status Success |

**Explorer verification (not RPC):** both transactions were read on Blockscout Arbitrum One
(`arbitrum.blockscout.com/tx/<hash>`). The drain tx is `From` the attacker EOA
`0xCe1a3BB0b98D0D90C7Dd0620Ab86C9A771888d88`, interacts with the malicious contract
`0x56362412AE17cac443AAFBAb4289946Ad958E8a1`, and sweeps USDT0 / LUA / LUAUSD / USDC into that
contract - matching the Verichains write-up. Block numbers are read from the tx (hex derived from
the decimal block number, not hardcoded). Loss figures differ between sources (~$264K SlowMist /
Olympix, ~$270K Verichains / GoPlus) and are reported as-is, not reconciled.

## Root cause (per Verichains)

The Sodium account's signature validation let the UserOp name the ERC-1271 signer contract. A
type-`0x01` signature was `0x01 || signerContract(20 bytes) || innerSig`; ECDSA recovery failed,
then OpenZeppelin `SignatureChecker` called the named contract's `isValidSignature`, which
returned the magic value `0x1626ba7e` for an arbitrary one-byte payload - validation passed with
no owner authorization. The session check compared `sessionKey` (from callData) against `signer`
(from the signature); both were attacker-controlled, and with no configured safe session the
account returned validation success. The same `validateUserOp` turned attacker-controlled
`paymasterAndData` into a persistent unlimited ERC-20 approval to the attacker's contract; because
validation returned success rather than failure, EntryPoint did not revert (AA24) and the approval
persisted, letting the attacker later `transferFrom` the funds.

## Why the harness must flag it (R15, axis i)

The address whose `isValidSignature` attestation authorizes the account is **decoded from the
caller-supplied `signature`** - not an immutable or owner-configured signer. An attacker names
their own permissive contract, so the "valid" answer is forgeable. R15 fires because the trusted
signer is caller-controlled. (The strict magic check is present and still does not help - the
distinction from R5/R6, which concern `ecrecover` of an EOA, not trust in a signer contract.)

## Minimization / boundary

Authored in-repo (MIT). Not a copy of the on-chain Sodium implementation (closed/unverified) or
of any third-party PoC. The ERC-4337 surface is reduced to the minimal `validateUserOp` that
carries the mechanism: attacker-named ERC-1271 signer + approval-from-paymasterAndData during
validation. No live contracts; offline compile only.

## Sources

- Verichains - "Lumi Finance Exploit: ERC-1271 Bypass and Unauthorized Token Approvals in Sodium
  Smart Accounts" (2026-07-16): https://blog.verichains.io/p/lumi-finance-exploit-erc-1271-bypass
- Loss cross-reference: SlowMist / Olympix / GoPlus incident reports (~$264K-$270K).

## License / attribution

Fixture `SodiumAccountClone.sol` is original work authored in this repository under **MIT** (see
its SPDX header). It is a minimized mechanism reproduction, not a copy of the on-chain Sodium
implementation or of any third-party PoC. Incident facts are attributed to the Verichains write-up
and the explorer records cited above.
