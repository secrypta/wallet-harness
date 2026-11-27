# Fixture provenance

```
Fixture:      blind-eth-sign/b-incident/bybit-blind-sign-victim
Vector:       blind-eth-sign
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)
Proof level:  INCIDENT-LEVEL (confirmed on-chain tx + contracts; minimized signing-defect
              reproduction). This upgrades the vector's b-tier from class-level
              (ethsign-blind-victim) to an incident-level anchor.

Origin:       Bybit / Safe theft (2025-02-21, ~$1.5B, the largest crypto theft on record).
              Bybit's cold-wallet multisig owners used the Safe{Wallet} web interface, whose
              front-end JavaScript had been tampered with: the UI displayed a normal transfer
              while the transaction actually submitted was malicious. The owners signed on
              hardware wallets that could not decode the Safe payload, so they BLIND-SIGNED an
              opaque transaction digest. That authorization executed a Safe `execTransaction`
              whose operation delegatecalled a malicious contract; the malicious code
              overwrote the Safe singleton (masterCopy, storage slot 0) with a malicious
              implementation exposing sweepETH()/sweepERC20(), which drained ~400,000 ETH/stETH.
              This is the blind-eth-sign vector: the defect modeled here is approving an
              opaque, undecoded signing payload. (The delegatecall/upgrade mechanics the
              operation used are covered by other detector rules; see honest scope below.)

Confirmed on-chain identifiers (Ethereum mainnet, verified via read-only RPC
eth_getTransactionByHash / eth_getCode / eth_getBlockByNumber):
              - Malicious execTransaction tx: 0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882
              - Block:                 21895238, timestamp 2025-02-21 14:13:35 UTC
              - to (Bybit Safe cold wallet / victim): 0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4
              - selector:              0x6a761202 = Safe execTransaction(...)
              - from (executor):       0x0fa09c3a328792253f8dee7116848723b72a6d2e
              - Malicious implementation (masterCopy set to): 0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516
                (1051 bytes of code on-chain; exposes the sweep functions per CertiK)
                Deployed 2025-02-19 07:15:23 UTC per SlowMist.
              (The Safe cold wallet 0x1db9...dfcf4 and the malicious impl 0xbDd0...9516 both
              return on-chain bytecode; the execTransaction tx above was read from mainnet and
              its `to`+selector confirm the Safe execTransaction path the owners blind-signed.)

Reference (independent, authoritative - cross-checked, >= 2-3 sources + on-chain):
              - SlowMist, "Bybit's $1.5 Billion Theft Unveiled: Safe{Wallet} Front-End Code
                Tampered" (malicious impl 0xbDd077...9516, delegatecall slot-0 masterCopy swap,
                sweepETH/sweepERC20).
              - CertiK, "Bybit Incident Technical Analysis" (masterCopy set to 0xbDd077...9516
                containing sweepETH()/sweepERC20(); ~$1.5B).
              - BlockSec, "Bybit Incident: A Web2 Breach Enables the Largest Crypto Hack in
                History" (tx 0x46deef...7882 replaced the masterCopy).
              - SunWeb3Sec/DeFiHackLabs, src/test/2025-02/Bybit_exp.sol (same tx + addresses;
                Apache-2.0 PoC, NOT vendored here - reference only).
              - On-chain confirmation (this repo): tx/addresses/selector/date read directly
                from Ethereum mainnet and consistent across the sources above.

Source code:  ../BlindMultisigWallet.sol (authored minimized model, this repo, MIT). It is NOT
              a copy of the Safe contracts nor of the malicious implementation; it models only
              the N-of-M signature verification over an opaque transaction digest + execution,
              the signing surface this vector is about.
License:      MIT (this repo). No third-party wallet code copied.

Minimization / honest scope:
              - Blind-signing: the owners sign getTransactionHash(to,value,data,nonce), an
                opaque 32-byte digest. On the real hardware wallets the Safe payload could not
                be decoded, which is the blind-signing condition; we model that by signing the
                raw digest without decoding (to,value,data). A clear-signing wallet would
                decode and display the operation and the owners would refuse.
              - We reproduce the AUTHORIZATION->DRAIN essence: the authorized operation here is
                a direct transfer of the wallet's balance to the attacker. The real operation
                used a delegatecall that swapped the masterCopy (slot 0) and then swept; those
                upgrade/delegatecall mechanics are a different detector surface and are NOT
                re-implemented here, to keep this fixture squarely about the blind-signing
                defect. Stated plainly so a reviewer is not misled about what is modeled.
              - Owner keys are key-derived stand-ins (vm keys): the real Bybit signer keys are
                (rightly) not public. The incident tx/contracts are cited and on-chain-verified.
Offline:      committed minimized model; no mainnet fork, no live RPC in the test. The on-chain
              verification above was a read-only lookup, not a live-contract test. Built/run in
              Docker.
Notes:        test/BybitBlindSignIncident.t.sol: three owners blind-sign the opaque digest, the
              attacker submits execTransaction, and the wallet's balance leaves to the attacker;
              the verdict is derived from that outcome. Expected verdict: VULNERABLE (TP).
```
