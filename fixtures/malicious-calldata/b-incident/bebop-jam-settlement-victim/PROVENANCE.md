# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/bebop-jam-settlement-victim
Vector:       malicious-calldata (arbitrary caller-supplied interactions spend a standing approval; signer-auth not bound to fund moves)
Tier:         b-incident
Split:        holdout
Expected:     vuln
Proof level:  INCIDENT-LEVEL (public tx + addresses, on-chain verified this session via read-only
              RPC: status/from/created-contract/2 USDC transfers/JamSettlement-in-logs/block-ts all
              confirmed; >=2 independent write-ups; minimized mechanism reproduction)

Origin:       Bebop JamSettlement drain, Arbitrum, 2025-08-12 (~$21K). Bebop's JamSettlement
              `settle(order, signature, interactions, ...)` executed caller-supplied `interactions`
              (arbitrary external calls) from the settlement's own context. The settlement is the
              approved spender for integrating users, so interactions of the form
              `transferFrom(victim, attacker, amount)` spend those users' standing allowances. The
              attacker submitted a SELF-TAKEN order (taker = attacker) with an EMPTY signature and
              two such interactions, draining two approvers. The signature/authorization check never
              bound the signer to the tokens the interactions moved, so no victim ever authorized
              the transfers.

Confirmed on-chain identifiers (public, Arbiscan):
              - Attack tx:          0xe5f8fe69b38613a855dbcb499a2c4ecffe318c620a4c4117bd0e298213b7619d
              - Attacker (EOA):     0x59537353248d0b12c7fcca56a4e420ffec4abc91
              - Attacker contract:  0x091101b0f31833c03dddd5b6411e62a212d05875
              - Vulnerable JamSettlement: 0xbeb0b0623f66be8ce162ebdfa2ec543a522f4ea6
              - Drained approver 1: 0x0c06e0737e81666023ba2a4a10693e93277cbbf1 (on-chain net ~20,068.56 USDC; the DeFiHackLabs PoC calldata cites 20,134.500015)
              - Drained approver 2: 0xe7ee27d53578704825cddd578cd1f15ea93eb6fd (1,000,000 USDC units)
              - Token (USDC, Arbitrum): 0xaf88d065e77c8cc2239327c5edb3a432268e5831
              Chain: Arbitrum. Order expiry in the real calldata = 1754987701 (2025-08-12).

On-chain verification (read-only JSON-RPC arb1.arbitrum.io, this session; offline fixture - no
live-contract calls):
              - eth_getTransactionByHash(0xe5f8fe69..619d) -> block 0x15e8eafd (367,586,045),
                `from` = attacker EOA 0x59537353..bc91, `to` = null (contract creation).
              - eth_getTransactionReceipt -> status 0x1 (success); in-tx created contract
                0x267acd62e4bc7c2edbb73f9698050e99833c64f6 (the write-up's 0x091101b0.. is a
                separately-cited attacker helper, not the contract created in THIS tx). Logs: the
                Arbitrum USDC token 0xaf88d065..5831 emits TWO Transfer events (the two drained
                approvers) and the vulnerable JamSettlement 0xbeb0b062..4ea6 appears in the logs -
                confirming the settlement moved two approvers' USDC in one attack tx.
              - eth_getBlockByNumber(0x15e8eafd) -> timestamp 2025-08-12 08:35:00 UTC (matches the
                reported 2025-08-12 incident date and the order expiry above).

Reference (authoritative write-ups - >=2 independent, consistent with the on-chain record above):
              - SuplabsYi post-mortem: https://x.com/SuplabsYi/status/1955230173365961128
              - crypto.training/hacks (reproduced on-chain exploits) - "Bebop JAM Settlement
                Exploit": signature bypass + unconstrained interactions, ~20,069 USDC drained from
                two pre-approving users, campaign total ~$21K (matches the two-approver drain and
                the ~20,068.56 USDC net above). https://crypto.training/hacks/

Mechanism reference (for locating the incident + confirming the identifiers above):
              - SunWeb3Sec/DeFiHackLabs, commit 8f077a91403c81af315c8903519a3bd9723a1903,
                src/test/2025-08/Bebop_dex_exp.sol, Apache-2.0. The DeFiHackLabs PoC is a
                mainnet-fork replay; it is NOT vendored here. See repo NOTICE for attribution.

Source code:  ./../JamSettlementClone.sol (authored minimized reproduction, THIS repo, MIT). Not a
              copy of the on-chain JamSettlement contract nor of the DeFiHackLabs PoC; it reproduces
              only the documented root cause offline: a settlement that runs arbitrary interactions
              under a signature gate that does not bind the signer to the moved funds, so an
              empty-signature self-taken order drains third parties' standing approvals.

Why vuln:    The settlement acts on an unauthenticated order and executes attacker-chosen
             `transferFrom` interactions against victims who approved it. The minimized test drives
             the real outcome (both approvers' balances move to the attacker) and the harness reads
             VULNERABLE from that outcome.

Vector note: Labeled malicious-calldata (R11 class), not signature-phishing. No victim signed
             anything: the attacker submitted a SELF-TAKEN order with an EMPTY signature and the
             drain is done by the caller-supplied interactions spending standing approvals - the
             same arbitrary-callee class as squid-multicall / drainer-kit. (M web-verified the
             incident and corrected the label from the initial signature-phishing proposal.)
```
