# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/seneca-performoperations-victim
Vector:       malicious-calldata
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       Seneca Protocol (decentralized lending / stablecoin) exploit, 2024-02-28,
              Ethereum, ~$6.4M drained from users who had approved the Chamber contract. The
              Chamber's `performOperations` entrypoint dispatched a CALL action to an internal
              `_call(callee, data)` that executed an arbitrary callee with arbitrary calldata
              and no validation. Because the Chamber held users' ERC-20 approvals, the attacker
              dispatched a CALL to a victim's token with transferFrom(victim, attacker, amount);
              it ran with msg.sender == the Chamber and drained the approval directly from the
              user's wallet (not from funds deposited into Seneca). ~80% was later returned.
Root cause:   Arbitrary external-call injection reached through a multi-action batch entrypoint
              (performOperations -> _call), draining standing approvals. Same approval-drain
              class as Socket / LI.FI / Transit / Rubic / Dexible, with a distinct reach path.

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Attack tx:  0x23fcf9d4517f7cc39815b09b0a80c023ab2c8196c826c93b4100f2e26b701286  (Ethereum)
              from  0x94641c01a4937f2c8ef930580cf396142a2942dc  (attacker EOA)
              to    0x65c210c59b43eb68112b7a4f75c8393c36491f06  (vulnerable Chamber)
              block 19325937, timestamp 2024-02-28 12:09:59 UTC
  The on-chain from/to match the attacker EOA and the vulnerable Chamber documented by
  Cyfrin / DeFiHackLabs, cross-confirming the tx hash (the attack tx called the Chamber directly).

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. Cyfrin - "Exploit Analysis & Proof of Concept: Seneca Attack" (performOperations -> _call
     arbitrary callee + calldata; Chamber held approvals; funds taken from user wallets)
     https://www.cyfrin.io/blog/seneca-attack-hack-analysis-proof-of-concept
  2. The Block - "Stablecoin protocol Seneca hit by $6 million exploit due to smart contract flaw"
     https://www.theblock.co/post/279761/stablecoin-protocol-seneca-hit-by-6-million-exploit-due-to-smart-contract-flaw
  3. Cointelegraph - "Decentralized lending platform Seneca exploited for $6.4M"
     https://cointelegraph.com/news/decentralized-lending-platform-seneca-exploited
  4. CertiK (via Chainspot coverage) - $6.4M estimate + performOperations arbitrary-call flaw
     https://news.chainspot.io/2024/02/29/seneca-protocol-exploited-6-4m-drained/
  5. BlockSec CTO - public description of the "arbitrary call" issue (approvals transferable out)
     (referenced in the Cyfrin analysis above)
  Loss ~$6-6.4M across sources; ~80% (~$5.3M) later returned. Representative, not asserted exact.

Source code:  ./SenecaChamberClone.sol (authored minimized clone of the vulnerable dispatch,
              this repo) + src/MockERC20.sol (the approved token).
License:      MIT (this repo). No third-party bytecode copied. DeFiHackLabs (Apache-2.0) used
              only as a reference for the attack tx / addresses; its PoC code was NOT vendored.
Minimization: Only the vulnerable surface is modeled - a performOperations batch that reaches
              an unvalidated arbitrary external call. The collateral/debt accounting is omitted.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/SenecaChamberIncident.t.sol: the attacker dispatches a CALL action to the
              token with transferFrom(victim -> attacker), draining the approval.
              Expected: VULNERABLE (TP).
```
