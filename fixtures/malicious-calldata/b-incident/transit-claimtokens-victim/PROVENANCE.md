# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/transit-claimtokens-victim
Vector:       malicious-calldata
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       Transit Swap (TransitFinance) cross-chain DEX aggregator exploit, 2022-10-01,
              BNB Chain (also Ethereum), >$21M drained from users who had granted the router
              ERC-20 approvals. The router pulled tokens through a transfer helper whose
              claimTokens(token, from, to, amount) executed transferFrom(from, to, amount)
              with the `from` (token OWNER) taken directly from the caller and never checked
              against msg.sender. The attacker named innocent users who had previously
              approved the router as `from`, and set `to` to the attacker, so the router
              moved those users' balances out. ~70% of funds were later returned.
Root cause:   Unvalidated caller-supplied owner parameter on a privileged transferFrom
              (arbitrary-party token pull). Same approval-drain class as the Socket, LI.FI,
              Rubic and Dexible incidents: a contract that users had approved moves a third
              party's tokens on purely caller-controlled input.

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Attack tx:  0x181a7882aac0eab1036eedba25bc95a16e10f61b5df2e99d240a16c334b9b189  (BNB Chain)
              from  0x5f0b31aa37bce387a8b21554a8360c6b8698fbef  (attacker EOA)
              to    0x8ca8fd9c7641849a14cbf72faf05c305b0c68a34  (attacker exploit contract)
              block 21816546, timestamp 2022-10-01 18:35:54 UTC
  TransitSwap router (victim entry): 0x8785bb8deae13783b24d7afe250d42ea7d7e9d72
  Transfer helper (ran transferFrom): 0xed1afc8c4604958c2f38a3408fa63b32e737c428
  The on-chain from/to/block match the attacker EOA and exploit contract documented by
  SlowMist / Numen / DeFiHackLabs, cross-confirming the tx hash.
  (Note: some early social posts cited 0x75f2aba6...bffd46 - that is a later fund-
  destination address, not the sender of the attack tx; the sender above is the attacker EOA.)

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. SlowMist - "Cross-chain DEX Aggregator Transit Swap Hacked Analysis" (root cause:
     controllable transferFrom via unvalidated input; attacker + helper addresses)
     https://slowmist.medium.com/cross-chain-dex-aggregator-transit-swap-hacked-analysis-74ba39c22020
  2. Numen Cyber - "Transit Swap Hack Analysis" (claimTokens helper 0xed1afc8c..., flow)
     https://www.numencyber.com/transit-swap-hack-analysis/
  3. QuillAudits - "Transit Finance $28.9M Exploit Analysis" (claimTokens, approvals abused)
     https://quillaudits.medium.com/transit-finance-28-9m-exploit-analysis-quillaudits-5d8228956102
  4. SharkTeam - "Approval and verification vulnerability analysis of TransitSwap"
     https://medium.com/@sharkteam/approval-and-verification-vulnerability-analysis-of-transitswap-security-incident-89cfe999a1ef
  5. Halborn - "Explained: The Transit Swap Hack (October 2022)"
     https://www.halborn.com/blog/post/explained-the-transit-swap-hack-october-2022
  Loss figures range ~$21M (on-chain, Rekt/SlowMist) to ~$28.9M (QuillAudits). Representative
  in the fixture, not asserted as exact. ~70% later returned by the attacker.

Source code:  ./TransitSwapClone.sol (authored minimized clone of the vulnerable transfer
              helper, this repo) + src/MockERC20.sol (the approved token).
License:      MIT (this repo). No third-party bytecode copied. DeFiHackLabs (Apache-2.0) used
              only as a reference for the attack tx / addresses; its PoC code was NOT vendored.
Minimization: Only the vulnerable surface is modeled - a transferFrom whose `from` (owner) is
              caller-supplied and unvalidated. The DEX/bridge routing and multi-chain plumbing
              are omitted.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/TransitSwapIncident.t.sol: the attacker calls claimTokens naming the victim
              as `from`; the router pulls the victim's infinite approval. Expected: VULNERABLE.
```
