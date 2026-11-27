# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/lifi-gaszip-victim
Vector:       malicious-calldata
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       LI.FI / Jumper exploit, 2024-07-16, Ethereum mainnet (+Arbitrum), ~$9.73M drained
              from 153 wallets (USDT/USDC/DAI, swapped to ~2,857 ETH). A GasZipFacet added to
              the LI.FI diamond ~5 days earlier exposed a swap path (depositToGasZipERC20) that
              performed an external call with a caller-supplied call TARGET and CALLDATA without
              validating them. The attacker set the target to a token and the calldata to
              transferFrom(victim, attacker, amount); the call ran with msg.sender == the LI.FI
              diamond, so users who had granted the diamond an INFINITE approval were drained
              (finite approvals - the LI.FI API/SDK default - were unaffected).
Root cause:   Unvalidated caller-supplied call target + calldata executed by the contract
              (arbitrary external call injection), draining standing infinite approvals. Same
              class as the Socket incident and as LI.FI's own 2022 bug (PeckShield: "basically
              the same").

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Attack tx:  0xd82fe84e63b1aa52e1ce540582ee0895ba4a71ec5e7a632a3faa1aff3e763873
              from  0x8b3cb6bf982798fba233bca56749e22eec42dcf3  (attacker EOA)
              to    0x986aca5f2ca6b120f4361c519d7a49c5ac50c240  (attacker exploit contract,
                    which internally called the LI.FI diamond)
              block 20318963, timestamp 2024-07-16 12:06:35 UTC
  LI.FI diamond (victim):  0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae
  GasZipFacet (added 5 days earlier): 0xf28a352377663ca134bd27b582b1a9a4dad7e534
  The on-chain from-address matches the attacker EOA reported by Rekt/BlockSec/QuillAudits,
  and the block date matches the independently-reported incident, cross-confirming the tx hash.

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. Rekt.news - "LiFi/Jumper" (attacker address, facet-add tx, affected diamonds, amount)
     https://rekt.news/lifi-jumper-rekt
  2. QuillAudits - "Same Mistake Twice? Decoding LiFi Protocol's $9.7M Exploit" (attack tx +
     GasZipFacet address + depositToGasZipERC20)
     https://www.quillaudits.com/blog/hack-analysis/lifi-protocol-exploit
  3. BlockSec / MetaSleuth - illicit fund-flow case study (attacker destination 0x8b3c...)
     https://blocksec.com/blog/illicit-fund-flow-case-study-lifi-attack-metasleuth
  4. SolidityScan - "Li.Fi Hack Analysis"
     https://blog.solidityscan.com/li-fi-hack-analysis-521388128d22/
  5. LI.FI Security Incident Report (official post-mortem, via Cryptonews coverage)
     https://cryptonews.com/news/lifi-protocol-releases-post-mortem-report-on-recent-11-6-million-hack/
  Amount: ~$9.73M (Rekt/QuillAudits on-chain) to ~$11.6M (LI.FI post-mortem, Ethereum+Arbitrum).
  Representative figure in the fixture; not asserted as exact.

Source code:  ./LiFiGasZipClone.sol (authored minimized clone of the vulnerable swap route, this
              repo) + src/MockERC20.sol (the approved token).
License:      MIT (this repo). No third-party bytecode copied.
Minimization: Only the vulnerable surface is modeled - a swap descriptor whose caller-supplied
              callTo+callData are executed unvalidated. The full diamond/facet routing and
              DEX-aggregator plumbing are omitted.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/LiFiIncident.t.sol: attacker injects transferFrom(victim -> attacker) via the
              swap route against an infinite approval; the diamond executes it as msg.sender and
              drains the victim. Expected: VULNERABLE (TP).
```
