# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/rubic-router-whitelist-victim
Vector:       malicious-calldata
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       Rubic Exchange cross-chain DEX aggregator exploit, 2022-12-25, Ethereum,
              ~$1.4M drained from users who had approved the RubicProxy contract. The proxy's
              forward-call path (routerCallNative / routerCall) low-level-called a "router"
              with caller-supplied calldata, gated only by a router whitelist. The team had
              mistakenly added a TOKEN (USDC) to that whitelist. The attacker passed the token
              as the "router" and transferFrom(victim, attacker, amount) as the calldata; the
              proxy executed the call as msg.sender and pulled victims' standing approvals.
Root cause:   Arbitrary external-call injection gated by an insufficient allowlist - the
              whitelist did not prove the target was a benign router rather than an ERC-20, so
              a whitelisted token turned the forward-call into transferFrom-as-the-proxy. Same
              approval-drain class as Socket / LI.FI / Transit / Dexible.

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Attack tx:  0x9a97d85642f956ad7a6b852cf7bed6f9669e2c2815f3279855acf7f1328e7d46  (Ethereum)
              from  0x001b91c794dfeecf00124d3f9525dd32870b6ee9  (attacker EOA)
              to    0x253dd81d642220267ccac1d8202c0b96a92b299e  (attacker exploit contract)
              block 16260581, timestamp 2022-12-25 08:31:11 UTC
  The on-chain from/to match the attacker EOA (0x001b91c7...) and attack contract
  (0x253dd81d...) documented by QuillAudits / DeFiHackLabs, cross-confirming the tx hash.

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. PeckShield - incident alert (mistaken USDC whitelist; ~1,100 ETH moved to Tornado Cash)
     https://twitter.com/peckshield/status/1606937055761952770
  2. BlockSec - incident thread (routerCall arbitrary calldata, approval drain)
     https://twitter.com/BlockSecTeam/status/1606993118901198849
  3. QuillAudits - "Decoding Rubic Exchange Exploit" (routerCallNative lacked validity checks;
     USDC whitelisted; transferFrom crafted; attacker + attack-contract addresses)
     https://quillaudits.medium.com/decoding-rubic-exchange-exploit-quillaudits-44828e71c417
  4. SolidityScan - "Rubic Exchange Hack Analysis - Whitelisting does not always work"
     https://blog.solidityscan.com/rubic-exchange-hack-analysis-whitelisting-does-not-always-work-effectively-d3aeb0816af4/
  5. DcentraLab Diligence - "Rubic DEX Aggregator Hack" analysis
     https://www.dcentralab.com/blog/dcentralab-diligence-analysis-rubic-dex-aggregator-hack
  Loss ~$1.4M across sources; representative in the fixture, not asserted as exact.

Source code:  ./RubicProxyClone.sol (authored minimized clone of the vulnerable forward-call
              path, this repo) + src/MockERC20.sol (the approved token).
License:      MIT (this repo). No third-party bytecode copied. DeFiHackLabs (Apache-2.0) used
              only as a reference for the attack tx / addresses; its PoC code was NOT vendored.
Minimization: Only the vulnerable surface is modeled - a whitelist that fails to distinguish a
              token from a router, plus caller-supplied calldata executed by the proxy. The
              real multi-provider routing and native-token handling are omitted.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/RubicProxyIncident.t.sol: an admin mistakenly whitelists the token; the
              attacker routes transferFrom(victim -> attacker) through it and drains the
              victim's approval. Expected: VULNERABLE (TP).
```
