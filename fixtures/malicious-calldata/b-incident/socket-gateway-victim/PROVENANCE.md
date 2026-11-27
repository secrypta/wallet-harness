# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/socket-gateway-victim
Vector:       malicious-calldata
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       Socket Gateway "arbitrary external call injection", 2024-01-16, Ethereum
              mainnet, ~$3.3M drained from ~219-230 wallets (ETH, MATIC, WBTC, WETH, DAI).
              A route added ~3 days earlier took the call TARGET (fromToken) and the CALLDATA
              (swapExtraData) directly from the caller and executed an unvalidated low-level
              call fromToken.call(swapExtraData). The attacker set the target to a token the
              victims had approved to the gateway and the calldata to transferFrom(victim,
              attacker, amount); the call ran with msg.sender == the Socket Gateway, so the
              victims' standing approvals were spent. The only post-call check compared the
              gateway's native-ETH balance delta to `amount`, so passing amount = 0 satisfied
              it while an arbitrary token function had run.
Root cause:   Unvalidated caller-supplied call target + calldata executed by the contract
              (arbitrary external call injection), draining users' standing approvals - a
              mislabeled/hidden-effect calldata drain. The effect (transferFrom) is decoupled
              from any presented intent; the guard checked the wrong invariant.

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Attack tx:  0xc6c3331fa8c2d30e1ef208424c08c039a89e510df2fb6ae31e5aa40722e28fd6
              from  0x50df5a2217588772471b84adbbe4194a2ed39066  (attacker EOA)
              to    null  (contract creation - the attacker's exploit contract)
              block 19021454, timestamp 2024-01-16 19:11:23 UTC
  SocketGateway (the approval target users had approved): 0x3a23f943181408eac424116af7b7790c94cb97a5
  Vulnerable route: route id 406 (per Rekt / Veridise).
  The on-chain from-address matches the attacker EOA reported by Rekt.news, and the block
  date matches the independently-reported incident, cross-confirming the tx hash.

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. Rekt.news - "Socket" (attacker address + attack tx + gateway address + patch tx)
     https://rekt.news/socket-rekt
  2. Veridise - "Arbitrary External Call Injection: Socket's $3.3M Exploit" (mechanism)
     https://veridise.com/blog/audit-insights/arbitrary_external_call_injection_socket_exploit/
  3. CertiK - "Socket Tech Incident Analysis" (gateway address + victim count)
     https://certik.com/resources/blog/3QR5sltpG4lmpau6S6mWcm-socket-tech-incident-analysis
  4. Beosin - "Socket Protocol ... Call Injection Attack ~$3.3M" (auditor analysis)
     https://beosin.com/resources/socket-protocol-falls-victim-to-hackers-call-injection-attack-resulting-in-approximately-33-million%C2%A0theft
  5. Halborn - "Explained: The Socket Protocol Hack (January 2024)" (independent writeup)
     https://www.halborn.com/blog/post/explained-the-socket-protocol-hack-january-2024
  Amount agrees across sources: ~$3.3M; victim count reported 219-230. Representative figure
  used in the fixture; not asserted as exact.

Source code:  ./SocketGatewayClone.sol (authored minimized clone of the vulnerable route,
              this repo) + src/MockERC20.sol (the approved token).
License:      MIT (this repo). No third-party bytecode copied.
Minimization: Only the vulnerable route is modeled - unvalidated caller target+calldata plus
              the ETH-balance post-check that amount = 0 bypasses. The real multi-route
              SocketGateway dispatch and implementation registry are omitted.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/SocketIncident.t.sol: attacker injects transferFrom(victim -> attacker)
              with amount = 0; the gateway executes it as msg.sender and drains the victim's
              approval. Expected: VULNERABLE (TP).
```
