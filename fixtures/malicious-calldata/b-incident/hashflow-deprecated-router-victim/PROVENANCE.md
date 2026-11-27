# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/hashflow-deprecated-router-victim
Vector:       malicious-calldata
Tier:         b-incident (minimized real public incident)
Split:        holdout                   # authored after v0.1 freeze; wal never tuned to it
Expected:     vuln                      # ground-truth label (matches meta `label`)

Incident:     Hashflow exploit, 2023-06-14, Ethereum (+4 other EVM chains), ~$600K-$640K.
Root cause:   A DEPRECATED Hashflow contract retained a publicly callable function that still
              invoked ERC-20 `transferFrom` against tokens users had left approved to it. Its
              post-deprecation access control was inadequate (the function was absent from the
              audited codebase, "Lack of Access Control" per CertiK), so ANY caller could
              redirect a victim's standing approval to an attacker-chosen recipient. First used
              by a white-hat for a "recovery", then reused by black-hats against wallets that
              had not revoked. Analyses cite the unverified function selector `0x1ce5...`.
Mechanism:    Caller-reachable `transferFrom` against standing approvals = the arbitrary-caller
              approval-drain shape of the malicious-calldata vector (cf. Socket 2024).
```

## On-chain artifacts (verified via read-only RPC, 2026-11-19)
- **Attack transaction:** `0xdedda493272b6b35660b9cc9070d2ea32ee61279b821184ff837e0a5752f4042`
  - `from` = `0xbdf38b7475ff810325aa39e988fb80e0aa007e84` (attacker EOA)
  - `to`   = `0xddb19a1bd22c53dac894ee4e2fbfdb0a06769216` (attacker exploit contract)
  - `block` = 17478994 (2023-06-14)
  - Verified: `eth_getTransactionByHash` via public RPC; `from`/`to`/`block` match the SharkTeam
    write-up and the Etherscan-labelled exploit contract.
- **Deprecated Hashflow contract (approval target):** `0x79cdFd7Bc46D577b95ed92bcdc8abAba1844Af0c`
  (per SharkTeam / Etherscan). The verified artifact above is the attack transaction itself.

## Independent sources (>=3 authorities; facts cross-checked)
- CertiK - "Post Mortem: Hashflow": https://www.certik.com/blog/post-mortem-hashflow
  (Lack of Access Control; ~$605K across 5 chains; vulnerable function out of audit scope.)
- SharkTeam - "Analysis of the HashFlow Attack Incident":
  https://medium.com/@sharkteam/sharkteam-analysis-of-the-hashflow-attack-incident-8d062b30074f
  (attacker `0xBDf3...7E84`, exploit contract `0xDDb1...9216`, attacked `0x79cd...Af0c`, attack tx.)
- PeckShield via The Block - "Hashflow faces ongoing exploit ... $600,000":
  https://www.theblock.co/post/234671/trading-firm-hashflow-faces-ongoing-exploit-with-600000-lost-so-far-peckshield
- revoke.cash exploit record: https://revoke.cash/exploits/hashflow
- Neptune Mutual - "How Was Hashflow Exploited?":
  https://medium.com/neptune-mutual/how-was-hashflow-exploited-514b47b32785

## What is authored here (MIT, no third-party bytecode)
`../HashflowDeprecatedRouterClone.sol` is my own minimized reproduction of the vulnerable
surface - a deprecated fill function with NO caller authorization that runs `transferFrom` on a
caller-chosen `(from, to, amount)` using the router's standing approvals. The real multi-function
RFQ router is abstracted to the one unauthorized transfer path the incident turned on. No code
or bytecode from Hashflow or any analysis repo is copied; sources are reference only.

## Why the harness must flag it (VULNERABLE)
`test/HashflowIncident.t.sol`: a victim approves the router, the attacker calls the deprecated
`fillRFQT(token, victim, attacker, amount)`, and the victim's approved balance is drained to the
attacker. Verdict is derived from the real outcome -> VULNERABLE.
