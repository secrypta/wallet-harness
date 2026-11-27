# Fixture provenance

```
Fixture:      set-approval-for-all/b-incident/premint-operator-victim
Vector:       set-approval-for-all
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)
Proof level:  INCIDENT-LEVEL (attacker address cross-confirmed by two auditors + on-chain;
              injected-setApprovalForAll mechanism documented; exact per-victim tx not pinned).

Origin:       PREMINT (premint.xyz) NFT allowlist tool, 2022-07-17. Attackers injected
              malicious JavaScript into the premint.xyz front-end (loaded from an attacker-
              controlled domain). During a routine action the injected code presented a fake
              "wallet verification" prompt whose actual on-chain transaction was
              setApprovalForAll(operator, true) (selector 0xa22cb465) to an operator returned
              by the attacker's back-end. The malicious operator then transferFrom-swept the
              victims' NFTs. ~314-321 NFTs were taken from ~28 wallets, ~275 ETH (~$375K);
              proceeds were laundered via Tornado Cash. This is the set-approval-for-all
              vector: blanket operator authority granted (unknowingly) to a malicious address.

Confirmed on-chain identifier (Ethereum mainnet, verified via read-only RPC
eth_getTransactionCount / eth_getCode / eth_getBalance):
              - Attacker EOA: 0x0C9797805a22E507Bf48F35C72A67f001b7418d0
                (active externally-owned account; non-zero nonce / outgoing tx history,
                consistent with an attacker that sold the stolen NFTs on OpenSea).
              - setApprovalForAll(address,bool) selector 0xa22cb465 (the injected call).
              NOTE: the blog/auditor sources do not publish an exact per-victim setApprovalForAll
              tx hash; the pinned, cross-confirmed on-chain artifact is the attacker EOA above.
              The date 2022-07-17 and the ~275 ETH / ~$375K figures are from the auditor
              write-ups (consistent across sources below).

Reference (independent, authoritative - cross-checked, >= 2-3 sources + on-chain):
              - Beosin, "Are NFT tools safe? What we can learn from the Premint hack?":
                names the attacker address 0x0C9797805a22E507Bf48F35C72A67f001b7418d0, traced
                through the OpenSea sales of the stolen NFTs.
              - CertiK, "PREMINT NFT Incident Analysis": independently lists the same attacker
                EOA (0x0C979...) among the exploiter accounts; ~275 ETH / $374,417.66.
              - SlowMist, "Analysis of Premint Malicious Code Injection": the injected code
                initiated setApprovalForAll authorizing an attacker back-end address.
              - GoPlus analysis (via reporting): the "signature verification" prompt was in
                fact an on-chain setApprovalForAll.
              - On-chain confirmation (this repo): the attacker EOA 0x0C979...18d0 was read
                directly from Ethereum mainnet as an active EOA, consistent with the above.

Source code:  reuses ../../../../src/MockERC721.sol (standard ERC-721 operator surface) and
              ../../../../src/MaliciousOperator.sol (the sweeping operator), both authored in
              this repo (MIT). No per-incident clone contract is added: the injected call
              targeted standard collections, so the standard ERC-721 operator path is the
              faithful model. Distinct incident from monkeydrainer-victim (phishing-as-a-service)
              and nfttrader-operator-victim (reentrant settlement); same vector mechanism.
License:      MIT (this repo). No third-party code copied.

Minimization / honest scope:
              The on-chain drain mechanism (setApprovalForAll -> operator transferFrom sweep)
              is identical to other set-approval incidents; what distinguishes PREMINT is the
              DELIVERY (compromised front-end presenting the approval as "verification"), which
              is an off-chain UX step and out of the detector's on-chain scope. The victim and
              collection are stand-ins; the attacker EOA is the real, on-chain-confirmed address.
Offline:      committed model reusing repo src/ contracts; no mainnet fork, no live RPC in the
              test. The on-chain verification above was a read-only lookup, not a live-contract
              test. Built/run in Docker.
Notes:        test/PremintIncident.t.sol: the victim grants blanket operator approval and the
              operator sweeps the whole collection; the verdict is derived from that outcome.
              Expected verdict: VULNERABLE (TP).
```
