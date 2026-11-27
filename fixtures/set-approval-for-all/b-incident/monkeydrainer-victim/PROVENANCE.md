# Fixture provenance

```
Fixture:      set-approval-for-all/b-incident/monkeydrainer-victim
Vector:       set-approval-for-all
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)

Origin:       Monkey Drainer - NFT/token phishing-as-a-service (2022-2023; SlowMist estimated
              ~$12.972M across 1,708 addresses; the $16M/$24M figures are unverified press/self-report)
Reference:    Mechanism: victims lured into setApprovalForAll(operator, true)
                selector 0xa22cb465 = keccak256("setApprovalForAll(address,bool)")[:4]
              Then the malicious operator transferFrom-swept the victims' whole collections.
              Sources (all public):
                - SlowMist - "Analysis of Monkey Drainer NFT Phishing Group" (2023-02): estimated
                  ~$12.972M across 1,708 addresses
                  (slowmist.medium.com/slowmist-analysis-of-monkey-drainer-nft-phishing-group-e4e269634854)
                - zerotracelabs - Monkey Drainer write-up (phishing-as-a-service analysis)
                - arXiv:2409.02386 - payload-based phishing dataset (508 NFT entries)
              Proof level: INCIDENT-LEVEL. The operation, method and selector are strongly
              documented; an exact per-victim approval/drain tx pair is not pinned at the
              blog-source level. Representative addresses are used in the test. If a precise
              victim tx is later confirmed on Etherscan, pin it here.
Source code:  ../MonkeyDrainerNFTClone.sol (authored minimized ERC-721 clone, this repo)
License:      MIT (this repo). No third-party code copied; only the operator-for-all +
              transferFrom surface needed to replay the documented sweep is modeled.

Minimization: Modeled only setApprovalForAll / isApprovedForAll / transferFrom with standard
              ERC-721 operator-for-all authorization. Metadata, enumerable, royalties and
              per-token approve are omitted - irrelevant to the operator-sweep path.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/MonkeyDrainerIncident.t.sol replays setApprovalForAll -> full-collection
              transferFrom sweep; the verdict is derived from the real outcome (collection
              emptied), not hardcoded. Expected: VULNERABLE (TP).
```
