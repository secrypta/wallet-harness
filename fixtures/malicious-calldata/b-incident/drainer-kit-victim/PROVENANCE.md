# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/drainer-kit-victim
Vector:       malicious-calldata
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)

Origin:       Drainer-kit hidden / mislabeled approval. Phishing kits present a transaction
              under a benign label ("Connect"/"Claim"/"Enable") whose real calldata hides an
              approve/transfer (directly or via multicall/delegatecall) to the attacker.
Reference:    Documented as a CLASS, not a single pinned tx:
                - arXiv:2409.02386 / NDSS 2025 - payload-based transaction phishing dataset
                  (approve-type + permit-type; benign-labeled payable drainers e.g. the
                  "SecurityUpdate" fallback that empties ETH)
                - public drainer-kit analyses (ghostkit / onchain-diary teardown writeups)

Incident anchor (real named campaign, Check Point Research 2025, "Inferno Drainer
              Reloaded" - https://research.checkpoint.com/2025/inferno-drainer-reloaded-
              deep-dive-into-the-return-of-the-most-sophisticated-crypto-drainer/):
                - Drainer owner / operator:  0x0000db5c8B030ae20308ac975898E09741e70000
                - Multicall helper contract:  0x0B7A19c3d261dcEeb6ed3b2023B07b6cc4E60543
                - Fake-token contracts (benign-named methods, vanity 0x0000..0000):
                    0x00002687313C403c002143b6c9A521c39EEf0000, and others
                - ERC-20 theft trace (Check Point Fig. 14): tx
                    0x2e122bed57044a997bd710b25bb58310a124bd10941e881a88393d62e7e1540d
                - FakeToken.Verify() benign-label trace (Fig. 13): tx
                    0x74399c282443b400e66df56aaa529efca38c168d7ebd73037c90df63d85a0e54
                - Largest-loss ERC-20 drains (sample, per report): USDC
                    0x48814377bfc3e5f76283b3cd3b166442328972a8f6f9074b8d6b9693ce25c40a
                    (2024-10-09); USDT
                    0xbf7f719c4f18ae3189ea0e614ff2d288fa2546fb6ad95d30931952ca36a9b5b6
                    (2024-10-21). Campaign window 2024-09-24 .. 2025-03-07, ~$9M / 30k+ wallets.
              Hidden-approve decode signature to look for in such calldata: selector
              0x095ea7b3 (approve(address,uint256)) with value 2^256-1 to the attacker.

              HONESTY CAVEAT (why this stays class-level, not strong): tx hashes above are
              cited from the Check Point report (public source; no live-RPC used). In the
              Inferno flow the approve and the drain are SEPARATE steps - the victim first
              approves the fake-token contract, then the OPERATOR sends the multicall/
              transferFrom drain - and the benign-labeled Verify() path drains ETH via a
              fallback rather than hiding an approve. We did NOT find a pinnable SINGLE victim
              transaction that hides approve(attacker,max) inside a multicall batch. So this
              fixture is anchored to a real campaign at the CLASS level; it is not a
              byte-for-byte replay of one of these transactions.

              Proof level: CLASS-LEVEL, incident-anchored (Inferno Drainer "Reloaded",
              Check Point 2025). Honestly flagged - stronger than a purely academic class
              anchor, but not single-tx "strong" (no verified one-tx hidden-approve-in-batch).
              This fixture reproduces the DOCUMENTED PATTERN (benign label hides an approve),
              NOT a byte-for-byte replay of one victim transaction.
Source code:  ../DrainerKitModule.sol (authored minimized clone, this repo) + the repo's
              CalldataVulnerableWallet (executes calldata "by its label").
License:      MIT (this repo). No third-party drainer bytecode copied.

Minimization: Only the benign-named entrypoint hiding `approve(self, max)` + a `drain` via
              `transferFrom` are modeled - the exact surface needed to replay the pattern.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/DrainerKitIncident.t.sol executes the module "by label", the hidden
              approve lands, and the attacker sweeps the balance; the verdict is derived from
              the real outcome (balance emptied). Expected: VULNERABLE (TP).
```
