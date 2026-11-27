# Fixture provenance

```
Fixture:      approve-drainer/b-incident/steth-whale-victim
Vector:       approve-drainer
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)
Split:        holdout                  # authored after wal detectors froze at v0.1

Origin:       2023-09-06 whale approval-phishing drain (~$24.24M). A whale was phished into
              granting token allowances to the attacker via on-chain "increaseAllowance"
              approvals (NOT an off-chain permit), after which the attacker transferFrom'd the
              whole balance out. Two legs: ~9,579.21 stETH (~$17.46M) and ~4,851 rETH (~$8.5M).
              The attacker then swapped the loot to ~13,785 ETH and ~1.64M DAI. This fixture
              replays the verified stETH leg.

On-chain (verified via Etherscan, browser, this session):
  Network:    Ethereum mainnet
  Drain tx:   0xcbe7b32e62c7d931a28f747bba3a0afa7da95169fcf380ac2f7d54f3a2f77913  (stETH leg)
  Status:     Success
  Block:      18078908
  Timestamp:  2023-09-06 17:31:35 UTC
  Victim:     0x13e382dfe53207E9ce2eeEab330F69da2794179E  (owner)
  Spender:    0x4c10a462CD1e639Da8A062aE8a33a23401120ab1  (held the approval, executed the
              transferFrom; Etherscan tag: Fake_Phishing186944)
  Recipient:  0x693b725a375f599f0b6efa0d910e749e1bec1555 (Etherscan tag: Fake_Phishing186943;
              where the stETH landed. The fixture models victim -> spender, matching the
              verified tx executor; recipient full address independently confirmed via RPC.)
  Token:      Lido stETH (0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84)
  Amount:     9,579.212966327732523199 stETH  (~$17,460,652 at tx time per Etherscan)
  Etherscan note on the tx: "Phish / Hack - A user lost $24M worth of Liquid Staked ETH in a
              phishing attack via unauthorized token approvals."

Reference (>= 3 independent authoritative sources + on-chain match):
  - PeckShield (auditor), alert: "A whale fell victim to a #phishing attack, losing $24.24M ...
    ~4,851 rETH and 9,579.2 stETH ... swapped ... for ~13,785 ETH and 1.64M DAI" (2023-09-07).
  - SharkTeam (auditor), on-chain asset-flow analysis: victim 0x13e382 authorized rETH/stETH
    to scammer address 1 (0x4c10a4) via "Increase Allowance"; funds moved to scammer address 2
    (0x693b72); later swapped on Uniswap/Curve.
  - Cointelegraph and CryptoSlate (major media) reporting the same incident, amounts and date.
  - Etherscan's OWN "Phish / Hack" label on the drain tx and the Fake_Phishing186943/186944
    address tags (maintained independently).
  All facts (victim/spender addresses, 9,579.21 stETH, 2023-09-06, Ethereum) agree across
  sources AND match the on-chain record. Proof level: STRONG.

Source code:  ../LidoStEthClone.sol (authored minimized clone, this repo)
License:      MIT (this repo). No third-party code copied; stETH's share/rebase accounting is
              NOT reproduced - only the OZ-style allowance + transferFrom surface needed to
              replay the documented path.
Minimization: Modeled only approve / increaseAllowance / transferFrom with standard
              OpenZeppelin-style allowance accounting (18-decimal token). The real victim and
              spender addresses above are used as-is for fidelity; VICTIM_BALANCE matches the
              exact on-chain stETH drained in the verified tx.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/StethWhaleIncident.t.sol replays increaseAllowance -> transferFrom and the
              verdict is derived from the real outcome (balance emptied). Expected: VULNERABLE (TP).
```
