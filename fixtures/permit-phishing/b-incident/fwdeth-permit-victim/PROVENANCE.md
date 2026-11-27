# Fixture provenance

```
Fixture:      permit-phishing/b-incident/fwdeth-permit-victim
Vector:       permit-phishing
Tier:         b-incident (MECHANISM-level)
Expected:     vuln                     # ground-truth label (matches meta `label`)
Split:        holdout                  # authored after wal detectors froze at v0.1

Origin:       fwDETH (Few Wrapped Duo ETH) EIP-2612 permit-phishing drain, ~$35M, on the Blast
              network. The victim was lured into signing ONE offline EIP-2612 `permit` message;
              the attacker (Angel Drainer kit) submitted the signed permit to set an allowance and
              drained the victim's fwDETH via `transferFrom`. Reported in two stages totalling
              15,079 fwDETH.

!!! PROOF LEVEL: MECHANISM-LEVEL (read this disclaimer) !!!
  - There is NO public drain-transaction hash for this incident in any source reviewed.
  - The official Blast block explorer (blastscan.io) has been DEPRECATED/discontinued (Blast
    mainnet API support ended 2024-10-31 per blastscan.io), so an authoritative explorer page for
    the drain tx cannot be cited or independently reproduced here.
  - Therefore this fixture is modeled at the MECHANISM level, exactly like the corpus's existing
    tier-b cases that reproduce a documented mechanism without a single pinned drain-tx
    (cf. beanstalk / furucombo / li-fi / socket). It is NOT verified down to an on-chain tx the
    way link-permit2-victim / spark-weth-permit-victim are.
  - NO transaction hash or full address is fabricated. The only full on-chain address below is
    one independently observed on a live Blast explorer; the victim address is left TRUNCATED
    exactly as the sources give it (not reconstructed).

Reported facts (from the sources below; amounts are the sources' reported figures):
  Network:    Blast (chainid 81457)
  Date:       2024-10-11 (Scam Sniffer / Lookonchain first reports)
  Token:      fwDETH - "Few Wrapped Duo ETH" (Duo protocol wrapped ETH derivative on Blast)
  Victim:     0xEab2E...a393  (TRUNCATED as published; NOT reconstructed. Arkham/Lookonchain
              speculatively linked it to an entity related to Continue Capital - unconfirmed.)
  Amount:     15,079 fwDETH (~$35M) drained in two stages: 12,817.15 + 2,261.85 fwDETH.
  Mechanism:  offline EIP-2612 `permit` phishing signature -> `transferFrom` drain. Per BlockSec
              co-founder Yajin (Andy) Zhou: the attacker "lured the victim into signing a permit
              message offline and then used the signed permit message to drain the fwDETH token".
  Attribution: SlowMist founder Cosine attributed the drain to the Angel Drainer phishing group.
  Downstream: 0x0605eDeE6a8b8b553caE09Abe83b2ebeb75516eC - an address observed (on the live
              Routescan Blast explorer, blastexplorer.io, this session) receiving and then
              unwrapping/selling the drained Duo-ETH proceeds. Used in the test only as a labelled
              recipient of the modeled sweep; it is a downstream launderer, not necessarily the
              per-stage transferFrom recipient (those intermediates are not published).

Reference (>= 2-3 independent authoritative sources on the INCIDENT; no independent on-chain
tx-level artifact exists, see disclaimer):
  - The Block - "$35 million worth of tokens drained from a crypto whale in phishing attack"
    (quotes BlockSec's Andy Zhou on the offline-permit mechanism).
  - Lookonchain - first on-chain-monitoring report (date, amount, suspected victim).
  - Scam Sniffer (official @realScamSniffer) - incident report, 2024-10-11.
  - SlowMist / Cosine - Angel Drainer attribution.
  - CoinJournal / DailyCoin / Cryptopolitan - media coverage of the same figures.
  Proof level: incident well-corroborated across multiple authorities on amount/date/network/
  mechanism; MECHANISM-level only (no pinned drain tx; deprecated explorer).

Relationship to other fixtures (distinctness, honest):
  - DISTINCT from spark-weth-permit-victim (also EIP-2612 permit -> two-transfer split) and
    usdc-permit-victim: a DIFFERENT incident on a DIFFERENT network (Blast, not Ethereum), a
    DIFFERENT token (fwDETH vs spWETH/USDC), a different victim and a different drainer group
    (Angel Drainer here; the spWETH drainer EOA 0x0000db5c... was a different operator). Same base
    EIP-2612 mechanism, different incident - consistent with the corpus already carrying usdc +
    spWETH as two separate EIP-2612 permit incidents.
  - DISTINCT from lixir-permit-victim (broken-permit, dummy signature) and
    anyswap-permit-bypass-victim (permit-bypass fallback): a different enabling bug.

Source code:  ../FwDethPermitClone.sol - a minimized, MIT, authored-here EIP-2612 permit token
              modeling exactly the ERC-20 + permit surface needed to replay the path. No
              third-party / exploit bytecode is copied or vendored. The owner used in the test is
              a test key (no real victim key / full victim address is used). The swept amounts are
              the sources' reported figures.
License:      MIT (this repo).
Offline:      committed; no fork, no live RPC in the test. Built/run in Docker.
Notes:        test/FwDethPermitIncident.t.sol: ONE phishing permit sets an unbounded allowance,
              then two transferFrom calls (the two reported stages) empty the victim's fwDETH.
              Verdict derived from the real outcome (balance == 0). Expected: VULNERABLE (TP).
```
