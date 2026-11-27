# Fixture provenance

```
Fixture:      permit2-phishing/b-incident/link-permit2-victim
Vector:       permit2-phishing
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)
Split:        holdout                  # authored after wal detectors froze at v0.1

Origin:       LINK (ChainLink) Permit2 phishing drain. The victim had a standing, long-lived
              ERC-20 approve(Permit2, max) on LINK (reported ~411 days old) and was phished
              into signing a SINGLE off-chain Uniswap Permit2 AllowanceTransfer message
              (PermitSingle) naming the attacker as spender with an unbounded amount. The
              attacker later submitted the signature and swept the entire LINK balance in one
              transferFrom. Canonical Permit2 on mainnet:
              0x000000000022D473030F116dDEE9F6B43aC78BA3.

On-chain (verified via Etherscan, browser, this session):
  Network:    Ethereum mainnet
  Drain tx:   0xa25807c87cc99a9c7195548c1438cde9ad937652cc3fb60fe609c01b339b04d0
  Status:     Success
  Block:      26113853
  Timestamp:  2026-10-03 19:18:11 UTC
  Victim:     0x71619d71474F8D0AAa9C18a757be7617686B499b  (owner; approve(Permit2,max) on LINK)
  Recipient:  0xA6809aeDEbFA10A0C2dbcF3363cB0Ff37866f73D  (where the LINK landed)
  Submitter:  0x0000cdCa01087D340e8fA4339b121B69a8aE0000  (Etherscan tag: Fake_Phishing1324813;
              the phishing contract that submitted the signature / spender)
  Drainer EOA:0x0000db5c8B030ae20308ac975898E09741e70000  (Etherscan tag: Fake_Phishing187019;
              the tx `From`)
  Amount:     12,041.303555521415836625 LINK  (one ERC-20 Transfer in the tx logs;
              ~$112,345 at tx-time price per Etherscan)

Reference (>= 2 independent authoritative sources + on-chain match):
  - Scam Sniffer (official @realScamSniffer), incident report naming the victim address and
    linking the drain tx; approval reported signed 2025-08-18, headline loss ~$167,342 in LINK
    (Scam Sniffer valued LINK higher than the tx-time Etherscan price; the on-chain token
    amount 12,041.30 LINK is used here as the authoritative figure).
  - Etherscan's OWN phishing labels, maintained independently of Scam Sniffer: the submitter
    contract 0x0000cdCa...0000 is tagged Fake_Phishing1324813 and the drainer EOA
    0x0000db5c...0000 is tagged Fake_Phishing187019 - independent corroboration that this is a
    phishing drain, not a legitimate transfer.
  - Secondary media (PANews, Phemex, KuCoin, ChainCatcher) report the same incident but trace
    back to the Scam Sniffer report, so they are NOT counted as independent confirmation.
  Proof level: STRONG for the on-chain drain (tx + addresses + amount + date + phishing labels
  all verified on Etherscan); the "~411-day-old approval / signed 2025-08-18" narrative rests on
  the Scam Sniffer report (single specialist tracker) and is cited as such.

Source code:  ../../../../src/ToyPermit2.sol (this repo's AllowanceTransfer model, PermitSingle)
              + src/MockERC20.sol (LINK stand-in, 18 decimals). No third-party bytecode copied.
License:      MIT (this repo).
Minimization: One token, one PermitSingle signature, one transferFrom are modeled; the LINK
              amount matches the on-chain drain. The REAL Uniswap Permit2 is exercised
              separately in tier (c); this tier reproduces the mechanism offline without
              AGPL/solmate dependencies. The victim/spender/recipient addresses above are the
              real, Etherscan-labeled on-chain addresses, used as-is for fidelity.
Offline:      committed; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/LinkPermit2Incident.t.sol: ONE PermitSingle signature then one transferFrom
              empties the victim's LINK. Verdict derived from the real outcome.
              Expected: VULNERABLE (TP).
```
