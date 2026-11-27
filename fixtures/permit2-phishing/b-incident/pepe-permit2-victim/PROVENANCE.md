# Fixture provenance

```
Fixture:      permit2-phishing/b-incident/pepe-permit2-victim
Vector:       permit2-phishing
Tier:         b-incident
Expected:     vuln

Origin:       PEPE holder Permit2 phishing, 2024-10-13, loss ~$1.39M (PEPE + MSTR + APU).
              The victim had the standard one-time approve(Permit2, max) on the tokens and
              signed a SINGLE malicious Uniswap Permit2 signature off-chain, granting the
              attacker unbounded pull rights over several tokens at once; the attacker then
              swept all of them. Permit2 contract on mainnet:
              0x000000000022D473030F116dDEE9F6B43aC78BA3.
Reference:    Scam Sniffer; Decrypt (decrypt.co/286076, "Pepe Holder Loses $1.4 Million in Uniswap
              Permit2 Phishing Attack"); Crypto Times (cryptotimes.io, 2024-10-14).
              Proof level: INCIDENT-LEVEL. The incident is well-documented and web-corroborated
              (PEPE + MSTR + APU, ~$1.39M, 2024-10-13, first reported by Scam Sniffer), BUT this
              fixture pins NO single drain tx, NO victim address and NO exact on-chain amounts - the
              token amounts below are representative units (see Minimization), not the on-chain
              figures. A specific tx/victim/amount could be pinned from Etherscan in a later pass;
              that was not done here, so the honest level is incident, not STRONG. (Contrast the
              sibling link-permit2-victim, which IS tx+victim+amount pinned on Etherscan.)
              Context: Scam Sniffer reported ~$494M drainer losses across 2024.
Source code:  ../../../../src/ToyPermit2.sol (this repo's AllowanceTransfer model, permitBatch)
              + src/MockERC20.sol (PEPE/MSTR/APU stand-ins). No third-party bytecode copied.
License:      MIT (this repo).
Minimization: The three tokens and one PermitBatch signature are modeled; token amounts are
              representative units, not the exact on-chain figures. The REAL Uniswap Permit2
              is exercised separately in tier (c); this tier reproduces the mechanism offline
              without AGPL/solmate dependencies.
Offline:      committed; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/PepePermit2Incident.t.sol: ONE permitBatch signature then three
              transferFrom calls empty all three balances. Verdict from the real outcome.
              Expected: VULNERABLE (TP).
```
