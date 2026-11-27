# Provenance - Odos limit-order-router ERC-6492 signature-validation drain

**Fixture:** `../OdosLimitOrderRouterClone.sol` (contract `OdosLimitOrderRouterClone`)
**Vector:** signature-phishing - ERC-1271 forged / permissive signer (drain-scan rule **R15**, axis iii)
**Verdict:** VULNERABLE (harness MUST flag)

## Incident facts

| Field | Value |
|---|---|
| Protocol | Odos - limit-order router |
| Date | 2025-01-23 |
| Chain | Base |
| Reported loss | ~$50,000 (OpenZeppelin Notorious Bug Digest #1) |
| Attacker EOA | `0x4015d786e33c1842c3e4d27792098e4a3612fc0e` (per QuillAudits / DeFiHackLabs) |
| Malicious contract | `0x22A7dA241A39F189a8Aec269A6F11A238B6086fc` (per QuillAudits / DeFiHackLabs) |
| Victim router | `OdosLimitOrderRouter` (labeled by Blockscout; QuillAudits names `0xB6333E994Fd02a9255E794C177EfBDEB1FE779C7`) |
| **Pinned attacker exploit tx** | `0xd10faa5b33ddb501b1dc6430896c966048271f2510ff9ed681dd6d510c5df9f6` - block **25431001** (`0x1840bd9`), 2025-01-23 21:55:49 UTC, method `exploit`, status Success |

**Explorer verification (not RPC):** the transaction was read on Blockscout Base
(`base.blockscout.com/tx/<hash>`). Blockscout labels the sender `ODOS Exploiter 1` and the
interacted contract `0x22A7dA241A39F189a8Aec269A6F11A238B6086fc`, and shows tokens transferred
`From` `OdosLimitOrderRouter` to the exploiter (USDC, WETH, CBBTC, AERO, VIRTUAL, FAI, LBTC, CBETH,
WSTETH, EURC). Block number read from the tx (hex derived from the decimal, not hardcoded). The
~$50K figure (OpenZeppelin) is across the coordinated attack, not this single tx.

## Root cause (per OpenZeppelin / QuillAudits)

The router's `isValidSigImpl` validated ERC-6492 "predeploy" signatures by inheriting the ERC-6492
reference `UniversalSigValidator` logic directly into the router rather than deploying it as an
independent contract and calling it. In the counterfactual branch (signer contract not yet
deployed) the reference logic low-level-calls a factory, with the `create2Factory` address and the
`factoryCalldata` BOTH taken from the attacker-supplied signature - i.e. an arbitrary call executed
from the router's own context during signature validation. The attacker pointed the signer at the
identity precompile at address `0x04` (which has no code) to force the deploy branch, then used the
arbitrary call to drain. `pcaversaccio` and the ERCs repo (issue #877) cite this as a real-world
case against inheriting the ERC-6492 reference implementation.

## Why the harness must flag it (R15, axis iii)

During signature validation the contract low-level-calls a **caller-supplied factory with
caller-supplied calldata** (both decoded from the `signature` parameter) and then trusts the
(attacker-named) signer's `isValidSignature`. R15 fires on the counterfactual deploy-and-trust
axis - the signer is caller-controlled too, so this fixture also exhibits axis (i).

## Minimization / boundary

Authored in-repo (MIT). Not a copy of the on-chain router or of DeFiHackLabs PoC code; the ERC-6492
counterfactual branch is reduced to the minimal arbitrary-call-during-validation shape. The
identity-precompile `0x04` detail is a runtime bypass and is described, not reproduced; the static
root cause (caller-supplied factory + calldata called inside validation) is what the fixture and
rule turn on. No live contracts; offline compile only.

## Sources

- OpenZeppelin - "The Notorious Bug Digest #1": https://www.openzeppelin.com/news/the-notorious-bug-digests-1
- QuillAudits - "What Went Wrong With Odos Protocol?":
  https://www.quillaudits.com/blog/hack-analysis/odos-protocol-arbitrary-call-vulnerability
- ethereum/ERCs issue #877 (ERC-6492 reference-impl warning): https://github.com/ethereum/ERCs/issues/877
- DeFiHackLabs reference: `src/test/2025-01/ODOS_exp.sol` (dated 20250123), tx as above.

## License / attribution

Fixture `OdosLimitOrderRouterClone.sol` is original work authored in this repository under **MIT**
(see its SPDX header). It is a minimized mechanism reproduction, not a copy of the on-chain Odos
router or of the DeFiHackLabs PoC. Incident facts are attributed to the OpenZeppelin / QuillAudits
write-ups, the DeFiHackLabs reference, and the explorer record cited above.
