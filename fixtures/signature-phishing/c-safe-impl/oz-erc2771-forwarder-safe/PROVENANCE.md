# Fixture provenance

```
Fixture:      signature-phishing/c-safe-impl/oz-erc2771-forwarder-safe
Vector:       signature-phishing
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent canonical verifier; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin ERC2771Forwarder - the canonical EIP-712 meta-transaction forwarder
              (ERC-2771) used to relay user-signed gasless transactions.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              file metatx/ERC2771Forwarder.sol -> vendored byte-identical at
              fixtures/vendor/oz/metatx/ERC2771Forwarder.sol (its import closure - ERC2771Context,
              ECDSA, EIP712, Nonces, Address, Errors - was already vendored; OZ uses relative
              imports, no repoint needed; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in fixtures/vendor/oz/LICENSE.
Source code:  ../MetaTxForwarderVault.sol (a meta-tx recipient that trusts the forwarder and
              attributes each withdrawal to the forwarded signer via OZ ERC2771Context._msgSender();
              adds only a per-user balance ledger + a caller-scoped withdraw - no change to the
              forwarder's verification logic).

Why holdout: The existing signature-phishing c-safe-impl holdouts all perform a DIRECT on-chain
             signature check - oz-sigchecker-safe (OZ SignatureChecker), oz-sig-safe (OZ
             EIP712+ECDSA), solady-erc1271-safe (Solady ERC-1271). This fixture exercises a
             different real surface: the canonical ERC-2771 META-TRANSACTION relay, where the
             forwarder's EIP-712 verification binds the relayed call to the signer. It is unseen
             safe code wal was never tuned against.

Behavior:    test/RealSafeMetaTxForwarderHoldout.t.sol has the phisher forge a ForwardRequest that
             claims from=victim but is signed with the attacker's key; the forwarder's signer check
             fails (ERC2771ForwarderInvalidSigner) and the relayed withdraw never runs. A guard
             confirms a genuine victim-signed request DOES execute (authority is real). The verdict
             is derived from the real outcome (vault + victim ledger intact under the forged
             request), not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
             This vector remains precision-side only (no independent vuln signature-phishing
             holdout at the bar); stated plainly, not padded into a false positive.
```
