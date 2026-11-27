# Fixture provenance

```
Fixture:      blind-eth-sign/c-safe-impl/solady-typed-sig-safe
Vector:       blind-eth-sign
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady EIP712 + SignatureCheckerLib - independent, widely-used MIT primitives for
              EIP-712 typed-data hashing and ECDSA/ERC-1271 signature validation.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              files src/utils/EIP712.sol, src/utils/SignatureCheckerLib.sol -> vendored
              byte-identical at fixtures/vendor/solady/ (one documented import-only repoint for
              the ERC1271 closure; these two files unchanged; see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ../SoladyTypedSigVault.sol (typed-signature-gated withdrawal over the unmodified
              Solady EIP712 + SignatureCheckerLib; adds only a typed Withdrawal struct, a replay
              nonce and a gated withdraw - no raw-hash/eth_sign entrypoint, no change to the
              hashing/validation logic).

Why holdout: The existing blind-eth-sign c-safe-impl fixtures use OpenZeppelin EIP712+ECDSA
             (oz-clearsign-safe), Uniswap Permit2's verifier (permit2-sigverify-safe) and a dev
             reference (typed-only-safe). This fixture exercises the same clear-signing defense on
             the INDEPENDENT Solady codebase wal was never tuned against - mirroring how the
             signature-phishing vector carries both an OpenZeppelin and a Solady holdout - so a
             clean verdict is an honest precision signal on unseen safe code.

Behavior:    test/RealSafeSoladyTypedSigHoldout.t.sol has the real owner key produce a BLIND
             eth_sign (personal_sign) signature over the Ethereum-Signed-Message-wrapped digest;
             the vault validates against the bare typed digest, so the recovered signer differs
             from the owner and the withdrawal reverts. A guard confirms a genuine TYPED-digest
             signature DOES withdraw (authority is real). The verdict is derived from the real
             outcome (vault balance intact under the blind signature), not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
             No fabricated incident: this is a precision-side safe holdout (no independent
             code-level vuln blind-eth-sign incident at the bar not already used elsewhere),
             stated plainly - not padded into a false positive.
```
