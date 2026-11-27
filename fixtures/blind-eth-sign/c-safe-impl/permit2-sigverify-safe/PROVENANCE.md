# Fixture provenance

```
Fixture:      blind-eth-sign/c-safe-impl/permit2-sigverify-safe
Vector:       blind-eth-sign
Tier:         c-safe-impl
Split:        holdout
Expected:     safe                     # ground-truth label (matches meta `label`)

Nature:       PRECISION-SIDE safe holdout. The only hard, well-documented blind-signing
              incident (Bybit, 2025-02-21) is already the delegatecall-hijack incident fixture;
              reusing it for a second vector would not be independent. No other clean,
              independently-documented blind-eth-sign incident reproducible at code level was
              found at our provenance bar (two extended web passes). So this vector's
              independent holdout is a genuinely-safe real implementation the harness MUST stay
              silent on, not a vuln repro.

Origin:       The canonical SAFE counterpart of the blind-eth-sign vector: a withdrawal that is
              authorized ONLY by a signature over a fully-typed EIP-712 digest (domain-separated
              `Withdrawal` struct). The blind-eth-sign danger is signing an opaque raw hash
              (legacy eth_sign) that a wallet cannot render; here such a signature does not
              match the typed digest, so the recovered signer != owner and the canonical
              verifier reverts - nothing moves. Signature recovery/validation is delegated to
              UNMODIFIED Uniswap Permit2 SignatureVerification (handles 65- and 64-byte EIP-2098
              sigs and ERC-1271 contract signers).

Upstream:     - Uniswap Permit2 SignatureVerification: github.com/Uniswap/permit2,
                commit cc56ad0f3439c502c246fc5cfcc3db92bb8b7219,
                src/libraries/SignatureVerification.sol (+ interfaces/IERC1271.sol), SPDX MIT.
                Vendored byte-identical at fixtures/vendor/permit2/ (see fixtures/vendor/PROVENANCE.md).

Independence: - vs this vector's dev fixture (typed-only-safe / ClearSigningWallet): that is a
                repo-authored reference impl; this delegates to real vendored Uniswap code.
              - vs signature-phishing's safe fixtures: those use OpenZeppelin (oz-sig-safe) and
                Solady (solady-erc1271-safe). This uses a THIRD, different canonical source
                (Uniswap Permit2's verifier), exactly as required.
              - Caveat (disclosed): the permit2-phishing holdout also draws on the Uniswap
                Permit2 project, but a DIFFERENT component - that one deploys the full Permit2
                contract and exercises SignatureTransfer (token-transfer bounding); this one
                links only the SignatureVerification library to gate a typed withdrawal
                (signature-validity). Different code paths, different surfaces.

Source code:  fixtures/blind-eth-sign/c-safe-impl/TypedSigGatedVault.sol (authored here: the
              vault shell + EIP-712 domain/typehash; the signature check is unmodified Permit2)
              + src/MockERC20.sol (repo primitive, the held asset, read-only) +
              test/RealSafePermit2SigVerifyHoldout.t.sol.
License:      MIT (this repo) + MIT (Uniswap Permit2).
Offline:      committed source only; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        The test shows the owner's FULLY-TYPED signature authorizes a withdrawal
              (authority is real -> BLOCKED is not vacuous), then shows a BLIND signature over
              an opaque raw hash (eth_sign style) is rejected by the real verifier
              (InvalidSigner), transferring nothing. Verdict derived from outcome (no
              unauthorized tokens leave). Expected: BLOCKED (TN). A false VULNERABLE here would
              be a real detector false positive and is reported, not suppressed.
```
