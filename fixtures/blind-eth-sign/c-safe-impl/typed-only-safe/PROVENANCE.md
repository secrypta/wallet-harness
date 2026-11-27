Fixture:      blind-eth-sign/c-safe-impl/typed-only-safe
Vector:       blind-eth-sign
Tier:         c-safe-impl
Expected:     safe

Origin:       Canonical defense: clear signing. Accept only decodable EIP-712 typed data the
              wallet can display and disable the raw-hash (eth_sign) entrypoint.
Reference:    EIP-712 typed structured data; ERC-7730 clear signing (Ethereum Foundation);
              MetaMask MIP-3 / Safe eth_sign removal.
Source code:  ClearSigningWallet.sol - reference-impl authored in this repo.
License:      MIT (this repo).

Minimization: REFERENCE-IMPL, honestly marked: no single canonical third-party library for
              "never blind-sign a raw hash", so tier (c) is a faithful implementation of the
              clear-signing direction (EIP-712 typed-only), NOT vendored code and NOT a
              lightly-edited toy. The wallet derives every digest itself from the order struct
              under its own domain separator.
Offline:      Fully offline; deterministic Foundry test in Docker.
Notes:        A signature over an attacker's bare hash recovers a signer != owner, so it cannot
              authorize anything here; a genuine typed order the owner signed still executes
              (guard), so BLOCKED is not vacuous. Harness MUST stay silent (BLOCKED).
