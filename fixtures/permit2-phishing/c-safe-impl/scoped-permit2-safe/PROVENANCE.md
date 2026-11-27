# Fixture provenance

```
Fixture:      permit2-phishing/c-safe-impl/scoped-permit2-safe
Vector:       permit2-phishing
Tier:         c-safe-impl
Expected:     safe

Nature:       The REAL Uniswap Permit2, vendored byte-for-byte at commit cc56ad0 (MIT), run
              under a scoped-signature policy. This is genuinely-safe real code, NOT a tweaked
              toy: the allowance accounting, EIP-712 signature verification, nonce and
              expiration handling exercised by this tier are the unmodified Permit2 core.
Source:       https://github.com/Uniswap/permit2  commit cc56ad0f3439c502c246fc5cfcc3db92bb8b7219
License:      MIT (Copyright (c) 2022 Uniswap Labs) - full text in
              ../../../vendor/permit2/LICENSE. See ../../../vendor/PROVENANCE.md for the
              vendored file list and the one documented deviation below.
Deviation:    Permit2 core is verbatim EXCEPT its two solmate token-plumbing imports in
              AllowanceTransfer.sol and SignatureTransfer.sol:
                import {ERC20} from "solmate/src/tokens/ERC20.sol";
                import {SafeTransferLib} from "solmate/src/utils/SafeTransferLib.sol";
              solmate is AGPL-3.0-only; to keep this repo pure MIT those two imports were
              repointed to an MIT shim (../mit-shim/{ERC20,SafeTransferLib}.sol) exposing the
              identical API (`ERC20` token type; `safeTransferFrom(ERC20,address,address,
              uint256)`). ONLY the two import lines changed; Permit2's defensive logic is
              untouched (verified: byte-for-byte diff limited to those two lines).
Source code:  ../../../vendor/permit2/src/Permit2.sol (+ closure) and this fixture's
              Permit2SafeToken.sol (MIT ERC-20 vehicle). Owner-decision: Variant C.
Offline:      committed vendored source; no mainnet fork, no live RPC. Built/run in Docker.
              Permit2 pins exact pragma 0.8.17, compiled via auto_detect_solc and linked at
              the bytecode level alongside the repo's 0.8.24 sources.
Notes:        test/RealSafePermit2.t.sol: a new Permit2() with a SCOPED signature (exact
              amount, short expiration); a full-balance transferFrom reverts with the real
              contract's InsufficientAllowance, assets intact -> BLOCKED. Guard: the scoped
              amount is genuinely pullable, so BLOCKED is not vacuous. Expected: BLOCKED (TN).
```
