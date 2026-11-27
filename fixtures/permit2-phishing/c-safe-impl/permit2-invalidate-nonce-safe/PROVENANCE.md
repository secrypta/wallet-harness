# Fixture provenance

```
Fixture:      permit2-phishing/c-safe-impl/permit2-invalidate-nonce-safe
Vector:       permit2-phishing
Tier:         c-safe-impl
Expected:     safe                     # ground-truth label (matches meta `label`)
Split:        holdout                  # authored after wal detectors froze at v0.1

Nature:       The REAL Uniswap Permit2, vendored byte-for-byte at commit cc56ad0 (MIT), run
              through its `invalidateNonces` pre-emption path. Genuinely-safe real code, NOT
              a tweaked toy: the nonce accounting and signature verification are the unmodified
              Permit2 core.
Source:       https://github.com/Uniswap/permit2  commit cc56ad0f3439c502c246fc5cfcc3db92bb8b7219
License:      MIT (Copyright (c) 2022 Uniswap Labs) - full text in
              ../../../vendor/permit2/LICENSE. See ../../../vendor/PROVENANCE.md for the
              vendored file list and the single documented deviation (two solmate imports
              repointed to an MIT shim; Permit2's defensive logic untouched).
Source code:  ../../../vendor/permit2/src/Permit2.sol (+ closure) and this vector's
              scoped-permit2-safe/Permit2SafeToken.sol (MIT ERC-20 vehicle), reused read-only.
Offline:      committed vendored source; no mainnet fork, no live RPC. Built/run in Docker.
              Permit2 pins exact pragma 0.8.17, compiled via auto_detect_solc and linked at
              the bytecode level alongside the repo's 0.8.24 sources (deployCode).
Notes:        test/RealSafePermit2Round2.t.sol (test_permit2_invalidateNonces_realSafe_blocked):
              the owner is phished into signing an UNBOUNDED PermitSingle at nonce 0, but
              calls `invalidateNonces(token, spender, 1)` before the attacker can submit it;
              the captured signature then reverts with the real contract's InvalidNonce (nonce
              0 != stored nonce 1), so no allowance is ever set and a drain is impossible ->
              BLOCKED. Expected verdict: BLOCKED (TN).
```
