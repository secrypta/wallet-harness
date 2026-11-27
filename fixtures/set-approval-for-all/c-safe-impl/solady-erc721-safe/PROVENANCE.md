# Fixture provenance

```
Fixture:      set-approval-for-all/c-safe-impl/solady-erc721-safe
Vector:       set-approval-for-all
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady ERC721 - an independent, widely-used MIT ERC-721 implementation.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/tokens/ERC721.sol -> vendored byte-identical at
              fixtures/vendor/solady/ERC721.sol (self-contained; see fixtures/vendor/PROVENANCE.md)
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ../SoladyERC721Fixture.sol (concrete NFT over the unmodified Solady ERC721;
              adds only name()/symbol()/tokenURI() + a test-only mint - no change to auth logic).

Why holdout: The existing set-approval-for-all c-safe-impl fixture uses OpenZeppelin ERC721.
             Solady is a DIFFERENT, independent codebase wal was never tuned against, so a clean
             verdict here is an honest precision signal on unseen safe code.

Behavior:    test/RealSafeSoladyNFTHoldout.t.sol gives a SCOPED single-token approval (approve,
             not setApprovalForAll), confirms the operator can move that one token, then attempts
             to sweep every OTHER token. Solady's per-token authorization reverts each sweep. The
             verdict is derived from the real outcome (non-scoped tokens stay with the holder),
             not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
