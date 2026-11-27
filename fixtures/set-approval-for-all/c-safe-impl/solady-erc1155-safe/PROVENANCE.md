# Fixture provenance

```
Fixture:      set-approval-for-all/c-safe-impl/solady-erc1155-safe
Vector:       set-approval-for-all
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady ERC1155 - an independent, widely-used MIT ERC-1155 implementation.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/tokens/ERC1155.sol -> vendored byte-identical at
              fixtures/vendor/solady/ERC1155.sol (self-contained, no imports; see
              fixtures/vendor/PROVENANCE.md)
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ../SoladyERC1155Fixture.sol (concrete ERC-1155 over the unmodified Solady ERC1155;
              adds only the abstract uri() getter + a test-only mint - no change to auth logic).

Why holdout: The existing set-approval-for-all c-safe-impl fixtures use OpenZeppelin ERC1155
             (same operator-for-all model, different codebase) and Solady ERC721 (same codebase,
             the per-token model). This fixture closes the remaining {Solady} x {ERC-1155} cell -
             the ERC-1155 operator-for-all authorization on the independent Solady codebase wal
             was never tuned against, so a clean verdict is an honest precision signal on unseen
             safe code.

Behavior:    test/RealSafeSoladyERC1155Holdout.t.sol mints a balance to a holder who never calls
             setApprovalForAll for the attacker, then has the un-approved attacker attempt a
             safeTransferFrom sweep - Solady reverts NotOwnerNorApproved and nothing moves. A
             guard confirms an explicitly setApprovalForAll-approved operator CAN move the tokens,
             so BLOCKED is a real rejection of an un-approved operator, not broken transfer logic.
             The verdict is derived from the real outcome (attacker balance stays 0), not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
