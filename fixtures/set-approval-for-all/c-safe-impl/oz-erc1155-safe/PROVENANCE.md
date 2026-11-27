# Fixture provenance

```
Fixture:      set-approval-for-all/c-safe-impl/oz-erc1155-safe
Vector:       set-approval-for-all
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin Contracts `token/ERC1155/ERC1155.sol` - the ERC-1155 operator-for-all
              authorization surface (`setApprovalForAll` / `isApprovedForAll`, enforced in
              `_update` on `safeTransferFrom` / `safeBatchTransferFrom`). Same blanket-operator
              vector as ERC-721, different token standard/codebase.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files token/ERC1155/{ERC1155,IERC1155}.sol,
                    token/ERC1155/extensions/IERC1155MetadataURI.sol,
                    token/ERC1155/utils/ERC1155Utils.sol, token/ERC1155/IERC1155Receiver.sol,
                    utils/{Arrays,Comparators,SlotDerivation}.sol (+ already-vendored Context,
                    introspection/{ERC165,IERC165}, math/Math, interfaces/draft-IERC6093)
              -> vendored byte-identical under fixtures/vendor/oz/ (same tag/commit as the rest
                 of the OZ tree; see fixtures/vendor/PROVENANCE.md). Fetched from the pinned commit
                 2026-11-17; nothing modified.
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text fixtures/vendor/oz/LICENSE.
Source code:  ../OzERC1155Fixture.sol (concrete OZ ERC1155 subclass adding ONLY a test-only
              `mint`; the operator-authorization logic is unmodified OZ).

Why holdout: distinct from oz-safe-operator / solady-erc721-safe (both ERC-721). This exercises
             OZ's ERC-1155 operator-for-all authorization, real code wal was never tuned against,
             so a clean verdict is an honest precision signal on a different token standard.

Behavior:    test/RealSafeOzERC1155Holdout.t.sol mints a holder two token ids; the holder does NOT
             grant setApprovalForAll to the attacker. The attacker's safeBatchTransferFrom sweep
             reverts in OZ's own `isApprovedForAll` check, so nothing leaves. A guard proves a
             holder-APPROVED operator CAN transfer, so BLOCKED is a real authorization rejection,
             not a broken token. Verdict derived from the real outcome.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.
Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and recorded as such, not suppressed.
```
