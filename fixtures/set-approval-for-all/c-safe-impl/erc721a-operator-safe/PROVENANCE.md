# Fixture provenance

```
Fixture:      set-approval-for-all/c-safe-impl/erc721a-operator-safe
Vector:       set-approval-for-all
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       ERC721A - a gas-optimized, independent ERC-721 implementation by Chiru Labs,
              widely deployed across NFT collections (packed sequential ownership + batch
              minting). This is a THIRD, independent NFT codebase, distinct from the OpenZeppelin
              and Solady implementations already in the corpus.
Source:       https://github.com/chiru-labs/ERC721A  tag v4.3.0
              commit 6f8a82a7b2833ad8b2fc7b54349281143a731fdd
              files contracts/{ERC721A,IERC721A}.sol (the full import closure - ERC721A.sol
              imports only IERC721A.sol, which is self-contained) -> vendored byte-identical at
              fixtures/vendor/erc721a/ (pristine upstream layout, zero modifications; see
              fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022 Chiru Labs; full text in fixtures/vendor/erc721a/LICENSE.
Source code:  ../Erc721AOperatorFixture.sol (concrete ERC721A: constructor sets name()/symbol()
              and a test-only sequential `mint` calling `_mint`; the operator-for-all and
              transfer-authorization logic is unmodified ERC721A).

Why holdout: The existing set-approval-for-all holdouts cover {OpenZeppelin} x {ERC-721, ERC-1155}
             and {Solady} x {ERC-721, ERC-1155}. This fixture covers a THIRD, independent ERC-721
             codebase (ERC721A) - real "wild" code used by thousands of collections, with a
             materially different internal design (packed ownership, batch mint) and its own
             operator-approval path. wal was never tuned against it: an honest precision check on
             unseen real safe code, not a lightly-edited twin of the OZ/Solady fixtures.

Behavior:    test/RealSafeErc721AOperatorHoldout.t.sol mints a collection to a holder, then has an
             operator the holder NEVER approved-for-all attempt to sweep every token. ERC721A's
             `transferFrom` reverts (TransferCallerNotOwnerNorApproved) because the caller is
             neither owner, per-token approved, nor an approved-for-all operator, so no token
             moves -> BLOCKED. A guard shows an operator the holder DID `setApprovalForAll(.,true)`
             CAN move a token, so BLOCKED is a real rejection of an un-approved operator, not
             broken transfer logic. The verdict is derived from the real outcome, not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
             Precision-side only (no independent vuln set-approval holdout at this cell).
```
