# Fixture provenance

```
Fixture:      set-approval-for-all/c-safe-impl/oz-erc721-operator-safe
Vector:       set-approval-for-all
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout
Expected:     safe

Origin:       OpenZeppelin ERC721 - the canonical ERC-721 operator-for-all / per-token
              authorization.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              file token/ERC721/ERC721.sol -> vendored byte-identical at fixtures/vendor/oz/ (see
              fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in fixtures/vendor/oz/LICENSE.
Source code:  ../OzERC721OperatorFixture.sol (concrete NFT over unmodified OZ ERC721; adds only
              name()/symbol() + a test-only mint - no change to the authorization logic).

Why holdout: The existing set-approval holdouts are OZ ERC-1155 (different standard) and Solady
             ERC-721/ERC-1155 (different codebase). This fixture covers the {OpenZeppelin} x
             {ERC-721} operator-for-all cell as a scored holdout: an operator the holder never
             granted setApprovalForAll to cannot sweep the holder's tokens.

Behavior:    test/RealSafeOzERC721OperatorHoldout.t.sol mints a collection to a holder who never
             approves the attacker, then the un-approved attacker attempts a transferFrom sweep of
             every token - OZ reverts ERC721InsufficientApproval each time. A guard confirms an
             operator the holder approved-for-all CAN move a token. Verdict derived from the real
             outcome (all tokens stay with the holder).
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
