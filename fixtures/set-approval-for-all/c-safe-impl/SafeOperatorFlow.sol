// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============================ PROVENANCE ============================
// Real-safe fixture (validation tier (c)) for the set-approval-for-all vector.
// This is the DEFENSIVE authorization policy exercised against the unmodified
// OpenZeppelin ERC721 (v5.1.0, commit 69c8def5f222ff96f2b5beff05dfba996368aa79,
// MIT). It scopes authority to the single token the action needs via
// `approve(operator, tokenId)` - never `setApprovalForAll`. OZ's own
// `transferFrom` authorization reverts any attempt to move another token.
// The harness MUST stay silent on this fixture (expected verdict: BLOCKED /
// label safe).
// ====================================================================

import {IERC721} from "../../vendor/oz/token/ERC721/IERC721.sol";

/// @title SafeOperatorFlow - scoped-approve wallet policy over real OZ ERC721.
/// @notice When an action needs an operator to handle exactly one token, this
///         wallet grants `approve(operator, actionTokenId)` - scoped authority
///         over THAT token only, never blanket `setApprovalForAll`. An operator
///         that later tries to sweep any other token is stopped by
///         OpenZeppelin's authorization check, so the set-approval-for-all
///         vector reverts for every token beyond the one in scope.
contract SafeOperatorFlow {
    function authorizeOperator(address token, address operator, uint256 actionTokenId) external {
        IERC721(token).approve(operator, actionTokenId);
    }
}
