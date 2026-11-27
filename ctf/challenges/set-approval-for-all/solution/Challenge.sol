// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC721Approve {
    function approve(address to, uint256 tokenId) external;
    function setApprovalForAll(address operator, bool approved) external;
}

/// @title Challenge - reference FIX for the set-approval-for-all vector.
/// @notice Grant a single-token approval for exactly `tokenId`. The operator can move that
///         one token, but has no rights over the rest of the collection.
contract Challenge {
    function authorizeOperator(address nft, address operator, uint256 tokenId) external {
        IERC721Approve(nft).approve(operator, tokenId);
    }
}
