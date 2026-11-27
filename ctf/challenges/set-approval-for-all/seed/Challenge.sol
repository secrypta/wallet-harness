// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC721Approve {
    function approve(address to, uint256 tokenId) external;
    function setApprovalForAll(address operator, bool approved) external;
}

/// @title Challenge - an NFT wallet that lets an operator move ONE of its tokens.
/// @notice This is the VULNERABLE version. The intended use: authorize `operator` to move
///         the single `tokenId` (e.g. to list it on a marketplace). The bug is that it
///         grants collection-wide operator rights (`setApprovalForAll`), so the operator
///         can walk off with EVERY token the wallet holds - the set-approval-for-all drain.
///
///         Fix `authorizeOperator` so only the one `tokenId` is exposed. Keep the signature
///         unchanged; change only the body.
contract Challenge {
    function authorizeOperator(address nft, address operator, uint256 tokenId) external {
        // BUG: grants blanket operator rights over the whole collection.
        tokenId; // currently ignored
        IERC721Approve(nft).setApprovalForAll(operator, true);
    }
}
