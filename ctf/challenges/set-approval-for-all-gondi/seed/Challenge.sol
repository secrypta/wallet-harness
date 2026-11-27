// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC721Move {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

/// @title Challenge - the Gondi "Purchase Bundler" (VULNERABLE version).
/// @notice Modeled on the Gondi drain (2026-03-09, ~$230K / ~78 NFTs; example tx
///         0x83bac5...6a06). Users granted this bundler a standing operator approval
///         (`setApprovalForAll(bundler, true)`) for the legitimate Sell & Repay flow. The bug:
///         `buy` has NO caller restriction, so anyone can name another user's NFT and the
///         bundler pulls it with that user's lingering approval and forwards it to `recipient`.
///
///         Your job is to fix `buy` so a caller can only route their OWN NFT through the
///         bundler, WITHOUT breaking the legitimate flow. Keep the signature exactly as-is;
///         change only the body.
contract Challenge {
    function buy(address nft, uint256 tokenId, address nftOwner, address recipient) external {
        // BUG: no check that msg.sender is entitled to nftOwner's token - the standing
        //      operator approval is abused to pull any approving owner's NFT.
        IERC721Move(nft).transferFrom(nftOwner, recipient, tokenId);
    }
}
