// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC721Move {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

/// @title Challenge - reference FIX for the Gondi Purchase Bundler drain.
/// @notice The standing operator approval makes the bundler ABLE to move the owner's NFT, so
///         the bundler must authorize WHO may ask it to. Only the NFT's own owner may route it
///         through the bundler. The legitimate Sell & Repay flow (owner routes their own NFT)
///         still works; a caller naming someone else's NFT is rejected.
contract Challenge {
    function buy(address nft, uint256 tokenId, address nftOwner, address recipient) external {
        require(msg.sender == nftOwner, "gondi: caller is not the NFT owner");
        IERC721Move(nft).transferFrom(nftOwner, recipient, tokenId);
    }
}
