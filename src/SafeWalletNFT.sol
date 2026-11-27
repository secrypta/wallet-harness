// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC721Approve {
    function approve(address operator, uint256 tokenId) external;
}

/// @title SafeWalletNFT - wallet with the DEFENSIVE NFT-approval policy.
/// @notice When the action needs an operator to handle exactly one token, this wallet
///         grants `approve(operator, actionTokenId)` - scoped authority over THAT token
///         only. An operator that later tries to pull any other token is stopped by the
///         ERC-721 authorization check, so the set-approval-for-all vector reverts for
///         every token beyond the one in scope and the rest of the collection stays put.
contract SafeWalletNFT {
    function authorizeOperator(address token, address operator, uint256 actionTokenId) external {
        IERC721Approve(token).approve(operator, actionTokenId);
    }
}
