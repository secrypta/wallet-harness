// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC721SetApprovalForAll {
    function setApprovalForAll(address operator, bool approved) external;
}

/// @title VulnerableWalletNFT - wallet with the UNSAFE NFT-approval policy.
/// @notice The legit action only needs an operator to handle ONE specific token, but
///         this wallet grants blanket `setApprovalForAll(operator, true)` instead. That
///         single call hands the operator standing authority over the wallet's ENTIRE
///         collection - present and future - so a malicious operator can sweep every
///         token later, off-screen, until the approval is revoked.
contract VulnerableWalletNFT {
    /// @param actionTokenId the one token the current action actually involves (ignored
    ///        on purpose - the unsafe policy over-authorizes to "all tokens").
    function authorizeOperator(address token, address operator, uint256 actionTokenId) external {
        actionTokenId; // deliberately unused: the bug is approving ALL, not just this one
        IERC721SetApprovalForAll(token).setApprovalForAll(operator, true);
    }
}
