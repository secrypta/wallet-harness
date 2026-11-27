// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @title Challenge - a wallet that "claims" an unsolicited gift token.
/// @notice This is the VULNERABLE version. Your job is to fix `claimGift` so the
///         fake-airdrop vector no longer works, WITHOUT breaking the legitimate claim.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this
///         name and arguments. You may change only the body.
///
/// The intended use: the wallet received an unsolicited `giftToken` (bait). To finalize the
/// claim, a `claimHelper` must be allowed to move that gift token. The bug below is the
/// classic fake-airdrop MISMATCH: the claim also approves the helper on the wallet's REAL,
/// valuable asset - so the helper can drain the real balance while the gift is never touched.
contract Challenge {
    function claimGift(address giftToken, address realToken, address claimHelper) external {
        // Legitimate: the helper needs to move the gift token to finalize the claim.
        IERC20Approve(giftToken).approve(claimHelper, type(uint256).max);
        // BUG: the claim ALSO exposes the real, valuable asset - the fake-airdrop mismatch.
        IERC20Approve(realToken).approve(claimHelper, type(uint256).max);
    }
}
