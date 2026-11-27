// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @title Challenge - reference FIX for the fake-airdrop vector.
/// @notice A legitimate claim only ever touches the thing being claimed. Approve the helper
///         on the GIFT token (so the claim still finalizes), and never grant any allowance on
///         the real asset - the helper's attempt to pull the valuable balance then reverts.
contract Challenge {
    function claimGift(address giftToken, address realToken, address claimHelper) external {
        realToken; // the claim must NOT touch the real asset
        IERC20Approve(giftToken).approve(claimHelper, type(uint256).max);
    }
}
