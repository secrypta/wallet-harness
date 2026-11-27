// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimized OFFLINE reproduction of the Gondi NFT-lending drain (2026-03-09, ~$230K, Ethereum).
// Authored in THIS repo (MIT). This is NOT a copy of Gondi's on-chain contracts and NOT a copy of
// any third-party PoC (the DeFiHackLabs catalog / write-ups are reference for FACTS only, not code;
// their code is Apache-2.0 and is not vendored). The documented MECHANISM is reproduced from
// authoritative write-ups; see ./gondi-bundler-victim/PROVENANCE.md for the incident facts
// (attacker, vulnerable contract, pinned tx hash, on-chain verification, sources).
//
// Root cause (per The Block / Cointelegraph / Revoke.cash / AutoSec): the recently-updated
// "Purchase Bundler" (Sell & Repay) entry point `buy(...)` carried NO `msg.sender` restriction, so
// anyone could call it. `_buy` then executed the bundled actions WITHOUT checking the caller's
// relation to the NFTs being moved. The internal authorization guard (`onlyLoanContract` on the
// post-transfer hook) was bypassed because the whole chain started at the unrestricted `buy`. Many
// users held a standing `setApprovalForAll(bundler, true)` from legitimate use; the attacker called
// `buy` with crafted executionData naming those users' idle (non-collateral) NFTs, and the bundler
// pulled them with the victims' lingering operator approval and forwarded them to the attacker.

/// @dev Minimal ERC-721 with the operator-for-all authority model the vector turns on.
contract GondiMiniERC721 {
    mapping(uint256 => address) public ownerOf;
    mapping(address => mapping(address => bool)) public isApprovedForAll;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 id) external {
        require(ownerOf[id] == address(0), "exists");
        ownerOf[id] = to;
        unchecked {
            ++balanceOf[to];
        }
    }

    function setApprovalForAll(address operator, bool approved) external {
        // Blanket collection-wide authority - the standing grant the drain abuses.
        isApprovedForAll[msg.sender][operator] = approved;
    }

    function transferFrom(address from, address to, uint256 id) public {
        require(ownerOf[id] == from, "wrong-from");
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "not-authorized");
        ownerOf[id] = to;
        unchecked {
            --balanceOf[from];
            ++balanceOf[to];
        }
    }
}

/// @notice Minimized vulnerable "Purchase Bundler". The flaw: `buy` is callable by anyone and the
///         bundled execution never verifies the caller's relation to the NFTs it moves, so a caller
///         can name arbitrary victims' idle NFTs and have the bundler pull them through the victims'
///         standing operator approval and deliver them to the caller.
contract GondiBundlerClone {
    /// @dev Encodes one bundled "purchase" leg: which victim's NFT to move.
    struct BuyLeg {
        GondiMiniERC721 collection;
        uint256 tokenId;
        address holder; // the account whose NFT the bundler pulls (attacker names a victim)
    }

    /// @dev THE FLAW: no `msg.sender` restriction and no check that the caller owns/authorizes the
    ///      legs. Mirrors the unrestricted `buy` -> `_buy` path that bypassed `onlyLoanContract`.
    function buy(BuyLeg[] calldata legs) external {
        for (uint256 i = 0; i < legs.length; ++i) {
            _buy(legs[i], msg.sender);
        }
    }

    /// @dev Pulls the holder's NFT via the lingering operator approval and hands it to `recipient`.
    function _buy(BuyLeg calldata leg, address recipient) internal {
        // Uses the victim's standing setApprovalForAll(bundler, true). No caller/holder consent check.
        leg.collection.transferFrom(leg.holder, address(this), leg.tokenId);
        leg.collection.transferFrom(address(this), recipient, leg.tokenId);
    }
}
