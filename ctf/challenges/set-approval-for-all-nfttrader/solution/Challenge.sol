// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC721Swap {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function transferFrom(address from, address to, uint256 tokenId) external;
}

/// @title Challenge - reference FIX for the NFTTrader reentrant swap drain.
/// @notice Decide the swap terms BEFORE the external call that can re-enter, and act on that
///         snapshot (checks-effects-interactions). A reentrant `editCounterparty` can still
///         rewrite storage, but this settlement uses the cached terms, so it cannot be
///         redirected onto a victim. A normal swap between two consenting parties still
///         completes.
contract Challenge {
    struct Swap {
        address opener;
        address openerNft;
        uint256 openerTokenId;
        address counterparty;
        address cpNft;
        uint256 cpTokenId;
        bool active;
    }

    mapping(uint256 => Swap) public swaps;
    uint256 public nextId;

    function createSwap(
        address openerNft,
        uint256 openerTokenId,
        address cpNft,
        uint256 cpTokenId,
        address counterparty
    ) external returns (uint256 id) {
        id = ++nextId;
        swaps[id] = Swap(msg.sender, openerNft, openerTokenId, counterparty, cpNft, cpTokenId, true);
    }

    function editCounterparty(uint256 swapId, address counterparty, address cpNft, uint256 cpTokenId) external {
        Swap storage s = swaps[swapId];
        require(msg.sender == s.opener, "nfttrader: not opener");
        s.counterparty = counterparty;
        s.cpNft = cpNft;
        s.cpTokenId = cpTokenId;
    }

    function completeSwap(uint256 swapId) external {
        Swap storage s = swaps[swapId];
        require(s.active, "nfttrader: inactive swap");
        s.active = false;
        // FIX: snapshot the terms BEFORE the external call that can re-enter, and settle on them.
        address opener = s.opener;
        address openerNft = s.openerNft;
        uint256 openerTokenId = s.openerTokenId;
        address counterparty = s.counterparty;
        address cpNft = s.cpNft;
        uint256 cpTokenId = s.cpTokenId;

        IERC721Swap(openerNft).safeTransferFrom(opener, counterparty, openerTokenId);
        IERC721Swap(cpNft).transferFrom(counterparty, opener, cpTokenId);
    }
}
